//! Typed policy-loading errors.
//!
//! Every failure has a variant. Human-readable [`Display`](core::fmt::Display)
//! text is rendered *from* the variant; nothing in the authority parses the
//! prose to decide what happened, because an error whose only machine-readable
//! form is a string is an error somebody eventually matches with
//! `contains("duplicate")`.
//!
//! Every variant carries where it happened. A load error that says "unknown
//! field" without naming the file and line is a load error an operator cannot
//! act on, and [`POLICY.md`] §5 requires a file and line for a *decision* —
//! being vaguer about a rejection than about an acceptance would be backwards.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use core::fmt;

use super::{SourceLocation, limits};

/// Where in the schema a value went wrong.
///
/// A path like `rule[3].when.path_under`, assembled as the walker descends, so
/// the message names the member rather than the offset.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldPath(String);

impl FieldPath {
    /// The document root.
    #[must_use]
    pub fn root() -> Self {
        Self(String::new())
    }

    /// A named member of this one.
    #[must_use]
    pub fn member(&self, name: &str) -> Self {
        if self.0.is_empty() {
            Self(name.to_owned())
        } else {
            Self(format!("{}.{name}", self.0))
        }
    }

    /// An indexed element of this one.
    #[must_use]
    pub fn index(&self, index: usize) -> Self {
        Self(format!("{}[{index}]", self.0))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("<document>")
        } else {
            f.write_str(&self.0)
        }
    }
}

/// What a scalar should have been.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expected {
    /// A TOML string.
    String,
    /// A TOML integer.
    Integer,
    /// A TOML boolean.
    Boolean,
    /// A TOML table.
    Table,
    /// A TOML array.
    Array,
    /// A string, or an array of them.
    StringOrArray,
}

impl Expected {
    /// The name used in messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::String => "a string",
            Self::Integer => "an integer",
            Self::Boolean => "a boolean",
            Self::Table => "a table",
            Self::Array => "an array",
            Self::StringOrArray => "a string or an array of strings",
        }
    }
}

impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value that is the right *type* but not a value this schema admits.
///
/// Separated from [`PolicyLoadError`] so the leaf parsers — an obligation, a
/// TTL, a CIDR — can be written and tested without knowing where in a document
/// they were called from. The walker adds the location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueError {
    /// Not one of the three effects.
    UnknownEffect,
    /// Not one of the reasons, or one the evaluator reserves for itself.
    UnknownReason,
    /// Not one of the ten obligations.
    UnknownObligation,
    /// An obligation's parameter is missing, present where none is defined, or
    /// malformed — which includes a numeric parameter that does not fit.
    ObligationParameter,
    /// The same obligation, or two parameterisations of it, twice.
    DuplicateObligation,
    /// More obligations than [`limits::MAX_OBLIGATIONS_PER_RULE`].
    TooManyObligations,
    /// Not `<positive integer><s|m|h>`, or out of range.
    Ttl,
    /// Zero uses, or more than [`limits::MAX_APPROVAL_USES`].
    ApprovalUses,
    /// Not one of the six approval scopes.
    UnknownApprovalScope,
    /// Not a verb the capability vocabulary defines.
    UnknownVerb,
    /// Not one of the origins.
    UnknownOrigin,
    /// Not one of the taint tiers.
    UnknownTaintLevel,
    /// Not one of the privacy classes.
    UnknownPrivacyClass,
    /// Not `sandbox` or `host`.
    UnknownEnvironment,
    /// Not a configuration key policy may read.
    UnknownConfigKey,
    /// A `${...}` symbol the closed anchor set does not define.
    UnknownPathAnchor,
    /// A rule-side path that is not anchored, not absolute, empty, too deep, or
    /// contains a segment a canonical path could never have.
    MalformedPath,
    /// A host pattern that is not a label sequence, or wildcards in TLD
    /// position.
    MalformedHost,
    /// An address and prefix that is not a CIDR, or whose prefix is out of
    /// range for its family.
    MalformedCidr,
    /// A rule id that is not `[a-z][a-z0-9-]*`, is empty, or is too long.
    MalformedRuleId,
    /// A profile name that is not `[a-z][a-z0-9-]*`, is empty, or is too long.
    MalformedProfileName,
    /// An integer that is negative where unsigned is required, or too large for
    /// the field.
    NumericRange,
    /// A list with no elements where at least one is required.
    EmptyList,
    /// A list with the same element twice.
    DuplicateListItem,
    /// More list elements than [`limits::MAX_LIST_ITEMS`].
    TooManyListItems,
    /// A string longer than [`limits::MAX_STRING_CHARS`].
    StringTooLong,
}

impl ValueError {
    /// What went wrong, as a sentence fragment.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownEffect => "not one of ALLOW, DENY, REQUIRE_APPROVAL",
            Self::UnknownReason => "not a reason a rule may state",
            Self::UnknownObligation => "not one of the ten obligations",
            Self::ObligationParameter => "the obligation's parameter is missing or malformed",
            Self::DuplicateObligation => "the same obligation twice",
            Self::TooManyObligations => "too many obligations on one rule",
            Self::Ttl => "not a duration of the form 10m, 1h or 30s",
            Self::ApprovalUses => "max_uses must be at least one and within bounds",
            Self::UnknownApprovalScope => "not one of the six approval scopes",
            Self::UnknownVerb => "not a verb the capability vocabulary defines",
            Self::UnknownOrigin => "not one of the run origins",
            Self::UnknownTaintLevel => "not one of the taint tiers",
            Self::UnknownPrivacyClass => "not one of the privacy classes",
            Self::UnknownEnvironment => "not sandbox or host",
            Self::UnknownConfigKey => "not a configuration key policy may read",
            Self::UnknownPathAnchor => "not a path anchor policy defines",
            Self::MalformedPath => "not an anchored or absolute path",
            Self::MalformedHost => "not a host pattern",
            Self::MalformedCidr => "not an address and prefix length",
            Self::MalformedRuleId => "not a rule id",
            Self::MalformedProfileName => "not a profile name",
            Self::NumericRange => "out of range for this field",
            Self::EmptyList => "an empty list where one element is required",
            Self::DuplicateListItem => "the same element twice",
            Self::TooManyListItems => "too many elements",
            Self::StringTooLong => "longer than the bound on a policy string",
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a policy source did not compile.
///
/// The variants are the categories a caller might treat differently: a bound
/// exceeded is an operator's mistake, a widening extension is a security
/// finding, and a syntax error is neither. Nothing recovers from any of them —
/// the loader produces a policy or it produces this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    /// The source is longer than [`limits::MAX_SOURCE_BYTES`].
    ///
    /// Reported *before* parsing, with the length that was refused, so the
    /// message is not "the parser ran out of room".
    SourceTooLarge {
        /// How many bytes were offered.
        bytes: usize,
        /// The bound.
        limit: usize,
    },
    /// The logical source name is empty or too long.
    SourceNameInvalid,
    /// More profiles than [`limits::MAX_PROFILES`] were handed to one load.
    TooManyProfiles {
        /// How many were offered.
        count: usize,
        /// The bound.
        limit: usize,
    },
    /// The TOML did not parse. Carries the parser's own message, which already
    /// names a line and column and shows the offending text.
    Syntax {
        /// Where, as best the loader can place it.
        at: SourceLocation,
        /// What the parser said.
        message: String,
    },
    /// `schema_version` is absent.
    SchemaVersionMissing {
        /// The source it is missing from.
        at: SourceLocation,
    },
    /// `schema_version` names a version this build does not implement.
    ///
    /// There is no forward compatibility and no silent fallback: a file
    /// claiming version 2 is refused rather than read as though it were
    /// version 1, because the fields version 2 adds are exactly the fields a
    /// version 1 reader would ignore.
    SchemaVersionUnsupported {
        /// Where the field is.
        at: SourceLocation,
        /// What it said.
        found: i64,
        /// What this build implements.
        supported: u32,
    },
    /// A member no version of this schema defines.
    ///
    /// The single most important rejection in the loader: `when.destinatoin_novel`
    /// must fail, not read as "the predicate is absent".
    UnknownField {
        /// Where.
        at: SourceLocation,
        /// Which member.
        field: FieldPath,
    },
    /// A member the schema requires is absent.
    MissingField {
        /// Where the table that should have had it is.
        at: SourceLocation,
        /// Which member.
        field: FieldPath,
    },
    /// A member of the right name and the wrong type.
    ///
    /// No coercion anywhere: `schema_version = "1"` is not `1`,
    /// `argv_safe = "true"` is not `true`, and `max_uses = 1.5` is not `1`.
    TypeMismatch {
        /// Where.
        at: SourceLocation,
        /// Which member.
        field: FieldPath,
        /// What the schema wanted.
        expected: Expected,
    },
    /// A member of the right type whose value the schema does not admit.
    BadValue {
        /// Where.
        at: SourceLocation,
        /// Which member.
        field: FieldPath,
        /// Why.
        error: ValueError,
    },
    /// Two rules, or two postconditions, with the same id.
    DuplicateRuleId {
        /// Where the second one is.
        at: SourceLocation,
        /// Where the first one was.
        first: SourceLocation,
        /// The id.
        id: String,
    },
    /// Two profiles with the same name in one load.
    DuplicateProfileName {
        /// The name.
        name: String,
    },
    /// More rules than [`limits::MAX_RULES`], or more postconditions than
    /// [`limits::MAX_POSTCONDITIONS`].
    TooManyRules {
        /// Where.
        at: SourceLocation,
        /// How many.
        count: usize,
        /// The bound.
        limit: usize,
    },
    /// A profile with no `default` rule.
    DefaultRuleMissing {
        /// The source.
        at: SourceLocation,
    },
    /// A `default` rule that is not the last rule in its profile.
    DefaultRuleNotLast {
        /// Where the default is.
        at: SourceLocation,
        /// How many rules follow it.
        followed_by: usize,
    },
    /// A `default` rule whose effect is not `DENY`.
    ///
    /// `default = ALLOW` is not a policy with a permissive default; it is a
    /// policy with no default at all, since every action reaches it.
    DefaultRuleNotDeny {
        /// Where.
        at: SourceLocation,
    },
    /// A `default` rule carrying a match predicate.
    ///
    /// A conditional default is a rule that sometimes does not match, and the
    /// evaluator would then fall off the end of the list.
    DefaultRuleConditional {
        /// Where.
        at: SourceLocation,
    },
    /// A predicate a rule's verbs cannot have.
    ///
    /// `when.argv_safe` on a rule restricted to `fs.*` verbs would be false
    /// for every action it could match, which makes it a rule that never
    /// fires. Refused so the author finds out at load rather than in
    /// production.
    PredicateNotApplicable {
        /// Where.
        at: SourceLocation,
        /// Which predicate.
        field: FieldPath,
        /// Why it cannot apply.
        detail: &'static str,
    },
    /// A rule uses a verb-specific predicate without constraining `when.verb`.
    ///
    /// Without the verbs, applicability cannot be decided, and a predicate
    /// whose applicability is unknown is a predicate that might silently never
    /// match.
    PredicateNeedsVerbs {
        /// Where.
        at: SourceLocation,
        /// Which predicate.
        field: FieldPath,
    },
    /// A `REQUIRE_APPROVAL` rule with no `approval` table, or a rule of
    /// another effect that has one.
    ApprovalSpecMismatch {
        /// Where.
        at: SourceLocation,
        /// What is wrong.
        detail: &'static str,
    },
    /// A profile `extends` a name the load was not given.
    ExtendsUnknownProfile {
        /// Where.
        at: SourceLocation,
        /// The name.
        name: String,
    },
    /// A profile that extends itself, directly or through a chain.
    ExtendsCycle {
        /// The chain, in order, ending at the repeat.
        chain: Vec<String>,
    },
    /// An `extends` chain longer than [`limits::MAX_EXTENDS_DEPTH`].
    ExtendsTooDeep {
        /// The chain.
        chain: Vec<String>,
        /// The bound.
        limit: usize,
    },
    /// An extending profile that could broaden what it extends.
    ///
    /// The one variant that is a security finding rather than a mistake. See
    /// [`super::compose`] for exactly which shapes are refused and why the
    /// refusal is decidable.
    WideningExtension {
        /// Where the offending rule is.
        at: SourceLocation,
        /// Which rule.
        id: String,
        /// Why it could widen.
        detail: &'static str,
    },
    /// An extending profile declaring an id its parent chain already uses.
    ///
    /// Shadowing by id would let a child rule take the place of a parent's
    /// hard denial while an audit record continued to name the parent's rule.
    ExtendsShadowsRuleId {
        /// Where the child's is.
        at: SourceLocation,
        /// The id.
        id: String,
        /// The profile that already uses it.
        parent: String,
    },
    /// An extending profile declaring its own `default`.
    ///
    /// The default belongs to the root of the chain. A child default would be
    /// a second default, and the composed policy would have two rules claiming
    /// to be the one that always matches.
    ExtendsRedeclaresDefault {
        /// Where.
        at: SourceLocation,
    },
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { bytes, limit } => write!(
                f,
                "policy source is {bytes} bytes, over the {limit}-byte bound (refused before parsing)"
            ),
            Self::SourceNameInvalid => write!(
                f,
                "the logical source name is empty or longer than {} characters",
                limits::MAX_SOURCE_NAME_CHARS
            ),
            Self::TooManyProfiles { count, limit } => {
                write!(
                    f,
                    "{count} profiles offered to one load, over the bound of {limit}"
                )
            }
            Self::Syntax { at, message } => write!(f, "{at}: {message}"),
            Self::SchemaVersionMissing { at } => {
                write!(f, "{at}: schema_version is required")
            }
            Self::SchemaVersionUnsupported {
                at,
                found,
                supported,
            } => write!(
                f,
                "{at}: schema_version {found} is not supported; this build implements {supported}"
            ),
            Self::UnknownField { at, field } => {
                write!(f, "{at}: unknown field `{field}`")
            }
            Self::MissingField { at, field } => {
                write!(f, "{at}: `{field}` is required")
            }
            Self::TypeMismatch {
                at,
                field,
                expected,
            } => write!(f, "{at}: `{field}` must be {expected}"),
            Self::BadValue { at, field, error } => {
                write!(f, "{at}: `{field}` is {error}")
            }
            Self::DuplicateRuleId { at, first, id } => {
                write!(f, "{at}: rule id `{id}` is already used at {first}")
            }
            Self::DuplicateProfileName { name } => {
                write!(f, "two profiles named `{name}` in one load")
            }
            Self::TooManyRules { at, count, limit } => {
                write!(f, "{at}: {count} rules, over the bound of {limit}")
            }
            Self::DefaultRuleMissing { at } => write!(
                f,
                "{at}: a rule with id `default` is required, and must be last"
            ),
            Self::DefaultRuleNotLast { at, followed_by } => write!(
                f,
                "{at}: the `default` rule is followed by {followed_by} more rules, which can never match"
            ),
            Self::DefaultRuleNotDeny { at } => {
                write!(f, "{at}: the `default` rule must be DENY")
            }
            Self::DefaultRuleConditional { at } => write!(
                f,
                "{at}: the `default` rule must have no `when` or `unless` predicate"
            ),
            Self::PredicateNotApplicable { at, field, detail } => {
                write!(f, "{at}: `{field}` cannot apply here: {detail}")
            }
            Self::PredicateNeedsVerbs { at, field } => write!(
                f,
                "{at}: `{field}` applies only to some verbs, so the rule must set `when.verb`"
            ),
            Self::ApprovalSpecMismatch { at, detail } => write!(f, "{at}: {detail}"),
            Self::ExtendsUnknownProfile { at, name } => {
                write!(f, "{at}: extends `{name}`, which this load was not given")
            }
            Self::ExtendsCycle { chain } => {
                write!(f, "extends cycle: {}", chain.join(" -> "))
            }
            Self::ExtendsTooDeep { chain, limit } => write!(
                f,
                "extends chain {} is deeper than {limit}",
                chain.join(" -> ")
            ),
            Self::WideningExtension { at, id, detail } => {
                write!(
                    f,
                    "{at}: rule `{id}` could widen the profile it extends: {detail}"
                )
            }
            Self::ExtendsShadowsRuleId { at, id, parent } => write!(
                f,
                "{at}: rule id `{id}` already exists in `{parent}`, which this profile extends"
            ),
            Self::ExtendsRedeclaresDefault { at } => write!(
                f,
                "{at}: an extending profile must not declare its own `default`; the root of the chain owns it"
            ),
        }
    }
}

impl core::error::Error for PolicyLoadError {}

#[cfg(test)]
mod tests {
    use super::{Expected, FieldPath, PolicyLoadError, ValueError};
    use crate::policy::SourceLocation;

    #[test]
    fn a_field_path_names_the_member_rather_than_the_offset() {
        let root = FieldPath::root();
        assert_eq!(root.to_string(), "<document>");
        let path = root
            .member("rule")
            .index(3)
            .member("when")
            .member("path_under");
        assert_eq!(path.as_str(), "rule[3].when.path_under");
    }

    #[test]
    fn every_value_error_says_something() {
        for error in [
            ValueError::UnknownEffect,
            ValueError::UnknownObligation,
            ValueError::Ttl,
            ValueError::MalformedCidr,
            ValueError::StringTooLong,
        ] {
            assert!(!error.as_str().is_empty());
            assert_eq!(error.to_string(), error.as_str());
        }
    }

    #[test]
    fn errors_render_with_a_place_and_a_reason() {
        let Some(at) = SourceLocation::new("balanced.toml", 63) else {
            unreachable!("a valid location")
        };
        let rendered = PolicyLoadError::UnknownField {
            at: at.clone(),
            field: FieldPath::root()
                .member("rule")
                .index(0)
                .member("when")
                .member("destinatoin_novel"),
        }
        .to_string();
        assert!(rendered.contains("balanced.toml:63"), "{rendered}");
        assert!(rendered.contains("destinatoin_novel"), "{rendered}");

        let sized = PolicyLoadError::SourceTooLarge {
            bytes: 999,
            limit: 100,
        }
        .to_string();
        assert!(sized.contains("999"));
        assert!(sized.contains("before parsing"), "{sized}");

        let mismatch = PolicyLoadError::TypeMismatch {
            at,
            field: FieldPath::root().member("schema_version"),
            expected: Expected::Integer,
        }
        .to_string();
        assert!(mismatch.contains("an integer"), "{mismatch}");
    }

    #[test]
    fn a_cycle_renders_the_chain_that_produced_it() {
        let rendered = PolicyLoadError::ExtendsCycle {
            chain: vec!["a".to_owned(), "b".to_owned(), "a".to_owned()],
        }
        .to_string();
        assert_eq!(rendered, "extends cycle: a -> b -> a");
    }
}
