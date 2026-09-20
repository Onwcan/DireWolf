//! The policy engine: the deterministic decision function.
//!
//! Given a canonical action and the run's kernel-owned context, return
//! `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, plus an explanation good enough to
//! debug and to show a human ([`POLICY.md`]).
//!
//! # The two gates are independent
//!
//! Policy answers *"should this action be allowed under current policy?"*.
//! Capabilities answer *"is this action within the authority the run holds?"*.
//! [ADR-0006] requires both, independently, always:
//!
//! ```text
//! final_allow = policy_allows ∧ capability_covers ∧ budget_permits ∧ binding_intact
//! ```
//!
//! This module implements the **first term only**. There is no function here
//! that takes a capability *set*, no shortcut that skips the capability check
//! when policy allows, and no combined boolean. A bug in either gate must not
//! be a full bypass, and it cannot be if neither can stand in for the other.
//!
//! # What it is
//!
//! A pure function. No I/O, no clock, no randomness, no environment, no
//! network, no filesystem — `load` takes policy *text* rather than a path,
//! because reading the operator's file is the authority layer's job and
//! because a parser that cannot open anything is a parser that can be fuzzed
//! and replayed. A decision can be recomputed months later from the audit
//! record and will be the same decision.
//!
//! # Two phases, and why
//!
//! [`POLICY.md`] §4 describes first-match evaluation; §5's `policy explain`
//! output shows two rules contributing to one decision, the second of which
//! turns on whether the first required approval. Those cannot both be true of
//! a single-phase evaluator. [ADR-0038] resolves it:
//!
//! 1. **Primary rules**, ordered, first match wins → a provisional decision.
//! 2. **Postconditions**, ordered, each of which may only *narrow* it.
//!
//! The selector for phase two is the provisional effect, which the evaluator
//! supplies from its own phase-one result. It is not a field of
//! [`PolicyContext`], and there is no constructor anywhere that accepts it —
//! see [`eval`] for the attack that closes.
//!
//! # What is not here
//!
//! No `kernel.db` (M3d), no approval registry, binding or standing grant (M6),
//! no socket or peer identity (M3e), no resource canonicalisation (M4), and no
//! execution of anything. An [`Obligation`] this module returns is data; the
//! thing that enforces it does not exist yet, and [`obligation`] says so.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md
//! [ADR-0006]: ../../../../../docs/adr/0006-policy-and-capability-boundary.md
//! [ADR-0038]: ../../../../../docs/adr/0038-policy-evaluation-phases-and-composition.md

pub mod action;
pub mod approval;
pub mod compose;
pub mod context;
pub mod effect;
pub mod error;
pub mod eval;
pub mod limits;
pub mod load;
pub mod obligation;
pub mod predicate;
pub mod profiles;
pub mod reason;
pub mod rule;
pub mod value;

// The fixture suites for the three shipped packs, and the evaluation
// benchmark. Unit tests because both need canonical `fs` and `process`
// identities, and since ADR-0037 one of those can only be built inside the
// crate -- an integration test links the library compiled without `cfg(test)`.
#[cfg(test)]
mod benchmark;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
pub(crate) mod testing;

use core::fmt;

use crate::capability::Capability;

pub use action::{ArgvSafety, CanonicalAction, Environment, IpAddress, Novelty};
pub use approval::{ApprovalScopeKind, ApprovalSpec, Ttl};
pub use compose::compose;
pub use context::{
    ConfigFlags, ConfigKey, Origin, PathAnchor, PathAnchors, PolicyContext, StandingGrantState,
    TaintLevel,
};
pub use effect::Effect;
pub use error::{Expected, FieldPath, PolicyLoadError, ValueError};
pub use eval::evaluate;
pub use load::{SCHEMA_VERSION, load};
pub use obligation::{AuditLevel, Obligation, Obligations, ProfileRef};
pub use predicate::{Match, MatchValue, PredicateName, Unevaluable, Unless, When};
pub use reason::Reason;
pub use rule::{CompiledPolicy, Postcondition, Profile, ProfileName, Rule};
pub use value::{Cidr, ExecutableSpec, RulePath};

/// A rule's identifier.
///
/// `[a-z][a-z0-9-]*`, bounded, with no doubled or trailing `-`. Deliberately
/// not a free Unicode identifier grammar: these names go into audit records and
/// are compared by machines, and two names that render alike and compare
/// differently are a way to make an audit log lie.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(String);

impl RuleId {
    /// The reserved id of the mandatory unconditional rule.
    pub const DEFAULT: &'static str = "default";

    /// Accept the identifier grammar.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        if rule::is_lower_kebab(text, limits::MAX_RULE_ID_CHARS) {
            Some(Self(text.to_owned()))
        } else {
            None
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the reserved default id.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.0 == Self::DEFAULT
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a rule is written: a logical source name and a line.
///
/// [`POLICY.md`] §1 requires every decision to carry "matched rule id, source
/// file and line", and §5 renders `policy/balanced.toml:63`. The line is the
/// real one, taken from the byte span the TOML parser reports for the rule's
/// `[[rule]]` header and converted against the same bounded source — not a
/// placeholder, and not the product of a second parser scanning for brackets.
///
/// # Newlines
///
/// The line is the count of `\n` before the span, plus one. A CRLF file and an
/// LF file with the same rules therefore report the same line, because `\r` is
/// not counted and the TOML parser accepts both. A rule's reported location
/// does not depend on how the file was checked out.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceLocation {
    source: String,
    line: u32,
}

impl SourceLocation {
    /// A location in a named source.
    ///
    /// Returns `None` for an empty or over-long name, or for line zero: there
    /// is no line zero, and a zero would be the placeholder this type exists to
    /// make impossible.
    #[must_use]
    pub fn new(source: &str, line: u32) -> Option<Self> {
        let chars = source.chars().count();
        if source.is_empty() || chars > limits::MAX_SOURCE_NAME_CHARS || line == 0 {
            return None;
        }
        Some(Self {
            source: source.to_owned(),
            line,
        })
    }

    /// A location for a failure that belongs to no particular line, such as an
    /// `extends` naming a profile the load was never given.
    ///
    /// Line 1 of a source named for the condition, rather than a real file at
    /// a fake line: an error saying `<load>:1` cannot be mistaken for one
    /// pointing into a policy file.
    #[must_use]
    pub(crate) fn synthetic() -> Self {
        Self {
            source: "<load>".to_owned(),
            line: 1,
        }
    }

    /// The logical source name.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The line, counting from one.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.source, self.line)
    }
}

/// A rule that contributed to a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    id: RuleId,
    source: SourceLocation,
    reason: Reason,
}

impl MatchedRule {
    /// Record a contribution.
    #[must_use]
    pub const fn new(id: RuleId, source: SourceLocation, reason: Reason) -> Self {
        Self { id, source, reason }
    }

    /// Which rule.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// Where it is.
    #[must_use]
    pub const fn source(&self) -> &SourceLocation {
        &self.source
    }

    /// What it said.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }
}

impl fmt::Display for MatchedRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.id, self.source)
    }
}

/// What policy decided, and everything needed to explain it.
///
/// Every field is typed. [`POLICY.md`] §2: `reason` is an enum "so denials are
/// machine-classifiable in evals and metrics; human-readable text is rendered
/// from it". There is no `HashMap<String, Value>` here, no free-form detail
/// and no prose that production control flow could branch on.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    effect: Effect,
    deciding: MatchedRule,
    primary: MatchedRule,
    postconditions: Vec<MatchedRule>,
    required_capability: Capability,
    approval: Option<ApprovalSpec>,
    obligations: Obligations,
    unevaluable: Option<Unevaluable>,
}

impl Decision {
    /// Assemble a decision. Crate-internal: [`evaluate`] is the only way in.
    pub(crate) const fn new(
        effect: Effect,
        deciding: MatchedRule,
        primary: MatchedRule,
        postconditions: Vec<MatchedRule>,
        required_capability: Capability,
        approval: Option<ApprovalSpec>,
        obligations: Obligations,
    ) -> Self {
        Self {
            effect,
            deciding,
            primary,
            postconditions,
            required_capability,
            approval,
            obligations,
            unevaluable: None,
        }
    }

    /// The same, for a decision forced by an input that was not fully
    /// canonicalised.
    pub(crate) const fn not_evaluated(
        deciding: MatchedRule,
        primary: MatchedRule,
        postconditions: Vec<MatchedRule>,
        required_capability: Capability,
        why: Unevaluable,
    ) -> Self {
        Self {
            effect: Effect::Deny,
            deciding,
            primary,
            postconditions,
            required_capability,
            approval: None,
            obligations: Obligations::none(),
            unevaluable: Some(why),
        }
    }

    /// What policy decided.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// The id of the rule the effect came from.
    ///
    /// The primary rule, unless a postcondition narrowed the decision, in
    /// which case the last one that did.
    #[must_use]
    pub const fn rule_id(&self) -> &RuleId {
        self.deciding.id()
    }

    /// Where that rule is written. Always a real file and a real line.
    #[must_use]
    pub const fn rule_source(&self) -> &SourceLocation {
        self.deciding.source()
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.deciding.reason()
    }

    /// The phase-one rule that matched, whether or not it decided.
    #[must_use]
    pub const fn primary_rule(&self) -> &MatchedRule {
        &self.primary
    }

    /// The postconditions that fired, in order.
    #[must_use]
    pub fn applied_postconditions(&self) -> &[MatchedRule] {
        &self.postconditions
    }

    /// The capability this action required.
    ///
    /// Echoed from the action, never constructed here. Whether the run *holds*
    /// it is the other gate's question and is not answered anywhere in this
    /// module.
    #[must_use]
    pub const fn required_capability(&self) -> &Capability {
        &self.required_capability
    }

    /// The approval shape that would satisfy this decision, if any.
    ///
    /// Present only on a `REQUIRE_APPROVAL`. A decision narrowed to `DENY`
    /// carries none, because there is no approval that would satisfy a denial —
    /// and offering one would tell an operator they could click past a refusal.
    #[must_use]
    pub const fn approval(&self) -> Option<&ApprovalSpec> {
        self.approval.as_ref()
    }

    /// The conditions an `ALLOW` carries.
    #[must_use]
    pub const fn obligations(&self) -> &Obligations {
        &self.obligations
    }

    /// The canonical value a predicate needed and the input did not carry, if
    /// that is what forced this decision.
    ///
    /// Present only on a denial, and typed rather than free text, so an
    /// operator is told *which* value was missing without anything having to
    /// parse prose to find out.
    #[must_use]
    pub const fn unevaluable(&self) -> Option<Unevaluable> {
        self.unevaluable
    }
}

impl fmt::Display for Decision {
    /// The shape of [`POLICY.md`] §5, one line per contributing rule.
    ///
    /// Deterministic code, not a rendering anything generated. A policy
    /// explanation is security-relevant output and no model produces it.
    ///
    /// [`POLICY.md`]: ../../../../../docs/POLICY.md
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}", self.effect, self.required_capability.verb())?;
        writeln!(f, "  matched rule  {}", self.primary)?;
        for applied in &self.postconditions {
            writeln!(f, "  then          {applied}")?;
        }
        writeln!(f, "  reason        {}", self.reason())?;
        if let Some(why) = self.unevaluable {
            writeln!(f, "  not evaluated {why}")?;
        }
        writeln!(f, "  required cap  {}", self.required_capability)?;
        if let Some(approval) = &self.approval {
            writeln!(f, "  would satisfy {approval}")?;
        }
        if !self.obligations.is_empty() {
            writeln!(f, "  obligations   {}", self.obligations)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleId, SourceLocation, limits};

    #[test]
    fn a_rule_id_follows_the_identifier_grammar() {
        for good in ["default", "deny-credential-paths", "a", "x1"] {
            assert!(RuleId::new(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "Default",
            "deny_credential_paths",
            "-x",
            "x-",
            "a--b",
            "1x",
        ] {
            assert!(RuleId::new(bad).is_none(), "{bad}");
        }
        let over = "a".repeat(limits::MAX_RULE_ID_CHARS + 1);
        assert!(RuleId::new(&over).is_none());
    }

    #[test]
    fn only_the_reserved_id_is_the_default() {
        let (Some(default), Some(other)) = (RuleId::new("default"), RuleId::new("defaults")) else {
            unreachable!("both are valid ids")
        };
        assert!(default.is_default());
        assert!(!other.is_default());
    }

    #[test]
    fn a_source_location_is_a_real_file_and_a_real_line() {
        let Some(at) = SourceLocation::new("balanced.toml", 63) else {
            unreachable!("valid")
        };
        assert_eq!(at.to_string(), "balanced.toml:63");
        assert_eq!(at.line(), 63);
        assert_eq!(at.source(), "balanced.toml");

        // There is no line zero. A type that could hold one is a type that
        // would eventually hold one for every rule.
        assert!(SourceLocation::new("balanced.toml", 0).is_none());
        assert!(SourceLocation::new("", 1).is_none());
        let long = "x".repeat(limits::MAX_SOURCE_NAME_CHARS + 1);
        assert!(SourceLocation::new(&long, 1).is_none());
    }

    #[test]
    fn a_synthetic_location_cannot_be_mistaken_for_a_file() {
        let at = SourceLocation::synthetic();
        assert_eq!(at.to_string(), "<load>:1");
        assert!(
            std::path::Path::new(at.source()).extension().is_none(),
            "a synthetic location must not look like a file"
        );
    }
}
