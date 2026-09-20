//! Compiled rules, postconditions and profiles.

use core::fmt;

use super::approval::ApprovalSpec;
use super::effect::Effect;
use super::error::ValueError;
use super::limits;
use super::obligation::Obligations;
use super::predicate::{Unless, When};
use super::reason::Reason;
use super::{RuleId, SourceLocation};

/// Whether a string is `[a-z][a-z0-9-]*`, bounded, with no doubled or trailing
/// `-`.
///
/// The grammar for every machine identifier in a policy file: rule ids,
/// profile names, sandbox and redaction profile references. Deliberately not
/// a Unicode identifier grammar — these names are compared, logged, and put in
/// audit records, and a name with two byte sequences that look alike is a name
/// two people can disagree about.
#[must_use]
pub fn is_lower_kebab(text: &str, max_chars: usize) -> bool {
    if text.is_empty() || text.len() > max_chars {
        return false;
    }
    let bytes = text.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if !first.is_ascii_lowercase() || *last == b'-' {
        return false;
    }
    if text.contains("--") {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// A profile's name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileName(String);

impl ProfileName {
    /// Accept the identifier grammar.
    ///
    /// # Errors
    ///
    /// [`ValueError::MalformedProfileName`].
    pub fn new(text: &str) -> Result<Self, ValueError> {
        if is_lower_kebab(text, limits::MAX_PROFILE_NAME_CHARS) {
            Ok(Self(text.to_owned()))
        } else {
            Err(ValueError::MalformedProfileName)
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One primary rule.
///
/// Immutable once compiled. There is no setter, no `&mut self` method and no
/// way to replace a part of one, so a loaded policy is a value rather than
/// something a later phase can edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    id: RuleId,
    source: SourceLocation,
    effect: Effect,
    reason: Reason,
    when: When,
    unless: Unless,
    obligations: Obligations,
    approval: Option<ApprovalSpec>,
}

impl Rule {
    /// Assemble a compiled rule. Crate-internal: [`super::load`] is the only
    /// way in, so every rule has been through the strict schema.
    #[expect(
        clippy::too_many_arguments,
        reason = "a rule has this many parts; a builder would only move them"
    )]
    pub(super) const fn new(
        id: RuleId,
        source: SourceLocation,
        effect: Effect,
        reason: Reason,
        when: When,
        unless: Unless,
        obligations: Obligations,
        approval: Option<ApprovalSpec>,
    ) -> Self {
        Self {
            id,
            source,
            effect,
            reason,
            when,
            unless,
            obligations,
            approval,
        }
    }

    /// The rule's identifier.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// Where it is written.
    #[must_use]
    pub const fn source(&self) -> &SourceLocation {
        &self.source
    }

    /// What it decides.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// The positive condition.
    #[must_use]
    pub const fn when(&self) -> &When {
        &self.when
    }

    /// The negative condition.
    #[must_use]
    pub const fn unless(&self) -> &Unless {
        &self.unless
    }

    /// The conditions an `ALLOW` carries.
    #[must_use]
    pub const fn obligations(&self) -> &Obligations {
        &self.obligations
    }

    /// The approval shape a `REQUIRE_APPROVAL` names.
    #[must_use]
    pub const fn approval(&self) -> Option<&ApprovalSpec> {
        self.approval.as_ref()
    }

    /// Whether this is the mandatory unconditional rule.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.id.is_default()
    }
}

/// One postcondition: the second evaluation phase.
///
/// # Why there is a second phase at all
///
/// [`POLICY.md`] §4 describes a first-match loop that returns as soon as a rule
/// matches. §5's `policy explain` output shows two rules firing for one
/// decision — `approve-novel-exec`, *then*
/// `deny-approval-needed-when-unattended` — and the second of those turns on
/// `would_require_approval`, which cannot be known until a provisional
/// decision exists. A single-phase evaluator cannot produce that output, and
/// the rule as written in §3 is either unreachable or circular.
///
/// [ADR-0038] resolves it: primary rules decide provisionally, and a small
/// closed set of postconditions may then **narrow** that decision and nothing
/// else. The selector is [`When::provisional_effect`], which the evaluator
/// supplies from its own phase-one result — never a caller.
///
/// # Why it cannot widen
///
/// Two independent reasons, and the second holds even if the first is wrong:
///
/// 1. **At load**, [`Postcondition::narrows`] checks that the effect is
///    narrower than or equal to *every* provisional effect the postcondition
///    can select. A postcondition selecting `REQUIRE_APPROVAL` and producing
///    `ALLOW` is refused.
/// 2. **At evaluation**, the applied effect is
///    [`Effect::meet`] of the provisional and the postcondition's, so the
///    result is no wider than the provisional whatever the load check did.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
/// [ADR-0038]: ../../../../../docs/adr/0038-policy-evaluation-phases-and-composition.md
/// [`When::provisional_effect`]: super::predicate::When::provisional_effect
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postcondition {
    id: RuleId,
    source: SourceLocation,
    effect: Effect,
    reason: Reason,
    when: When,
    unless: Unless,
}

impl Postcondition {
    /// Assemble a compiled postcondition. Crate-internal.
    pub(super) const fn new(
        id: RuleId,
        source: SourceLocation,
        effect: Effect,
        reason: Reason,
        when: When,
        unless: Unless,
    ) -> Self {
        Self {
            id,
            source,
            effect,
            reason,
            when,
            unless,
        }
    }

    /// The postcondition's identifier.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// Where it is written.
    #[must_use]
    pub const fn source(&self) -> &SourceLocation {
        &self.source
    }

    /// What it narrows to.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// The positive condition, including the provisional-effect selector.
    #[must_use]
    pub const fn when(&self) -> &When {
        &self.when
    }

    /// The negative condition.
    #[must_use]
    pub const fn unless(&self) -> &Unless {
        &self.unless
    }

    /// Which provisional effects this postcondition selects.
    ///
    /// Absent means all three, which is why the load check below quantifies
    /// over [`Effect::ALL`] in that case: a postcondition with no selector
    /// applies to an `ALLOW` too, so only `DENY` could be narrower than
    /// everything it selects.
    ///
    /// Reads both spellings of the selector, because the question "could this
    /// widen any effect it selects?" is about the *values*, and
    /// `provisional_effect = "REQUIRE_APPROVAL"` names the same one as
    /// `["REQUIRE_APPROVAL"]`. The parser still kept them apart; this is the
    /// one caller entitled to stop caring which it was.
    #[must_use]
    pub fn selects(&self) -> Vec<Effect> {
        self.when.provisional_effect.as_ref().map_or_else(
            || Effect::ALL.to_vec(),
            |named| named.values().copied().collect(),
        )
    }

    /// Whether this postcondition can only narrow.
    ///
    /// True when its effect is `⊑` every provisional effect it can select.
    /// Checked at load; the evaluator does not rely on it.
    #[must_use]
    pub fn narrows(&self) -> bool {
        self.selects()
            .into_iter()
            .all(|provisional| self.effect.narrower_or_equal(provisional))
    }
}

/// A policy compiled from one source, before composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    name: ProfileName,
    source: SourceLocation,
    extends: Option<ProfileName>,
    rules: Vec<Rule>,
    postconditions: Vec<Postcondition>,
}

impl Profile {
    /// Assemble a compiled profile. Crate-internal.
    pub(super) const fn new(
        name: ProfileName,
        source: SourceLocation,
        extends: Option<ProfileName>,
        rules: Vec<Rule>,
        postconditions: Vec<Postcondition>,
    ) -> Self {
        Self {
            name,
            source,
            extends,
            rules,
            postconditions,
        }
    }

    /// The profile's name.
    #[must_use]
    pub const fn name(&self) -> &ProfileName {
        &self.name
    }

    /// Where it came from.
    #[must_use]
    pub const fn source(&self) -> &SourceLocation {
        &self.source
    }

    /// What it extends, if anything.
    #[must_use]
    pub const fn extends(&self) -> Option<&ProfileName> {
        self.extends.as_ref()
    }

    /// Its rules, in source order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Its postconditions, in source order.
    #[must_use]
    pub fn postconditions(&self) -> &[Postcondition] {
        &self.postconditions
    }
}

/// A policy ready to evaluate: one profile, with its `extends` chain resolved.
///
/// The rules are the chain flattened in order — the extending profile's first,
/// then its parent's, then its parent's — which is the order
/// [`POLICY.md`] §3 states ("`extends` rules evaluate AFTER this file's") and
/// which [`super::compose`] makes safe by bounding what an extending profile
/// may contain.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    name: ProfileName,
    chain: Vec<ProfileName>,
    rules: Vec<Rule>,
    postconditions: Vec<Postcondition>,
}

impl CompiledPolicy {
    /// Assemble a composed policy. Crate-internal: [`super::compose`] is the
    /// only way in, so every policy has been through the non-widening check.
    pub(super) const fn new(
        name: ProfileName,
        chain: Vec<ProfileName>,
        rules: Vec<Rule>,
        postconditions: Vec<Postcondition>,
    ) -> Self {
        Self {
            name,
            chain,
            rules,
            postconditions,
        }
    }

    /// The profile this policy is.
    #[must_use]
    pub const fn name(&self) -> &ProfileName {
        &self.name
    }

    /// The `extends` chain, this profile first.
    #[must_use]
    pub fn chain(&self) -> &[ProfileName] {
        &self.chain
    }

    /// Every rule, in evaluation order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Every postcondition, in evaluation order.
    #[must_use]
    pub fn postconditions(&self) -> &[Postcondition] {
        &self.postconditions
    }

    /// The mandatory unconditional rule, which is always last.
    #[must_use]
    pub fn default_rule(&self) -> Option<&Rule> {
        self.rules.last().filter(|rule| rule.is_default())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProfileName, is_lower_kebab};
    use crate::policy::effect::Effect;
    use crate::policy::error::ValueError;
    use crate::policy::limits;
    use crate::policy::obligation::ProfileRef;

    #[test]
    fn the_identifier_grammar_is_bounded_ascii_kebab() {
        for good in [
            "a",
            "git",
            "deny-credential-paths",
            "a1",
            "x-1-y",
            "default",
        ] {
            assert!(is_lower_kebab(good, 64), "{good} must be accepted");
        }
        for bad in [
            "",
            "A",
            "Git",
            "1abc",
            "-abc",
            "abc-",
            "a--b",
            "a_b",
            "a.b",
            "a/b",
            "a b",
            "café",
            "deny\u{0}rule",
        ] {
            assert!(!is_lower_kebab(bad, 64), "{bad} must be refused");
        }
    }

    #[test]
    fn the_identifier_grammar_is_bounded() {
        let long = "a".repeat(limits::MAX_RULE_ID_CHARS);
        assert!(is_lower_kebab(&long, limits::MAX_RULE_ID_CHARS));
        let longer = "a".repeat(limits::MAX_RULE_ID_CHARS + 1);
        assert!(!is_lower_kebab(&longer, limits::MAX_RULE_ID_CHARS));
    }

    #[test]
    fn every_identifier_type_shares_the_grammar() {
        // One grammar, three uses: a mismatch between them would mean a name
        // accepted in one place and refused in another.
        assert!(ProfileName::new("balanced").is_ok());
        assert!(ProfileRef::new("oci-strict").is_some());
        for bad in ["Balanced", "", "-x", "a--b"] {
            assert_eq!(ProfileName::new(bad), Err(ValueError::MalformedProfileName));
            assert!(ProfileRef::new(bad).is_none());
        }
    }

    #[test]
    fn a_postcondition_with_no_selector_may_only_deny() {
        use super::Postcondition;
        use crate::policy::predicate::{Unless, When};
        use crate::policy::reason::Reason;
        use crate::policy::{RuleId, SourceLocation};

        let (Some(id), Some(at)) = (RuleId::new("p"), SourceLocation::new("t.toml", 1)) else {
            unreachable!("valid")
        };
        for effect in Effect::ALL {
            let post = Postcondition::new(
                id.clone(),
                at.clone(),
                effect,
                Reason::NoHumanAvailable,
                When::default(),
                Unless::default(),
            );
            assert_eq!(post.selects().len(), 3, "no selector means all three");
            assert_eq!(
                post.narrows(),
                effect == Effect::Deny,
                "{effect} with no selector"
            );
        }
    }

    #[test]
    fn a_postcondition_narrows_exactly_when_its_effect_is_below_every_selection() {
        use super::Postcondition;
        use crate::policy::predicate::{MatchValue, Unless, When};
        use crate::policy::reason::Reason;
        use crate::policy::{RuleId, SourceLocation};

        let (Some(id), Some(at)) = (RuleId::new("p"), SourceLocation::new("t.toml", 1)) else {
            unreachable!("valid")
        };
        let build = |effect: Effect, selects: Vec<Effect>| {
            Postcondition::new(
                id.clone(),
                at.clone(),
                effect,
                Reason::NoHumanAvailable,
                When {
                    provisional_effect: Some(MatchValue::In(selects)),
                    ..When::default()
                },
                Unless::default(),
            )
        };
        // The shipped shape: REQUIRE_APPROVAL becomes DENY.
        assert!(build(Effect::Deny, vec![Effect::RequireApproval]).narrows());
        // Equal is narrowing-or-equal, and so permitted.
        assert!(build(Effect::RequireApproval, vec![Effect::RequireApproval]).narrows());
        // The two widenings the ADR names.
        assert!(!build(Effect::Allow, vec![Effect::RequireApproval]).narrows());
        assert!(!build(Effect::RequireApproval, vec![Effect::Deny]).narrows());
        assert!(!build(Effect::Allow, vec![Effect::Deny]).narrows());
        // Quantified over every selection, not just the first.
        assert!(!build(Effect::RequireApproval, vec![Effect::Allow, Effect::Deny]).narrows());
        assert!(build(Effect::Deny, vec![Effect::Allow, Effect::RequireApproval]).narrows());
    }
}
