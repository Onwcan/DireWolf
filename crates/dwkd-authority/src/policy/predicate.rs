//! The closed predicate vocabulary, and what matching one means.
//!
//! [`POLICY.md`] §3: "Fields are a **fixed, typed set** populated by the
//! canonicaliser. A rule cannot invent a field; unknown keys fail at load."
//! This module is that set. It is a struct of optional typed fields, not a
//! map — the same shape, and for the same reason, as the capability
//! `ConstraintSet`: a map admits a key nobody defined, and the failure mode of
//! an undefined key is a predicate that quietly reads as absent.
//!
//! # There are no boolean combinators
//!
//! Implicit AND within a rule, implicit OR within a list, and `unless`. No
//! user-defined function, no regex against arbitrary input, no arithmetic, no
//! iteration, no nesting. A rule file is not a program, and
//! [`POLICY.md`] §3 records what would have to become true before a DSL is
//! reconsidered.
//!
//! # Absent means "does not constrain"; it never means "false"
//!
//! A predicate a rule does not write imposes nothing. A predicate a rule
//! *does* write, against an action that has no such attribute, does **not**
//! match — an `fs.read` has no argv, so `when.argv_safe = true` cannot be true
//! of it. That is the fail-closed direction for an `ALLOW` rule and the wrong
//! one for a `DENY`, which is why [`PredicateName::applies_to`] exists: a rule
//! whose predicates cannot apply to its own verbs is refused at load, so the
//! case never arises in a shipped profile.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use core::fmt;

use crate::capability::{Scope, ScopeFamily, SyntacticScope, Verb};

use super::action::{ArgvSafety, CanonicalAction, Environment, Novelty};
use super::context::{ConfigKey, Origin, PathAnchor, PolicyContext, TaintLevel};
use super::effect::Effect;
use super::value::{Cidr, ExecutableSpec, RulePath};
use crate::capability::{HostPattern, PrivacyClass};

/// A match predicate's right-hand side, in the shape the rule author wrote it.
///
/// [`POLICY.md`] §3's operator table documents **two** spellings for a match
/// predicate, and documents them for any field:
///
/// | operator | semantics |
/// |---|---|
/// | `eq` / implicit scalar | equality |
/// | list value | membership (`in`) |
///
/// So `when.verb = "fs.read"` and `when.verb = ["fs.read"]` are both valid
/// policy, and this enum is the reason they stay *different values* after
/// loading.
///
/// # Why not one `Vec`
///
/// An earlier loader read a scalar as a one-element list. That is a **parser
/// coercion**: two source shapes entering the compiled policy as one, so the
/// representation no longer says what the file said. It is the same class of
/// convenience as reading `"1"` as `1` — harmless in the case somebody tested,
/// and a place where strictness has quietly stopped applying. A strict loader
/// that coerces in one direction has a coercion; the number of directions is
/// not the property.
///
/// The two variants may of course *decide the same way*: `In(["fs.read"])`
/// matches exactly what `Eq("fs.read")` matches. That equivalence is a fact
/// about the matching semantics, established by [`MatchValue::any`] looking at
/// the variant, rather than a fact about the parser having thrown one of them
/// away.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchValue<T> {
    /// `field = value` — equality against exactly this value.
    Eq(T),
    /// `field = [a, b, c]` — membership. Never empty: a predicate nothing can
    /// satisfy is a rule that never fires written as one that does.
    In(Vec<T>),
}

impl<T> MatchValue<T> {
    /// Whether any named value satisfies `predicate`.
    ///
    /// Matches on the variant rather than flattening to a slice, so the two
    /// spellings are still two things at the point the decision is made.
    pub fn any(&self, mut predicate: impl FnMut(&T) -> bool) -> bool {
        match self {
            Self::Eq(value) => predicate(value),
            Self::In(values) => values.iter().any(predicate),
        }
    }

    /// The same, for a predicate that can fail to be *evaluated* — a rule-side
    /// path needing an anchor the context does not hold.
    ///
    /// # Errors
    ///
    /// Whatever `predicate` returns, on the first value that cannot be
    /// evaluated.
    pub fn try_any<E>(&self, mut predicate: impl FnMut(&T) -> Result<bool, E>) -> Result<bool, E> {
        match self {
            Self::Eq(value) => predicate(value),
            Self::In(values) => {
                for value in values {
                    if predicate(value)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Every value this condition names.
    ///
    /// For the callers that must reason about *all* of them — the load-time
    /// check that a postcondition cannot widen any provisional effect it
    /// selects. Not a way to collapse the variants: which one this is stays
    /// observable through [`MatchValue::is_scalar`].
    pub fn values(&self) -> impl Iterator<Item = &T> {
        match self {
            Self::Eq(value) => core::slice::from_ref(value).iter(),
            Self::In(values) => values.iter(),
        }
    }

    /// Whether the author wrote the scalar spelling.
    #[must_use]
    pub const fn is_scalar(&self) -> bool {
        matches!(self, Self::Eq(_))
    }

    /// How many values it names.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Eq(_) => 1,
            Self::In(values) => values.len(),
        }
    }

    /// Whether it names none. Unreachable for a loaded policy, which refuses
    /// an empty list; present so `len` has its companion.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: PartialEq> MatchValue<T> {
    /// Whether `candidate` is one of the named values.
    pub fn matches(&self, candidate: &T) -> bool {
        self.any(|value| value == candidate)
    }
}

/// Every predicate a rule may write, as a name.
///
/// Used for two things the loader needs and prose cannot give it:
/// deciding applicability, and naming a field in an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PredicateName {
    /// `when.verb`.
    Verb,
    /// `when.path_under`.
    PathUnder,
    /// `when.max_bytes`.
    MaxBytes,
    /// `when.executable_in`.
    ExecutableIn,
    /// `when.argv_safe`.
    ArgvSafe,
    /// `when.host_matches`.
    HostMatches,
    /// `when.ip_in`.
    IpIn,
    /// `when.destination_novel`.
    DestinationNovel,
    /// `when.environment`.
    Environment,
    /// `when.origin`.
    Origin,
    /// `when.taint_level`.
    TaintLevel,
    /// `when.privacy_class`.
    PrivacyClass,
    /// `when.provisional_effect` — postconditions only.
    ProvisionalEffect,
    /// `unless.config`.
    UnlessConfig,
    /// `unless.standing_grant`.
    UnlessStandingGrant,
}

impl PredicateName {
    /// Every predicate, in declaration order.
    pub const ALL: [Self; 15] = [
        Self::Verb,
        Self::PathUnder,
        Self::MaxBytes,
        Self::ExecutableIn,
        Self::ArgvSafe,
        Self::HostMatches,
        Self::IpIn,
        Self::DestinationNovel,
        Self::Environment,
        Self::Origin,
        Self::TaintLevel,
        Self::PrivacyClass,
        Self::ProvisionalEffect,
        Self::UnlessConfig,
        Self::UnlessStandingGrant,
    ];

    /// The TOML member name, without its `when.` or `unless.` prefix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verb => "verb",
            Self::PathUnder => "path_under",
            Self::MaxBytes => "max_bytes",
            Self::ExecutableIn => "executable_in",
            Self::ArgvSafe => "argv_safe",
            Self::HostMatches => "host_matches",
            Self::IpIn => "ip_in",
            Self::DestinationNovel => "destination_novel",
            Self::Environment => "environment",
            Self::Origin => "origin",
            Self::TaintLevel => "taint_level",
            Self::PrivacyClass => "privacy_class",
            Self::ProvisionalEffect => "provisional_effect",
            Self::UnlessConfig => "config",
            Self::UnlessStandingGrant => "standing_grant",
        }
    }

    /// Whether this predicate can ever be true of an action with this verb.
    ///
    /// The rule is the scope family: `path_under` and `max_bytes` are about a
    /// path, `executable_in` and `argv_safe` about an executable, `ip_in`
    /// about an endpoint. A predicate over a family the verb does not have is
    /// a predicate that is false for every action the rule could match, which
    /// makes the rule dead — so the loader refuses it rather than shipping a
    /// denial that never fires.
    ///
    /// The run-level predicates — origin, taint, privacy, environment — apply
    /// to everything, because every action happens in a run and somewhere.
    #[must_use]
    pub fn applies_to(self, verb: Verb) -> bool {
        match self {
            Self::Verb
            | Self::Environment
            | Self::Origin
            | Self::TaintLevel
            | Self::PrivacyClass
            | Self::ProvisionalEffect
            | Self::UnlessConfig
            | Self::UnlessStandingGrant => true,
            Self::PathUnder | Self::MaxBytes => verb.scope_family() == ScopeFamily::Path,
            Self::ExecutableIn | Self::ArgvSafe => verb.scope_family() == ScopeFamily::Executable,
            Self::HostMatches => matches!(
                verb.scope_family(),
                ScopeFamily::Endpoint | ScopeFamily::Domain
            ),
            Self::IpIn => verb.scope_family() == ScopeFamily::Endpoint,
            Self::DestinationNovel => matches!(
                verb.scope_family(),
                ScopeFamily::Endpoint | ScopeFamily::Domain | ScopeFamily::ChannelTarget
            ),
        }
    }

    /// Why a predicate does not apply, for the load error.
    #[must_use]
    pub const fn requires(self) -> &'static str {
        match self {
            Self::PathUnder | Self::MaxBytes => "it applies to fs verbs, whose scope is a path",
            Self::ExecutableIn | Self::ArgvSafe => {
                "it applies to process verbs, whose scope is an executable"
            }
            Self::HostMatches => "it applies to network and browser verbs",
            Self::IpIn => "it applies to network verbs, whose scope is an endpoint",
            Self::DestinationNovel => {
                "it applies to verbs with a destination: network, browser, channel"
            }
            _ => "it applies to every verb",
        }
    }
}

impl fmt::Display for PredicateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The positive half of a rule's condition.
///
/// Every field absent is the `default` rule: it matches everything, which is
/// why exactly one rule is allowed to be shaped like this and why it must be
/// last.
/// The positive half of a rule's condition, continued.
///
/// # Two kinds of field, and the shapes each accepts
///
/// The ten **match** predicates take a [`MatchValue`], so the scalar and list
/// spellings [`POLICY.md`] §3 documents both survive loading as themselves.
/// The three **scalar** predicates take a value: a numeric comparison and two
/// canonicaliser-derived classifications are not membership tests, and a list
/// there is a type error rather than a shorthand.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct When {
    /// `verb` — equality or membership.
    pub verb: Option<MatchValue<Verb>>,
    /// `path_under` — component-wise containment under the named path, or
    /// under any of them.
    pub path_under: Option<MatchValue<RulePath>>,
    /// `max_bytes` — the action moves no more than this. **Scalar only**: a
    /// numeric bound is not a membership test, and `max_bytes = [1, 2]` names
    /// no bound.
    pub max_bytes: Option<u64>,
    /// `executable_in` — the named executable, or any of them.
    pub executable_in: Option<MatchValue<ExecutableSpec>>,
    /// `argv_safe` — the canonicaliser's classification equals this.
    /// **Scalar only**: it is a boolean in the source, and a list of booleans
    /// is not a predicate anybody meant to write.
    pub argv_safe: Option<ArgvSafety>,
    /// `host_matches` — label-aware containment by the named pattern, or any.
    pub host_matches: Option<MatchValue<HostPattern>>,
    /// `ip_in` — the destination address is in the named range, or any.
    pub ip_in: Option<MatchValue<Cidr>>,
    /// `destination_novel` — the run has, or has not, been here before.
    /// **Scalar only**, as `argv_safe`.
    pub destination_novel: Option<Novelty>,
    /// `environment` — equality or membership.
    pub environment: Option<MatchValue<Environment>>,
    /// `origin` — equality or membership.
    pub origin: Option<MatchValue<Origin>>,
    /// `taint_level` — equality or membership.
    pub taint_level: Option<MatchValue<TaintLevel>>,
    /// `privacy_class` — equality or membership.
    pub privacy_class: Option<MatchValue<PrivacyClass>>,
    /// `provisional_effect` — equality or membership. Postconditions only; the
    /// loader refuses it on a primary rule.
    pub provisional_effect: Option<MatchValue<Effect>>,
}

/// The negative half.
///
/// Two predicates, both of which suppress an otherwise-matching rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unless {
    /// `config` — this kernel configuration flag is set.
    pub config: Option<ConfigKey>,
    /// `standing_grant` — a standing grant covers the action.
    ///
    /// Parsed because it is part of the format, and never satisfied before M6:
    /// see [`StandingGrantState`](super::context::StandingGrantState).
    pub standing_grant: Option<bool>,
}

/// A canonical value a predicate needed and the input did not carry.
///
/// [`POLICY.md`] §4 step 1 asserts that the request is fully canonicalised.
/// This is what that assert has to say when it fails, and it is typed so the
/// explanation can name what was missing rather than saying "no match".
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unevaluable {
    /// A rule-side path named an anchor the context does not resolve.
    PathAnchor(PathAnchor),
    /// A rule constrained the destination address and the action has none.
    ResolvedAddress,
}

impl fmt::Display for Unevaluable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathAnchor(anchor) => write!(f, "the path anchor {anchor} is unresolved"),
            Self::ResolvedAddress => f.write_str("the destination address is unresolved"),
        }
    }
}

/// Whether a rule's predicates matched, or could not be evaluated.
///
/// The third case is not a failure of the rule — it is a failure of the
/// *input*, and the evaluator turns it into a denial naming what was missing.
/// Folding it into `false` would silently disable a deny rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Every predicate the rule wrote is true of this action.
    Yes,
    /// At least one is false.
    No,
    /// A predicate needed a canonical value the input does not carry.
    Unevaluable(Unevaluable),
}

impl Match {
    /// `Yes` when the condition holds.
    const fn from_bool(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }

    /// Conjunction, short-circuiting on the first `No` and propagating an
    /// unevaluable predicate over it.
    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unevaluable(why), _) => Self::Unevaluable(why),
            (Self::No, _) => Self::No,
            (Self::Yes, other) => other,
        }
    }
}

impl When {
    /// Which predicates this condition writes.
    #[must_use]
    pub fn present(&self) -> Vec<PredicateName> {
        let mut names = Vec::new();
        let mut note = |present: bool, name: PredicateName| {
            if present {
                names.push(name);
            }
        };
        note(self.verb.is_some(), PredicateName::Verb);
        note(self.path_under.is_some(), PredicateName::PathUnder);
        note(self.max_bytes.is_some(), PredicateName::MaxBytes);
        note(self.executable_in.is_some(), PredicateName::ExecutableIn);
        note(self.argv_safe.is_some(), PredicateName::ArgvSafe);
        note(self.host_matches.is_some(), PredicateName::HostMatches);
        note(self.ip_in.is_some(), PredicateName::IpIn);
        note(
            self.destination_novel.is_some(),
            PredicateName::DestinationNovel,
        );
        note(self.environment.is_some(), PredicateName::Environment);
        note(self.origin.is_some(), PredicateName::Origin);
        note(self.taint_level.is_some(), PredicateName::TaintLevel);
        note(self.privacy_class.is_some(), PredicateName::PrivacyClass);
        note(
            self.provisional_effect.is_some(),
            PredicateName::ProvisionalEffect,
        );
        names
    }

    /// Whether this condition writes nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.present().is_empty()
    }

    /// Whether every predicate written here holds of this action.
    ///
    /// `provisional_effect` is not evaluated here: it selects a postcondition
    /// and is checked by [`super::eval`] against a value no caller supplies.
    #[must_use]
    pub fn matches(&self, action: &CanonicalAction, context: &PolicyContext) -> Match {
        let verb = action.capability().verb();
        let scope = action.capability().scope();

        let mut result =
            Match::from_bool(self.verb.as_ref().is_none_or(|named| named.matches(&verb)));
        result = result.and(Match::from_bool(
            self.environment
                .as_ref()
                .is_none_or(|named| named.matches(action.environment())),
        ));
        result = result.and(Match::from_bool(
            self.origin
                .as_ref()
                .is_none_or(|named| named.matches(&context.origin())),
        ));
        result = result.and(Match::from_bool(
            self.taint_level
                .as_ref()
                .is_none_or(|named| named.matches(&context.taint())),
        ));
        result = result.and(Match::from_bool(
            self.privacy_class
                .as_ref()
                .is_none_or(|named| named.matches(&context.privacy())),
        ));
        result = result.and(Match::from_bool(self.max_bytes.is_none_or(|limit| {
            action.byte_count().is_some_and(|bytes| bytes <= limit)
        })));
        result = result.and(Match::from_bool(
            self.argv_safe
                .is_none_or(|wanted| action.argv_safety() == Some(wanted)),
        ));
        result = result
            .and(Match::from_bool(self.destination_novel.is_none_or(
                |wanted| action.destination_novelty() == Some(wanted),
            )));
        result = result.and(Match::from_bool(
            self.host_matches
                .as_ref()
                .is_none_or(|named| host_matches(named, scope)),
        ));
        if result == Match::No {
            return result;
        }

        // The three that can fail to *evaluate* rather than to hold, because
        // they need a canonical value the input may not carry.
        if let Some(ranges) = &self.ip_in {
            match address_in(ranges, action) {
                Ok(matched) => result = result.and(Match::from_bool(matched)),
                Err(why) => return Match::Unevaluable(why),
            }
        }
        if let Some(paths) = &self.path_under {
            match path_under(paths, context, scope) {
                Ok(matched) => result = result.and(Match::from_bool(matched)),
                Err(anchor) => return Match::Unevaluable(Unevaluable::PathAnchor(anchor)),
            }
        }
        if let Some(specs) = &self.executable_in {
            match executable_in(specs, context, scope) {
                Ok(matched) => result = result.and(Match::from_bool(matched)),
                Err(anchor) => return Match::Unevaluable(Unevaluable::PathAnchor(anchor)),
            }
        }
        result
    }
}

/// Whether the named rule-side path contains the action's canonical path,
/// or any of them does.
fn path_under(
    named: &MatchValue<RulePath>,
    context: &PolicyContext,
    scope: &Scope,
) -> Result<bool, PathAnchor> {
    let Scope::Path(candidate) = scope else {
        // A universal scope is not a path. `fs.read:*` names every path, and
        // "every path" is not under any particular root -- treating it as
        // matching would let a wildcard capability satisfy a rule written
        // about one directory.
        return Ok(false);
    };
    named.try_any(|path| path.contains(context.anchors(), candidate))
}

/// Whether the named rule-side executable is the action's, or any of them is.
fn executable_in(
    named: &MatchValue<ExecutableSpec>,
    context: &PolicyContext,
    scope: &Scope,
) -> Result<bool, PathAnchor> {
    let Scope::Executable(candidate) = scope else {
        return Ok(false);
    };
    named.try_any(|spec| spec.matches(context.anchors(), candidate))
}

/// Whether any rule-side host pattern covers the action's destination.
///
/// Containment is [`HostPattern::contains`], which compares **labels**. The
/// bug it avoids is `ends_with("example.com")`, under which `*.example.com`
/// would cover `evil-example.com`; and a wildcard cannot sit in TLD position
/// because the pattern grammar refuses it.
fn host_matches(named: &MatchValue<HostPattern>, scope: &Scope) -> bool {
    let candidate = match scope {
        Scope::Syntactic(SyntacticScope::Endpoint(endpoint)) => endpoint.host(),
        Scope::Syntactic(SyntacticScope::Domain(host)) => host,
        _ => return false,
    };
    named.any(|pattern| pattern.contains(candidate))
}

/// Whether the action's destination address lies in one of the ranges.
///
/// One address, so there is one reading. An earlier draft took a *set* and
/// asked whether every member was in range; an adversarial fixture found the
/// hole. "Every" is fail-closed for an `ALLOW` and fail-**open** for a `DENY`,
/// so a host answering with one public and one loopback address escaped a rule
/// denying the loopback. "Any" has the mirror-image problem. No single
/// quantifier over a set is safe in both directions, which is why
/// [`CanonicalAction::destination_ip`] carries exactly one.
///
/// **That makes the policy decision unambiguous; it does not make the system
/// rebinding-resistant.** Whether the connection actually uses the address
/// policy judged is M4's and the broker's to guarantee — see
/// [`CanonicalAction::destination_ip`] for the contract that owes.
///
/// An action with no address at all is **unevaluable**, not a non-match: a
/// network rule evaluated against an action nobody resolved is exactly the
/// uncanonicalised input [`POLICY.md`] §4 step 1 refuses.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
fn address_in(named: &MatchValue<Cidr>, action: &CanonicalAction) -> Result<bool, Unevaluable> {
    let address = action
        .destination_ip()
        .ok_or(Unevaluable::ResolvedAddress)?;
    Ok(named.any(|range| range.contains(&address)))
}

impl Unless {
    /// Which predicates this condition writes.
    #[must_use]
    pub fn present(&self) -> Vec<PredicateName> {
        let mut names = Vec::new();
        if self.config.is_some() {
            names.push(PredicateName::UnlessConfig);
        }
        if self.standing_grant.is_some() {
            names.push(PredicateName::UnlessStandingGrant);
        }
        names
    }

    /// Whether this condition writes nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.config.is_none() && self.standing_grant.is_none()
    }

    /// Whether the rule is suppressed.
    ///
    /// `unless.standing_grant = true` suppresses when a grant is held, which
    /// through M5 is never — the state type has one variant and it is
    /// `Unavailable`. `unless.standing_grant = false` suppresses when one is
    /// *not* held, which through M5 is always; it is accepted because the
    /// grammar admits a boolean, and no shipped profile writes it.
    #[must_use]
    pub fn suppresses(&self, context: &PolicyContext) -> bool {
        let by_config = self.config.is_some_and(|key| context.config().is_set(key));
        let by_grant = self
            .standing_grant
            .is_some_and(|wanted| context.standing_grant().is_held() == wanted);
        by_config || by_grant
    }
}

#[cfg(test)]
mod tests {
    use super::{Match, PredicateName};
    use crate::capability::{Action, Namespace, Verb};

    fn verb(namespace: Namespace, action: Action) -> Verb {
        let Some(verb) = Verb::new(namespace, action) else {
            unreachable!("a documented pair")
        };
        verb
    }

    #[test]
    fn predicate_names_are_distinct_and_non_empty() {
        let mut seen: Vec<&str> = Vec::new();
        for name in PredicateName::ALL {
            let text = name.as_str();
            assert!(!text.is_empty());
            assert!(!seen.contains(&text), "duplicate predicate name {text}");
            seen.push(text);
        }
        assert_eq!(seen.len(), PredicateName::ALL.len());
    }

    #[test]
    fn path_predicates_apply_to_fs_verbs_and_nothing_else() {
        let fs = verb(Namespace::Fs, Action::Read);
        let exec = verb(Namespace::Process, Action::Exec);
        let https = verb(Namespace::Network, Action::Https);
        for name in [PredicateName::PathUnder, PredicateName::MaxBytes] {
            assert!(name.applies_to(fs), "{name} applies to fs");
            assert!(!name.applies_to(exec), "{name} must not apply to process");
            assert!(!name.applies_to(https), "{name} must not apply to network");
        }
    }

    #[test]
    fn executable_predicates_apply_to_process_verbs_and_nothing_else() {
        let fs = verb(Namespace::Fs, Action::Write);
        let exec = verb(Namespace::Process, Action::Exec);
        for name in [PredicateName::ExecutableIn, PredicateName::ArgvSafe] {
            assert!(name.applies_to(exec), "{name} applies to process");
            assert!(!name.applies_to(fs), "{name} must not apply to fs");
        }
    }

    #[test]
    fn address_and_host_predicates_track_their_scope_families() {
        let https = verb(Namespace::Network, Action::Https);
        let browser = verb(Namespace::Browser, Action::Use);
        let channel = verb(Namespace::Channel, Action::Send);
        let fs = verb(Namespace::Fs, Action::Read);

        assert!(PredicateName::HostMatches.applies_to(https));
        assert!(PredicateName::HostMatches.applies_to(browser));
        assert!(!PredicateName::HostMatches.applies_to(fs));

        // ip_in is endpoints only: a browser domain is a name, not an address.
        assert!(PredicateName::IpIn.applies_to(https));
        assert!(!PredicateName::IpIn.applies_to(browser));

        for applicable in [https, browser, channel] {
            assert!(PredicateName::DestinationNovel.applies_to(applicable));
        }
        assert!(!PredicateName::DestinationNovel.applies_to(fs));
    }

    #[test]
    fn run_level_predicates_apply_to_every_verb() {
        for name in [
            PredicateName::Verb,
            PredicateName::Environment,
            PredicateName::Origin,
            PredicateName::TaintLevel,
            PredicateName::PrivacyClass,
            PredicateName::UnlessConfig,
            PredicateName::UnlessStandingGrant,
        ] {
            for v in Verb::ALL {
                assert!(name.applies_to(*v), "{name} must apply to {v}");
            }
        }
    }

    #[test]
    fn every_predicate_applies_to_something() {
        for name in PredicateName::ALL {
            assert!(
                Verb::ALL.iter().any(|v| name.applies_to(*v)),
                "{name} applies to no verb at all, so no rule could use it"
            );
        }
    }

    #[test]
    fn conjunction_propagates_an_unevaluable_predicate_over_a_plain_no() {
        use super::Unevaluable;
        use crate::policy::context::PathAnchor;
        let unresolved = Match::Unevaluable(Unevaluable::PathAnchor(PathAnchor::Workspace));
        assert_eq!(unresolved.and(Match::No), unresolved);
        assert_eq!(Match::Yes.and(unresolved), unresolved);
        assert_eq!(Match::Yes.and(Match::Yes), Match::Yes);
        assert_eq!(Match::No.and(Match::Yes), Match::No);
        // A `No` reached first still short-circuits: the rule did not match,
        // and no canonical value was needed to know that.
        assert_eq!(Match::No.and(unresolved), Match::No);
        assert_ne!(
            Unevaluable::ResolvedAddress,
            Unevaluable::PathAnchor(PathAnchor::Workspace)
        );
    }
}
