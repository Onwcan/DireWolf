//! The two-phase evaluator.
//!
//! # `would_require_approval` is not an input, and cannot be
//!
//! [`POLICY.md`] §3 ships this rule:
//!
//! ```toml
//! [[rule]]
//! id     = "deny-approval-needed-when-unattended"
//! effect = "DENY"
//! reason = "NO_HUMAN_AVAILABLE"
//! when.origin                 = "scheduled"
//! when.would_require_approval = true
//! unless.standing_grant       = true
//! ```
//!
//! Read it as a phase-one predicate and it is either circular — the answer
//! depends on the evaluation it is part of — or unreachable, because it sits
//! after `approve-novel-exec` in a first-match list and a first match returns.
//! Read it as a *caller-supplied boolean* and it is an authority the caller
//! holds: a runtime that says `would_require_approval = false` has turned off
//! every unattended denial, which is [ADR-0028]'s finding C1 in a new field.
//!
//! So it is neither. The fact is [`Effect::RequireApproval`] being the
//! provisional result, and the rule is a **postcondition** whose selector is
//! `when.provisional_effect = ["REQUIRE_APPROVAL"]` — a value this function
//! computes and passes to phase two, which no [`PolicyContext`] carries and no
//! constructor accepts. [`would_require_approval`] below is the whole of it,
//! and it takes an [`Effect`], not a caller.
//!
//! # Postconditions can only narrow
//!
//! Twice over. [`Postcondition::narrows`] is checked at load, and the applied
//! effect here is [`Effect::meet`] of the running effect and the
//! postcondition's — so even a postcondition that somehow reached this
//! function without the load check cannot widen the decision.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md
//! [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md

use super::action::CanonicalAction;
use super::context::PolicyContext;
use super::effect::Effect;
use super::obligation::Obligations;
use super::predicate::{Match, Unevaluable};
use super::reason::Reason;
use super::rule::{CompiledPolicy, Postcondition, Rule};
use super::{Decision, MatchedRule};

/// Whether approval would be required, which is a fact about the evaluation
/// and not about the caller.
///
/// The one place the concept exists. It takes the provisional effect; there is
/// no overload taking a context, a request or a boolean, and adding one would
/// be the bypass this module's header describes.
#[must_use]
pub const fn would_require_approval(provisional: Effect) -> bool {
    matches!(provisional, Effect::RequireApproval)
}

/// Decide.
///
/// Pure: no I/O, no clock, no randomness, no iteration over a hash map. The
/// same policy, action and context return the same decision, byte for byte,
/// however many times it is called and in whatever order relative to anything
/// else.
///
/// The `default` rule is mandatory and unconditional, so phase one always
/// matches something and this function is total.
#[must_use]
pub fn evaluate(
    policy: &CompiledPolicy,
    action: &CanonicalAction,
    context: &PolicyContext,
) -> Decision {
    let capability = action.capability().clone();

    // ---- phase one: ordered primary rules, first match wins ---------------
    let Some(matched) = first_match(policy, action, context) else {
        // Unreachable while `default` is mandatory, unconditional and last,
        // which `load` and `compose` both enforce. Denying is the only honest
        // answer to "the policy has no default": returning an Option here
        // would move the decision to a caller who has less to go on.
        return unmatched(policy, capability);
    };

    match matched {
        Matched::Unresolved { rule, why } => {
            let at = MatchedRule::new(
                rule.id().clone(),
                rule.source().clone(),
                Reason::UnresolvedCanonicalInput,
            );
            Decision::not_evaluated(at.clone(), at, Vec::new(), capability, why)
        }
        Matched::Rule(rule) => {
            let primary = MatchedRule::new(rule.id().clone(), rule.source().clone(), rule.reason());
            let mut effect = rule.effect();
            let mut deciding = primary.clone();
            let mut applied = Vec::new();

            // ---- phase two: postconditions, each narrowing or nothing -----
            for post in policy.postconditions() {
                if !selects(post, effect) {
                    continue;
                }
                match post.when().matches(action, context) {
                    // A postcondition whose own path predicate cannot be
                    // evaluated denies, for the same reason a rule's does.
                    Match::Unevaluable(why) => {
                        let at = MatchedRule::new(
                            post.id().clone(),
                            post.source().clone(),
                            Reason::UnresolvedCanonicalInput,
                        );
                        applied.push(at.clone());
                        return Decision::not_evaluated(at, primary, applied, capability, why);
                    }
                    Match::No => continue,
                    Match::Yes => {}
                }
                if post.unless().suppresses(context) {
                    continue;
                }
                // The meet, not an assignment. `narrows()` was checked at
                // load; this makes widening unrepresentable rather than
                // merely refused.
                let narrowed = effect.meet(post.effect());
                applied.push(MatchedRule::new(
                    post.id().clone(),
                    post.source().clone(),
                    post.reason(),
                ));
                if narrowed != effect {
                    deciding =
                        MatchedRule::new(post.id().clone(), post.source().clone(), post.reason());
                }
                effect = narrowed;
            }

            // An approval shape describes what a human could grant, so it
            // survives only while approval is still what the decision asks
            // for. Obligations are conditions on a permission, so a denial
            // carries none.
            let approval = match effect {
                Effect::RequireApproval => rule.approval().cloned(),
                Effect::Allow | Effect::Deny => None,
            };
            let obligations = match effect {
                Effect::Allow | Effect::RequireApproval => rule.obligations().clone(),
                Effect::Deny => Obligations::none(),
            };

            Decision::new(
                effect,
                deciding,
                primary,
                applied,
                capability,
                approval,
                obligations,
            )
        }
    }
}

/// What phase one produced.
enum Matched<'a> {
    /// A rule matched.
    Rule(&'a Rule),
    /// A rule's predicate needed a canonical value the input does not carry.
    Unresolved {
        /// The rule that needed it.
        rule: &'a Rule,
        /// Which value.
        why: Unevaluable,
    },
}

/// Scan the rules in order and stop at the first that matches and is not
/// suppressed.
///
/// Source order, always. No priority score, no specificity ranking, no hash
/// iteration, and nothing that could reorder between runs.
fn first_match<'a>(
    policy: &'a CompiledPolicy,
    action: &CanonicalAction,
    context: &PolicyContext,
) -> Option<Matched<'a>> {
    for rule in policy.rules() {
        match rule.when().matches(action, context) {
            Match::Unevaluable(why) => {
                return Some(Matched::Unresolved { rule, why });
            }
            Match::No => continue,
            Match::Yes => {}
        }
        if rule.unless().suppresses(context) {
            continue;
        }
        return Some(Matched::Rule(rule));
    }
    None
}

/// Whether a postcondition applies to this provisional effect.
///
/// The effect is the *running* one, so a chain of postconditions each sees the
/// decision as it stands. A postcondition selecting `REQUIRE_APPROVAL` after
/// an earlier one has already narrowed to `DENY` does not fire, which is what
/// "would require approval" means once it no longer would.
fn selects(post: &Postcondition, effect: Effect) -> bool {
    post.when()
        .provisional_effect
        .as_ref()
        .is_none_or(|named| named.matches(&effect))
}

/// The decision for a policy with no matching rule at all.
///
/// Only reachable if the mandatory default were absent, which the loader and
/// the composer both refuse. Denying with the profile's own name in the
/// location keeps it explainable rather than silent.
fn unmatched(policy: &CompiledPolicy, capability: crate::capability::Capability) -> Decision {
    let Some(id) = super::RuleId::new(super::RuleId::DEFAULT) else {
        unreachable!("the reserved id is a valid id")
    };
    let at = MatchedRule::new(
        id,
        super::SourceLocation::synthetic(),
        Reason::NoMatchingRule,
    );
    let _ = policy;
    Decision::new(
        Effect::Deny,
        at.clone(),
        at,
        Vec::new(),
        capability,
        None,
        Obligations::none(),
    )
}

#[cfg(test)]
mod tests {
    use super::would_require_approval;
    use crate::policy::effect::Effect;

    #[test]
    fn approval_is_required_exactly_when_the_provisional_effect_says_so() {
        assert!(would_require_approval(Effect::RequireApproval));
        assert!(!would_require_approval(Effect::Allow));
        assert!(!would_require_approval(Effect::Deny));
    }

    #[test]
    fn the_fact_is_a_function_of_the_effect_and_of_nothing_else() {
        // The signature is the property: one argument, and it is an Effect.
        // A version of this taking a PolicyContext, a request or a bool would
        // be the unattended bypass, so there is no such overload to call.
        let derived: Vec<bool> = Effect::ALL
            .into_iter()
            .map(would_require_approval)
            .collect();
        assert_eq!(derived, vec![false, true, false]);
    }
}
