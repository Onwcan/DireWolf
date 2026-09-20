//! `extends`, and why an extending profile cannot widen the one it extends.
//!
//! # The requirement
//!
//! [`POLICY.md`] §7: "A profile may only *narrow* the profile it `extends`.
//! Attempting to widen fails at load time with an error naming both rules."
//!
//! That is a statement about **every possible input**, and proving it over
//! arbitrary predicates would mean deciding implication between them —
//! "does `path_under = ${WORKSPACE}` imply `path_under = ${WORKSPACE}/src`?"
//! — for a predicate set that includes host wildcards, CIDR ranges and
//! component-wise path containment. That is a decision procedure, it would be
//! the most security-critical code in the loader, and a fixture suite
//! demonstrating it on a hundred cases would prove nothing about the hundred
//! and first.
//!
//! # The V1 subset, and why it is decidable
//!
//! So M3c does not attempt it. It ships a restricted composition whose
//! non-widening property needs no reasoning about predicates at all
//! ([ADR-0038]):
//!
//! > **An extending profile may only add rules whose effect is `DENY`.**
//!
//! Rules compose by concatenation, the child's first, exactly as
//! [`POLICY.md`] §3 says ("`extends` rules evaluate AFTER this file's"). So for
//! any action, first-match evaluation of the composed policy returns either:
//!
//! * a child rule — whose effect is `DENY`, the bottom of the lattice, and
//!   therefore `⊑` whatever the parent would have returned; or
//! * the parent's own result, unchanged, because no child rule matched.
//!
//! In both cases `composed(a) ⊑ parent(a)`, for every `a`. The proof is two
//! lines and quantifies over the whole input space, which is what the
//! requirement asks for and what a fixture suite cannot give.
//!
//! The same argument covers postconditions, which an extending profile may
//! also only add as `DENY`, and which already cannot widen on their own
//! account ([`Postcondition::narrows`](super::Postcondition::narrows)).
//!
//! # What that costs, stated plainly
//!
//! A child cannot relax anything — correct, and the point — but it also cannot
//! *add a permission*, even one its parent would have permitted anyway. A
//! profile wanting to allow something its parent denies is not an extension of
//! that parent; it is a different profile, and the three shipped packs are
//! standalone for exactly that reason. `extends` is for the operator who wants
//! `balanced` plus three site-specific denials, which is the case
//! [`POLICY.md`] describes and the one worth supporting.
//!
//! The natural V2 is to compose by [`Effect::meet`] of the two profiles'
//! independent results, which lifts the DENY-only restriction and keeps
//! non-widening by the same lattice law. It costs a second evaluation per
//! decision and a merge rule for obligations and approval shapes, and it is
//! recorded in [ADR-0038] as the successor rather than built now.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md
//! [ADR-0038]: ../../../../../docs/adr/0038-policy-evaluation-phases-and-composition.md

use super::effect::Effect;
use super::error::PolicyLoadError;
use super::limits;
use super::rule::{CompiledPolicy, Profile, ProfileName};

/// Compose `name` with everything it extends, refusing anything that could
/// widen.
///
/// `profiles` is the bounded set the caller supplies. Nothing here reads a
/// directory or searches for a parent by name: the authority layer that owns
/// the policy directory decides which files exist and hands them in, so the
/// loader stays pure and a profile cannot pull in a file nobody reviewed.
///
/// # Errors
///
/// [`PolicyLoadError::ExtendsUnknownProfile`] for a parent the load was not
/// given, [`PolicyLoadError::ExtendsCycle`] for a chain that repeats,
/// [`PolicyLoadError::ExtendsTooDeep`] past [`limits::MAX_EXTENDS_DEPTH`],
/// [`PolicyLoadError::WideningExtension`] for a child rule that is not `DENY`,
/// [`PolicyLoadError::ExtendsShadowsRuleId`] for an id a parent already uses,
/// [`PolicyLoadError::ExtendsRedeclaresDefault`] for a child `default`, and
/// [`PolicyLoadError::DefaultRuleMissing`] if the root of the chain has none.
pub fn compose(
    name: &ProfileName,
    profiles: &[Profile],
) -> Result<CompiledPolicy, PolicyLoadError> {
    let chain = resolve_chain(name, profiles)?;

    // Every profile but the last in the chain is *extending*, so every one of
    // them is restricted. The last is the root and owns the default.
    let Some((root, extenders)) = chain.split_last() else {
        unreachable!("resolve_chain returns at least the named profile")
    };

    for profile in extenders {
        check_extender(profile, root, extenders)?;
    }

    let mut rules = Vec::new();
    let mut postconditions = Vec::new();
    for profile in &chain {
        rules.extend(profile.rules().iter().cloned());
        postconditions.extend(profile.postconditions().iter().cloned());
    }

    // The root's `default` is last in the root, and the root is last in the
    // chain, so it is last overall -- which the evaluator relies on and which
    // is cheaper to assert than to trust.
    if !rules.last().is_some_and(super::rule::Rule::is_default) {
        return Err(PolicyLoadError::DefaultRuleMissing {
            at: root.source().clone(),
        });
    }

    Ok(CompiledPolicy::new(
        name.clone(),
        chain.iter().map(|p| p.name().clone()).collect(),
        rules,
        postconditions,
    ))
}

/// The profiles to evaluate, this one first and the root last.
fn resolve_chain<'a>(
    name: &ProfileName,
    profiles: &'a [Profile],
) -> Result<Vec<&'a Profile>, PolicyLoadError> {
    let find = |wanted: &ProfileName| profiles.iter().find(|p| p.name() == wanted);
    let Some(mut current) = find(name) else {
        return Err(PolicyLoadError::ExtendsUnknownProfile {
            at: super::SourceLocation::synthetic(),
            name: name.to_string(),
        });
    };

    let mut chain = vec![current];
    let mut seen = vec![current.name().clone()];
    while let Some(parent) = current.extends() {
        if seen.contains(parent) {
            let mut cycle: Vec<String> = seen.iter().map(ProfileName::to_string).collect();
            cycle.push(parent.to_string());
            return Err(PolicyLoadError::ExtendsCycle { chain: cycle });
        }
        let Some(next) = find(parent) else {
            return Err(PolicyLoadError::ExtendsUnknownProfile {
                at: current.source().clone(),
                name: parent.to_string(),
            });
        };
        // Bounded before descending, not after: the depth check is what stops
        // a long chain, and a cycle is already impossible by `seen`.
        if chain.len() >= limits::MAX_EXTENDS_DEPTH {
            let mut too_deep: Vec<String> = seen.iter().map(ProfileName::to_string).collect();
            too_deep.push(parent.to_string());
            return Err(PolicyLoadError::ExtendsTooDeep {
                chain: too_deep,
                limit: limits::MAX_EXTENDS_DEPTH,
            });
        }
        seen.push(parent.clone());
        chain.push(next);
        current = next;
    }
    Ok(chain)
}

/// Every restriction on a profile that extends another.
fn check_extender(
    profile: &Profile,
    root: &Profile,
    extenders: &[&Profile],
) -> Result<(), PolicyLoadError> {
    for rule in profile.rules() {
        // Unreachable: the loader refuses a `default` in a profile that
        // declares `extends`, which is every profile reaching this loop.
        // Kept because composition is the layer that would notice if the two
        // ever disagreed, and the cost is one comparison per rule at load.
        if rule.is_default() {
            return Err(PolicyLoadError::ExtendsRedeclaresDefault {
                at: rule.source().clone(),
            });
        }
        if rule.effect() != Effect::Deny {
            return Err(PolicyLoadError::WideningExtension {
                at: rule.source().clone(),
                id: rule.id().to_string(),
                detail: WIDENING_DETAIL,
            });
        }
        check_id_is_fresh(rule.id().as_str(), rule.source(), profile, root, extenders)?;
    }
    for post in profile.postconditions() {
        if post.effect() != Effect::Deny {
            return Err(PolicyLoadError::WideningExtension {
                at: post.source().clone(),
                id: post.id().to_string(),
                detail: WIDENING_DETAIL,
            });
        }
        check_id_is_fresh(post.id().as_str(), post.source(), profile, root, extenders)?;
    }
    Ok(())
}

const WIDENING_DETAIL: &str = "an extending profile may only add DENY rules, because DENY is the only effect \
     that is narrower than every result its parent could return";

/// Whether an id is already used anywhere else in the chain.
///
/// Shadowing by id is refused separately from widening, because it is a
/// different failure: a child rule taking a parent's id makes an audit record
/// name a rule the reader will look up in the wrong file. That it currently
/// could not also widen is not a reason to allow the confusion.
fn check_id_is_fresh(
    id: &str,
    at: &super::SourceLocation,
    profile: &Profile,
    root: &Profile,
    extenders: &[&Profile],
) -> Result<(), PolicyLoadError> {
    let others = extenders
        .iter()
        .copied()
        .chain(core::iter::once(root))
        .filter(|other| other.name() != profile.name());
    for other in others {
        let clashes = other.rules().iter().any(|r| r.id().as_str() == id)
            || other.postconditions().iter().any(|p| p.id().as_str() == id);
        if clashes {
            return Err(PolicyLoadError::ExtendsShadowsRuleId {
                at: at.clone(),
                id: id.to_owned(),
                parent: other.name().to_string(),
            });
        }
    }
    Ok(())
}
