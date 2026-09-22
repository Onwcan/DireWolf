//! Attenuation: the only operation that produces a capability from a
//! capability.
//!
//! [`CAPABILITIES.md`] §4 is categorical:
//!
//! > Only narrowing operations exist in the API. There is **no widening
//! > operation in the kernel's interface at all** — not a privileged one, not
//! > an internal one.
//!
//! and §8 says why:
//!
//! > Widening APIs "for internal use" — every such API becomes the bypass.
//!
//! So this module has one function, it returns a `Result`, and the success
//! branch is reached only after the candidate has been checked against its
//! parent with the same [`Capability::contains`] every other caller uses. The
//! guarantee is therefore structural: a `Capability` that came out of
//! [`attenuate`] is contained by the one that went in, because the code that
//! returns it cannot be reached otherwise.
//!
//! Fresh authority is not made here. It is minted from a profile, the active
//! skills, the parent run and the ceiling, at admission, by `crate::state`
//! (M3d) — which calls this module's containment and never the reverse.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

use super::Capability;
use super::constraint::ConstraintSet;
use super::error::AttenuationError;
use super::scope::Scope;

/// What a caller is asking to narrow.
///
/// Every field is additive-or-tightening by intent, and none of them can widen
/// in effect: whatever this asks for, the result is checked. There is
/// deliberately no way to express "remove a constraint" or "broaden the scope",
/// because those are not narrowings and giving them a spelling would make the
/// check the only thing standing between them and a grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Narrowing {
    /// A scope to replace the parent's with. Must be covered by the parent's.
    pub scope: Option<Scope>,
    /// Constraints to set. A constraint the parent did not have may be added
    /// (rule A); a constraint the parent had may be tightened, never loosened.
    pub constraints: ConstraintSet,
}

impl Narrowing {
    /// A narrowing that changes nothing. `attenuate(c, &Narrowing::none())`
    /// returns `c`, which is the identity the idempotence property rests on.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Narrow to a scope.
    #[must_use]
    pub fn to_scope(scope: Scope) -> Self {
        Self {
            scope: Some(scope),
            constraints: ConstraintSet::unconstrained(),
        }
    }

    /// Narrow by constraints.
    #[must_use]
    pub fn with_constraints(constraints: ConstraintSet) -> Self {
        Self {
            scope: None,
            constraints,
        }
    }
}

/// Narrow `parent` by `narrowing`.
///
/// # Guarantee
///
/// On `Ok(child)`, `parent.contains(&child)` holds. Not by construction of the
/// candidate — a caller can ask for anything — but because the candidate is
/// tested and a failing one never leaves this function.
///
/// # Errors
///
/// [`AttenuationError::WouldWiden`] when the result would not be contained by
/// the parent: a broader scope, a loosened limit, a superset of methods, or a
/// constraint dropped (which is [`CAPABILITIES.md`]'s rule 2 — a missing
/// constraint on the child is *unconstrained*, and therefore wider).
///
/// [`AttenuationError::Invalid`] when the narrowing does not form a valid
/// capability for the verb, such as a scope from the wrong family.
///
/// [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md
pub fn attenuate(
    parent: &Capability,
    narrowing: &Narrowing,
) -> Result<Capability, AttenuationError> {
    let scope = narrowing
        .scope
        .clone()
        .unwrap_or_else(|| parent.scope().clone());
    let constraints = parent.constraints().overlay(&narrowing.constraints);
    let candidate = Capability::new(parent.verb(), scope, constraints)?;

    // The whole safety argument, in one line. Nothing above it is trusted.
    if !parent.contains(&candidate) {
        return Err(AttenuationError::WouldWiden);
    }
    Ok(candidate)
}

/// Narrow `parent` to `child` exactly, if that is a narrowing.
///
/// A convenience for a delegation that already knows the capability it wants,
/// rather than the narrowing that would produce it. Same guarantee, same check.
///
/// # Errors
///
/// [`AttenuationError::VerbChanged`] if the verbs differ — attenuation narrows
/// one authority and does not change what the authority is *for* — and
/// [`AttenuationError::WouldWiden`] if `child` is not contained by `parent`.
pub fn delegate(parent: &Capability, child: &Capability) -> Result<Capability, AttenuationError> {
    if parent.verb() != child.verb() {
        return Err(AttenuationError::VerbChanged);
    }
    if !parent.contains(child) {
        return Err(AttenuationError::WouldWiden);
    }
    Ok(child.clone())
}
