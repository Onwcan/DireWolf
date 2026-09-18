//! The typed vocabulary of authority, and the `⊑` lattice over it.
//!
//! A capability is a **specific, scoped, checkable permission**
//! ([`CAPABILITIES.md`] §1). Not a role, not a risk label, not a policy result,
//! not an approval, and not a bearer string. `fs.read:/workspace/src` either
//! covers a resource or it does not, and that question has one deterministic
//! answer.
//!
//! # The invariant
//!
//! > **Child authority never exceeds parent authority.**
//!
//! Formally ([`CAPABILITIES.md`] §3):
//!
//! ```text
//! a ⊑ b  iff  a.verb == b.verb
//!          ∧  scope_contains(b.scope, a.scope)
//!          ∧  ∀ k ∈ constraints(b) : constraint_narrower_or_equal(a[k], b[k])
//!          ∧  ∀ k ∈ constraints(a) \ constraints(b) : true
//!
//! A ⊑ B  iff  ∀ a ∈ A, ∃ b ∈ B : a ⊑ b
//! ```
//!
//! The set rule is **existential over whole parents**. One parent capability
//! must cover a child capability entirely; the scope of one and the constraint
//! of another never combine. That is the no-synthesis property, and it is a
//! property of the shape of the code — there is no function anywhere that takes
//! two parents — rather than of a check somebody remembered to write.
//!
//! # What this module is not
//!
//! It answers *"is this authority shape contained by that one?"*. It does not
//! answer *"should this be allowed?"* — that is policy, it is M3c, and
//! [ADR-0006] requires both gates independently. It mints nothing, persists
//! nothing, and reads nothing from the world.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md
//! [ADR-0006]: ../../../../../docs/adr/0006-policy-and-capability-boundary.md

pub mod attenuate;
pub mod constraint;
pub mod error;
pub mod parse;
pub mod scope;
pub mod set;
pub mod spec;
pub mod verb;

// The `fs` and `process` half of the lattice. A unit test module because those
// are the only tests needing a canonical identity, and since ADR-0037 a
// canonical identity cannot be constructed outside `crate::resource` -- which
// includes from an integration test, since one links the library compiled
// without `cfg(test)`.
#[cfg(test)]
mod resource_lattice;

use core::fmt;

pub use attenuate::{Narrowing, attenuate};
pub use constraint::{
    ArgvAllowlist, ArgvToken, ConstraintSet, Method, MethodSet, NoSymlinkTargets, PrivacyClass,
};
pub use error::{
    AttenuationError, CapabilityError, ConstraintName, ScopeError, UnresolvedScope, ValueError,
};
pub use parse::{MAX_CAPABILITY_CHARS, parse};
pub use scope::{
    ChannelTarget, DeclaredPath, Endpoint, HostLabel, HostPattern, Label, Pattern, PortSpec,
    ProviderModel, Scope, ScopeFamily, ScopeSpec, SyntacticScope,
};
// Re-exported so a holder's import path is unchanged, and so that the
// compile_fail evidence on these types is reached through the name callers
// actually use. Only *construction* moved: see `crate::resource`.
pub use crate::resource::{CanonicalPath, ExecutableIdentity, PathComponent, Sha256Digest};
pub use set::CapabilitySet;
pub use spec::CapabilitySpec;
pub use verb::{Action, Namespace, Verb};

/// A capability in authority-comparable form: verb, resolved scope,
/// constraints.
///
/// Immutable by construction. There is no `&mut self` method, no field setter
/// and no way to replace a part of one — so an existing capability cannot be
/// edited wider, and the only operations are comparison ([`Capability::contains`])
/// and narrowing ([`attenuate`]), which verifies its own result.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    verb: Verb,
    scope: Scope,
    constraints: ConstraintSet,
}

impl Capability {
    /// Assemble a capability, checking that its parts belong together.
    ///
    /// This is not a widening operation and not a grant. It builds a *value*;
    /// whether anybody holds it is a question for the milestone that mints.
    ///
    /// # Errors
    ///
    /// [`CapabilityError::ScopeFamilyMismatch`] if the scope is not `*` and not
    /// of the verb's family, and [`CapabilityError::ConstraintNotApplicable`]
    /// if a constraint is attached to a verb it does not apply to — the same
    /// applicability rule the parser enforces, checked again here because this
    /// is the other way in.
    pub fn new(
        verb: Verb,
        scope: Scope,
        constraints: ConstraintSet,
    ) -> Result<Self, CapabilityError> {
        if !scope.fits(verb.scope_family()) {
            return Err(CapabilityError::ScopeFamilyMismatch);
        }
        for name in constraints.present() {
            if !name.applies_to(verb) {
                return Err(CapabilityError::ConstraintNotApplicable { name, verb });
            }
        }
        Ok(Self {
            verb,
            scope,
            constraints,
        })
    }

    /// The verb.
    #[must_use]
    pub const fn verb(&self) -> Verb {
        self.verb
    }

    /// The scope.
    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The constraints.
    #[must_use]
    pub const fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }

    /// Whether `self` covers `other` — that is, `other ⊑ self`.
    ///
    /// All three clauses of the lattice definition, in order. The verb is
    /// compared first because a scope comparison across verbs is meaningless
    /// and `*` is only universal *within* a verb: `fs.read:*` covers no
    /// `fs.write` at all.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.verb == other.verb
            && self.scope.contains(&other.scope)
            && other.constraints.narrower_or_equal(&self.constraints)
    }

    /// Whether `self ⊑ other`. The same relation read the other way, for call
    /// sites where the child is the subject.
    #[must_use]
    pub fn is_contained_by(&self, other: &Self) -> bool {
        other.contains(self)
    }

    /// The canonical text of this capability.
    ///
    /// For the ten resolution-free families this is valid capability text and
    /// re-parses. For `fs` and `process` it renders the *resolved* identity — a
    /// canonical path, or a path and a hash — which is deliberately not a
    /// request spelling: a resolved identity is something the authority holds,
    /// not something a caller may ask for.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.verb, self.scope)?;
        if !self.constraints.is_empty() {
            write!(f, "?{}", self.constraints)?;
        }
        Ok(())
    }
}
