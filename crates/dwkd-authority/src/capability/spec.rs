//! [`CapabilitySpec`] — a capability as *declared*.
//!
//! This is what parsing produces and what a request carries. It is deliberately
//! not comparable: it has no `contains`, and there is no `Ord`-based shortcut
//! that could stand in for one. The only way from here to authority is
//! [`CapabilitySpec::resolve`], and for the two families whose identity is a
//! resource it refuses.
//!
//! The distinction is the whole of §15 of the M3b brief, and it is worth
//! stating plainly: **a raw resource spelling is not a canonical resource
//! identity.** `fs.read:/workspace` is a sentence about a path. Which inode it
//! names depends on the filesystem at the moment somebody looks, on symlinks,
//! on mounts, and on a Unicode normalisation this build does not perform. M4
//! answers that question; M3b refuses to pretend it has.

use core::fmt;

use super::Capability;
use super::constraint::ConstraintSet;
use super::error::{CapabilityError, UnresolvedScope};
use super::scope::{Scope, ScopeSpec};
use super::verb::Verb;
use crate::resource::CanonicalPath;

/// A capability as declared: verb, declared scope, constraints.
///
/// Well-formed, and nothing more. Being well-formed is not being granted, and
/// it is not being comparable either.
///
/// ```compile_fail
/// // A declaration has no containment relation. This is the compile error that
/// // makes "an unresolved resource cannot reach an authority comparison" a
/// // property of the program rather than a rule a reviewer enforces.
/// use dwkd_authority::capability::parse;
/// let a = parse("fs.read:/workspace").unwrap();
/// let b = parse("fs.read:/workspace/src").unwrap();
/// let _ = a.contains(&b);
/// ```
///
/// ```compile_fail
/// // Nor read the other way round.
/// use dwkd_authority::capability::parse;
/// let a = parse("fs.read:/workspace").unwrap();
/// let b = parse("fs.read:/workspace/src").unwrap();
/// let _ = b.is_contained_by(&a);
/// ```
///
/// ```compile_fail
/// // And a declaration cannot be put in a set, which is the other place a
/// // comparison would happen.
/// use dwkd_authority::capability::{CapabilitySet, parse};
/// let mut set = CapabilitySet::empty();
/// set.insert(parse("fs.read:/workspace").unwrap());
/// ```
///
/// The relation it *does* have is [`CapabilitySpec::resolve`], and for `fs` and
/// `process` that refuses:
///
/// ```
/// use dwkd_authority::capability::{UnresolvedScope, parse};
/// let declared = parse("fs.read:/workspace").unwrap();
/// assert!(declared.needs_resolution());
/// assert_eq!(declared.resolve(), Err(UnresolvedScope::CanonicalPath));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilitySpec {
    verb: Verb,
    scope: ScopeSpec,
    constraints: ConstraintSet,
}

impl CapabilitySpec {
    /// Assemble a specification. Crate-internal: [`super::parse`] is the
    /// public way in, so every specification has been through the grammar.
    pub(crate) const fn new(verb: Verb, scope: ScopeSpec, constraints: ConstraintSet) -> Self {
        Self {
            verb,
            scope,
            constraints,
        }
    }

    /// The verb.
    #[must_use]
    pub const fn verb(&self) -> Verb {
        self.verb
    }

    /// The declared scope.
    #[must_use]
    pub const fn scope(&self) -> &ScopeSpec {
        &self.scope
    }

    /// The constraints.
    #[must_use]
    pub const fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }

    /// Whether this declaration names a resource the authority would have to
    /// resolve before it could compare it.
    #[must_use]
    pub const fn needs_resolution(&self) -> bool {
        matches!(
            self.scope,
            ScopeSpec::DeclaredPath(_) | ScopeSpec::DeclaredExecutable(_)
        )
    }

    /// Promote to an authority-comparable [`Capability`], without touching any
    /// resource.
    ///
    /// Succeeds for the ten families that are their own identity. Fails for
    /// `fs` and `process`, whose identities are an inode and a file hash.
    ///
    /// This is the **only** bridge from a declaration to authority, and it is
    /// the reason a raw path cannot reach a containment check: there is no
    /// other function that takes a [`ScopeSpec`] and returns a [`Scope`], and
    /// [`Scope::Path`] holds a [`super::scope::CanonicalPath`], which has no
    /// constructor accepting a path string.
    ///
    /// # Errors
    ///
    /// [`UnresolvedScope`], naming which identity M4 owes.
    pub fn resolve(&self) -> Result<Capability, UnresolvedScope> {
        let scope = match &self.scope {
            ScopeSpec::Universal => Scope::Universal,
            ScopeSpec::Syntactic(s) => Scope::Syntactic(s.clone()),
            ScopeSpec::DeclaredPath(_) => return Err(UnresolvedScope::CanonicalPath),
            ScopeSpec::DeclaredExecutable(_) => return Err(UnresolvedScope::ExecutableIdentity),
        };
        // The parser already enforced applicability and family agreement, so
        // this cannot fail; mapping it keeps the function total rather than
        // asserting that.
        Capability::new(self.verb, scope, self.constraints.clone())
            .map_err(|_: CapabilityError| UnresolvedScope::CanonicalPath)
    }

    /// Promote a path declaration, given the [`CanonicalPath`] the resource
    /// layer's grammar derived **for this declaration's path** (M4b,
    /// ADR-0043).
    ///
    /// This does not canonicalise and cannot: a [`CanonicalPath`] exists only
    /// because `crate::resource` made one, so all this does is assemble the
    /// capability from a value it could not have forged. Crate-internal — the
    /// state layer is the one caller, and it passes the path it just derived
    /// from [`Self::scope`].
    ///
    /// # Errors
    ///
    /// [`UnresolvedScope::CanonicalPath`] when the scope is not a declared
    /// path.
    pub(crate) fn resolve_path(
        &self,
        canonical: CanonicalPath,
    ) -> Result<Capability, UnresolvedScope> {
        if !matches!(self.scope, ScopeSpec::DeclaredPath(_)) {
            return Err(UnresolvedScope::CanonicalPath);
        }
        Capability::new(self.verb, Scope::Path(canonical), self.constraints.clone())
            .map_err(|_: CapabilityError| UnresolvedScope::CanonicalPath)
    }

    /// The canonical text of this specification.
    ///
    /// Constraints render in the fixed order of [`ConstraintSet`] and set
    /// members in the fixed order of their own types, so two specifications
    /// that are equal render identically and re-parse to the same value.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for CapabilitySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.verb, self.scope)?;
        if !self.constraints.is_empty() {
            write!(f, "?{}", self.constraints)?;
        }
        Ok(())
    }
}
