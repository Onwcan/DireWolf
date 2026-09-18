//! [`CapabilitySet`] — a set of capabilities, and subset over it.
//!
//! ```text
//! A ⊑ B  iff  ∀ a ∈ A, ∃ b ∈ B : a ⊑ b
//! ```
//!
//! The quantifier is the security property. `∃ b` ranges over **whole parent
//! capabilities**: one of them must cover the child entirely. A child is never
//! assembled from the scope of one parent and the constraints of another, and
//! the reason is not a check — it is that no function in this file ever holds
//! two parents at once.

use core::fmt;

use super::Capability;

/// A deterministic, minimal set of capabilities.
///
/// Two properties that are easy to state and easy to get wrong:
///
/// * **Order-independent.** Members are kept sorted, so two sets built from the
///   same capabilities in different orders are equal and render identically.
/// * **Minimal.** A capability already covered by another is not stored, and
///   inserting a capability drops the members it covers. The result is an
///   antichain: no member covers another, so there is exactly one
///   representation of a given authority and "no semantic duplicate authority"
///   is a property of the type rather than a convention.
///
/// Minimisation never changes what the set covers. Dropping `fs.read:/w/src`
/// when `fs.read:/w` is present removes a member, not an authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilitySet {
    members: Vec<Capability>,
}

impl CapabilitySet {
    /// The empty set. Bottom of the lattice: `∅ ⊑ A` for every `A`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A set from capabilities, minimised.
    #[must_use]
    pub fn from_capabilities<I: IntoIterator<Item = Capability>>(items: I) -> Self {
        let mut set = Self::empty();
        for item in items {
            set.insert(item);
        }
        set
    }

    /// Add a capability, keeping the set minimal and sorted.
    ///
    /// Returns whether the set changed. A capability already covered changes
    /// nothing; one that covers existing members replaces them.
    pub fn insert(&mut self, capability: Capability) -> bool {
        if self.members.iter().any(|held| held.contains(&capability)) {
            return false;
        }
        self.members.retain(|held| !capability.contains(held));
        // Sorted on the derived order, which is total and depends on nothing
        // but the values -- no hashing, no insertion order, no clock.
        let position = self
            .members
            .binary_search(&capability)
            .unwrap_or_else(|index| index);
        self.members.insert(position, capability);
        true
    }

    /// The members, in canonical order.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.members
    }

    /// How many members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Iterate the members in canonical order.
    pub fn iter(&self) -> core::slice::Iter<'_, Capability> {
        self.members.iter()
    }

    /// Whether some **single** member covers `capability`.
    ///
    /// The existential of the set rule. The closure sees one member at a time
    /// and has nowhere to put a second, which is what makes synthesis
    /// unexpressible rather than merely forbidden.
    #[must_use]
    pub fn covers(&self, capability: &Capability) -> bool {
        self.members.iter().any(|held| held.contains(capability))
    }

    /// Whether `self ⊑ other`: every member of `self` is covered by a single
    /// member of `other`.
    #[must_use]
    pub fn is_contained_by(&self, other: &Self) -> bool {
        self.members.iter().all(|a| other.covers(a))
    }

    /// Whether `self` covers every member of `other` — the same relation read
    /// the other way.
    #[must_use]
    pub fn contains_set(&self, other: &Self) -> bool {
        other.is_contained_by(self)
    }

    /// The canonical text of the set: members in order, newline-free, comma
    /// separated.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        self.to_string()
    }
}

impl<'a> IntoIterator for &'a CapabilitySet {
    type Item = &'a Capability;
    type IntoIter = core::slice::Iter<'a, Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.iter()
    }
}

impl IntoIterator for CapabilitySet {
    type Item = Capability;
    type IntoIter = std::vec::IntoIter<Capability>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.into_iter()
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(items: I) -> Self {
        Self::from_capabilities(items)
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, member) in self.members.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{member}")?;
        }
        Ok(())
    }
}
