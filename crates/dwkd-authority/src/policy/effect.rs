//! [`Effect`] and the restrictiveness order over it.

use core::fmt;

/// What policy decided.
///
/// **Three-valued, and it stays that way inside the authority.** A rule that
/// says `effect = "REQUIRE_APPROVAL"` evaluates to [`Effect::RequireApproval`];
/// collapsing it in the evaluator would lose both the rule author's intent and
/// the audit record of it ([`POLICY.md`] §2).
///
/// What crosses DWKP is a different type. Through M5 the wire carries
/// `ALLOW | DENY`, because an authority with no approval registry cannot obtain
/// an approval and therefore refuses
/// ([ADR-0036](../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md)
/// §9). That mapping happens at the boundary, which M3e owns. It is not this
/// enum's business and it is not done here.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Permitted, subject to the obligations the decision carries.
    Allow,
    /// Permitted only if a human approves the shape the decision names.
    RequireApproval,
    /// Refused.
    Deny,
}

impl Effect {
    /// Every effect, most restrictive first.
    pub const ALL: [Self; 3] = [Self::Deny, Self::RequireApproval, Self::Allow];

    /// The wire spelling, which is also the TOML spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::RequireApproval => "REQUIRE_APPROVAL",
            Self::Deny => "DENY",
        }
    }

    /// Parse the TOML spelling. Exact: no case folding, no aliases.
    ///
    /// `allow` is not `ALLOW`. A policy file whose author meant one and wrote
    /// the other has a bug, and accepting both would make the canonical form of
    /// a rule depend on how it was typed.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == text)
    }

    /// How much authority this effect conveys, smaller being less.
    ///
    /// Private, and computed by an exhaustive `match` rather than by a
    /// discriminant: `as` on an enum is the kind of implicit ordering
    /// [`POLICY.md`] means when it says restrictiveness must be named logic.
    /// Reordering the variants above must not silently invert the lattice.
    ///
    /// [`POLICY.md`]: ../../../../../docs/POLICY.md
    const fn authority(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::RequireApproval => 1,
            Self::Allow => 2,
        }
    }

    /// Whether `self` is at least as restrictive as `other` — that is,
    /// `self ⊑ other` under `DENY ⊑ REQUIRE_APPROVAL ⊑ ALLOW`.
    #[must_use]
    pub const fn narrower_or_equal(self, other: Self) -> bool {
        self.authority() <= other.authority()
    }

    /// Whether `self` is strictly more restrictive than `other`.
    #[must_use]
    pub const fn strictly_narrower(self, other: Self) -> bool {
        self.authority() < other.authority()
    }

    /// The more restrictive of the two — the meet of the lattice.
    ///
    /// Total, associative and commutative, because the order is total. This is
    /// the operation every composition and postcondition step is built from, so
    /// that "never widens" is a property of the function rather than of a check
    /// somebody remembered to write.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        if self.narrower_or_equal(other) {
            self
        } else {
            other
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Effect;

    #[test]
    fn the_order_is_total_and_deny_is_the_bottom() {
        for a in Effect::ALL {
            assert!(a.narrower_or_equal(a), "{a} must be ⊑ itself");
            assert!(Effect::Deny.narrower_or_equal(a));
            assert!(a.narrower_or_equal(Effect::Allow));
            for b in Effect::ALL {
                assert!(
                    a.narrower_or_equal(b) || b.narrower_or_equal(a),
                    "{a} and {b} must be comparable"
                );
            }
        }
    }

    #[test]
    fn every_pair_orders_as_the_document_says() {
        use Effect::{Allow, Deny, RequireApproval};
        // DENY ⊑ REQUIRE_APPROVAL ⊑ ALLOW, and nothing above holds below.
        assert!(Deny.strictly_narrower(RequireApproval));
        assert!(RequireApproval.strictly_narrower(Allow));
        assert!(Deny.strictly_narrower(Allow));
        assert!(!RequireApproval.narrower_or_equal(Deny));
        assert!(!Allow.narrower_or_equal(RequireApproval));
        assert!(!Allow.narrower_or_equal(Deny));
    }

    #[test]
    fn meet_never_widens_either_argument() {
        for a in Effect::ALL {
            for b in Effect::ALL {
                let m = a.meet(b);
                assert!(m.narrower_or_equal(a), "{m} must be ⊑ {a}");
                assert!(m.narrower_or_equal(b), "{m} must be ⊑ {b}");
                assert_eq!(m, b.meet(a), "meet must commute");
            }
        }
    }

    #[test]
    fn meet_is_associative() {
        for a in Effect::ALL {
            for b in Effect::ALL {
                for c in Effect::ALL {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
                }
            }
        }
    }

    #[test]
    fn spellings_round_trip_and_are_case_sensitive() {
        for e in Effect::ALL {
            assert_eq!(Effect::parse(e.as_str()), Some(e));
        }
        for bad in [
            "allow",
            "Allow",
            "ALLOW ",
            "",
            "deny",
            "require_approval",
            "PERMIT",
        ] {
            assert_eq!(Effect::parse(bad), None, "{bad} must not parse");
        }
    }
}
