//! [`ApprovalSpec`] — the shape a rule author says would satisfy a
//! `REQUIRE_APPROVAL`.
//!
//! **This is data, not authority.** M3c parses it, carries it on a
//! [`Decision`](super::Decision), and renders it. It does not ask a human,
//! match an existing approval, persist one, bind one, or satisfy the
//! requirement. There is no approval registry until M6
//! ([`APPROVALS.md`], [ROADMAP.md](../../../../../docs/ROADMAP.md) M6), and
//! nothing here pretends otherwise.
//!
//! No wall clock is read. A [`Ttl`] is a duration the rule states; turning it
//! into a `not_after` needs the kernel's clock, at the milestone that has one.
//!
//! [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md

use core::fmt;

use super::error::ValueError;
use super::limits;

/// Which shape of action an approval would cover.
///
/// The `ApprovalScope` of [`APPROVALS.md`] §3, minus its resolved payloads:
/// `PathSet { inodes, verb }` needs inodes, and an inode is a canonical
/// resource identity this milestone cannot derive. What a *rule* declares is
/// the discriminant — the breadth the author intends — and M6 fills in the
/// payload when it has a resolved action and a human to ask.
///
/// [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApprovalScopeKind {
    /// This argv, this inode, once.
    ExactAction,
    /// One prompt, one binding, N files.
    PathSet,
    /// This executable with this argv shape.
    ExecutableAndArgv,
    /// A subtree, bound to its root's inode at approval time.
    PathSubtree,
    /// A resolved host with a method set.
    HostAndMethods,
    /// A credential handle against an upstream.
    CredentialUse,
}

impl ApprovalScopeKind {
    /// Every scope, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::ExactAction,
        Self::PathSet,
        Self::ExecutableAndArgv,
        Self::PathSubtree,
        Self::HostAndMethods,
        Self::CredentialUse,
    ];

    /// The TOML spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactAction => "exact_action",
            Self::PathSet => "path_set",
            Self::ExecutableAndArgv => "executable_and_argv",
            Self::PathSubtree => "path_subtree",
            Self::HostAndMethods => "host_and_methods",
            Self::CredentialUse => "credential_use",
        }
    }

    /// Parse the TOML spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

impl fmt::Display for ApprovalScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How long an approval would remain spendable.
///
/// Stored as whole seconds. The spelling is a small closed grammar —
/// a positive decimal integer and one of `s`, `m`, `h` — because
/// [`POLICY.md`] writes `"10m"` and `"1h"` and nothing else, and because a
/// general duration parser is a dependency this milestone does not need to
/// read two shapes of string.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ttl(u32);

impl Ttl {
    /// Parse `<positive integer><s|m|h>`.
    ///
    /// Strict in every direction that could produce a *longer* life than the
    /// author wrote: no whitespace, no sign, no fraction, no bare number, no
    /// compound `1h30m`, no unit beyond the three, and no overflow — the
    /// multiplication is checked, so `4294967295h` is refused rather than
    /// wrapped into something short and plausible.
    ///
    /// # Errors
    ///
    /// [`ValueError::Ttl`] for anything that is not exactly that shape, and for
    /// a duration of zero or one past [`limits::MAX_APPROVAL_TTL_SECONDS`].
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let Some((digits, unit)) = text.split_at_checked(text.len().saturating_sub(1)) else {
            return Err(ValueError::Ttl);
        };
        let multiplier = match unit {
            "s" => 1_u32,
            "m" => 60,
            "h" => 3600,
            _ => return Err(ValueError::Ttl),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ValueError::Ttl);
        }
        let count: u32 = digits.parse().map_err(|_| ValueError::Ttl)?;
        let seconds = count.checked_mul(multiplier).ok_or(ValueError::Ttl)?;
        if seconds == 0 || seconds > limits::MAX_APPROVAL_TTL_SECONDS {
            return Err(ValueError::Ttl);
        }
        Ok(Self(seconds))
    }

    /// The duration in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Ttl {
    /// Renders in the largest exact unit, so `600` is `10m` rather than `600s`
    /// and a specification has one canonical spelling.
    #[expect(
        clippy::integer_division,
        reason = "the divisor is checked to divide exactly on the line above"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (value, unit) = if self.0.is_multiple_of(3600) {
            (self.0 / 3600, 'h')
        } else if self.0.is_multiple_of(60) {
            (self.0 / 60, 'm')
        } else {
            (self.0, 's')
        };
        write!(f, "{value}{unit}")
    }
}

/// What a `REQUIRE_APPROVAL` rule says would satisfy it.
///
/// All three fields are mandatory. [`APPROVALS.md`] §3 is explicit that
/// "scope breadth and `max_uses` must scale together", and a default for
/// either would be the loader choosing the breadth of a human's decision. A
/// missing `approval` table on a `REQUIRE_APPROVAL` rule is a load error for
/// the same reason.
///
/// [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalSpec {
    scope: ApprovalScopeKind,
    ttl: Ttl,
    max_uses: u32,
}

impl ApprovalSpec {
    /// Assemble a specification.
    ///
    /// # Errors
    ///
    /// [`ValueError::ApprovalUses`] for zero uses — an approval nothing can
    /// spend — or for more than [`limits::MAX_APPROVAL_USES`].
    pub const fn new(
        scope: ApprovalScopeKind,
        ttl: Ttl,
        max_uses: u32,
    ) -> Result<Self, ValueError> {
        if max_uses == 0 || max_uses > limits::MAX_APPROVAL_USES {
            return Err(ValueError::ApprovalUses);
        }
        Ok(Self {
            scope,
            ttl,
            max_uses,
        })
    }

    /// The breadth the rule author intended.
    #[must_use]
    pub const fn scope(&self) -> ApprovalScopeKind {
        self.scope
    }

    /// How long it would remain spendable.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// How many times it could be spent.
    #[must_use]
    pub const fn max_uses(&self) -> u32 {
        self.max_uses
    }
}

impl fmt::Display for ApprovalSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, ttl {}, up to {} use{}",
            self.scope,
            self.ttl,
            self.max_uses,
            if self.max_uses == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalScopeKind, ApprovalSpec, Ttl};
    use crate::policy::error::ValueError;
    use crate::policy::limits;

    #[test]
    fn every_documented_scope_round_trips() {
        for scope in ApprovalScopeKind::ALL {
            assert_eq!(ApprovalScopeKind::parse(scope.as_str()), Some(scope));
        }
        for bad in ["ExactAction", "EXACT_ACTION", "exact-action", "", "subtree"] {
            assert!(ApprovalScopeKind::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_shipped_ttls_parse_and_render_canonically() {
        for (text, seconds) in [("10m", 600), ("1h", 3600), ("30s", 30), ("90m", 5400)] {
            let Ok(ttl) = Ttl::parse(text) else {
                unreachable!("{text} must parse")
            };
            assert_eq!(ttl.seconds(), seconds);
            // 90m renders as 90m, not 1h30m: one unit, exactly.
            assert_eq!(
                Ttl::parse(&ttl.to_string()),
                Ok(ttl),
                "{text} must round-trip"
            );
        }
        let Ok(ten_minutes) = Ttl::parse("600s") else {
            unreachable!()
        };
        assert_eq!(ten_minutes.to_string(), "10m", "one canonical spelling");
    }

    #[test]
    fn a_malformed_ttl_is_refused_rather_than_guessed() {
        for bad in [
            "", "m", "h", "s", "10", "10d", "10M", "10 m", " 10m", "10m ", "-5m", "1.5h", "1h30m",
            "0s", "0m", "0h", "+5m", "0x10s", "١٠m",
        ] {
            assert_eq!(
                Ttl::parse(bad),
                Err(ValueError::Ttl),
                "{bad} must not parse"
            );
        }
    }

    #[test]
    fn a_ttl_overflow_is_refused_and_never_wraps() {
        // 4294967295h would wrap to something short and plausible.
        assert_eq!(Ttl::parse("4294967295h"), Err(ValueError::Ttl));
        assert_eq!(Ttl::parse("99999999999s"), Err(ValueError::Ttl));
        // And the documented cap holds.
        let over = limits::MAX_APPROVAL_TTL_SECONDS + 1;
        assert_eq!(Ttl::parse(&format!("{over}s")), Err(ValueError::Ttl));
        assert!(Ttl::parse(&format!("{}s", limits::MAX_APPROVAL_TTL_SECONDS)).is_ok());
    }

    #[test]
    fn an_approval_nothing_can_spend_is_refused() {
        let Ok(ttl) = Ttl::parse("1h") else {
            unreachable!()
        };
        assert_eq!(
            ApprovalSpec::new(ApprovalScopeKind::ExactAction, ttl, 0),
            Err(ValueError::ApprovalUses)
        );
        assert_eq!(
            ApprovalSpec::new(
                ApprovalScopeKind::ExactAction,
                ttl,
                limits::MAX_APPROVAL_USES + 1
            ),
            Err(ValueError::ApprovalUses)
        );
        assert!(ApprovalSpec::new(ApprovalScopeKind::ExactAction, ttl, 1).is_ok());
    }

    #[test]
    fn a_specification_renders_what_a_human_would_be_granting() {
        let Ok(ttl) = Ttl::parse("1h") else {
            unreachable!()
        };
        let Ok(spec) = ApprovalSpec::new(ApprovalScopeKind::ExecutableAndArgv, ttl, 20) else {
            unreachable!()
        };
        assert_eq!(
            spec.to_string(),
            "executable_and_argv, ttl 1h, up to 20 uses"
        );
        let Ok(once) = ApprovalSpec::new(ApprovalScopeKind::ExactAction, ttl, 1) else {
            unreachable!()
        };
        assert_eq!(once.to_string(), "exact_action, ttl 1h, up to 1 use");
    }
}
