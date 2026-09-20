//! [`Reason`] — why, as a closed enum.

use core::fmt;

/// Why policy decided what it decided.
///
/// **An enum, not a string.** Denials are machine-classifiable in evals and
/// metrics, and production control flow never branches on prose
/// ([`POLICY.md`] §2). Human-readable text is rendered from this; it is not
/// what this is.
///
/// **Closed, and deliberately small.** Every variant is required by a rule one
/// of the three shipped profiles actually contains, or by the evaluator itself.
/// A reason that might be useful later is not here: adding one is a variant, a
/// rule that produces it and a test, which is the cost that keeps the set
/// honest.
///
/// `NO_CAPABILITY` is **not** here, and its absence is the point. A capability
/// miss is the *other* gate ([ADR-0006]); a policy reason for it would imply
/// policy had checked something it must not check.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
/// [ADR-0006]: ../../../../../docs/adr/0006-policy-and-capability-boundary.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// The action would modify DireWolf's own installation, configuration or
    /// state. `deny-direwolf-self-modification`.
    SelfModification,
    /// The action names credentials or another path no agent has business in.
    /// `deny-credential-paths`.
    SensitivePath,
    /// The action names a container control socket or another route out of the
    /// isolation it is running in. `deny-container-socket`.
    SandboxEscapeVector,
    /// A destructive action inside the workspace. `approve-workspace-delete`.
    DestructiveInWorkspace,
    /// An executable no profile allowlists. `approve-novel-exec`.
    UnknownExecutable,
    /// Execution outside the sandbox, which is off unless an operator turned it
    /// on. `deny-host-exec-unless-opted-in`.
    HostExecutionDisabled,
    /// Egress from a run holding content the agent chose to fetch.
    /// `approve-egress-when-tainted`.
    UntrustedContentInRun,
    /// Approval was required and nobody can be asked.
    /// `deny-approval-needed-when-unattended`.
    NoHumanAvailable,
    /// The profile does not permit this class of action at all. `safe`'s
    /// blanket denials.
    ProfileCeiling,
    /// No rule matched. The mandatory `default`.
    NoMatchingRule,
    /// A rule permitted it and named no reason of its own.
    ///
    /// Present because [`super::Decision`] carries a reason unconditionally and
    /// an empty string is not a value: an `ALLOW` whose reason is `""` reads as
    /// a missing field rather than as "this rule said yes".
    PermittedByRule,
    /// A rule needed a canonical value the action or context does not hold —
    /// an unresolved `${...}` anchor, or a network action with no destination
    /// address.
    ///
    /// [`POLICY.md`](../../../../../docs/POLICY.md) §4 step 1 is "validate
    /// request is fully canonicalised (assert; uncanonicalised input is a
    /// bug)". This is that assert, fail-closed. Treating the predicate as *not
    /// matching* would silently disable a deny rule, which is the "a typo
    /// makes a predicate disappear" failure the strict loader exists to
    /// prevent, arriving one layer later.
    UnresolvedCanonicalInput,
}

impl Reason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 12] = [
        Self::SelfModification,
        Self::SensitivePath,
        Self::SandboxEscapeVector,
        Self::DestructiveInWorkspace,
        Self::UnknownExecutable,
        Self::HostExecutionDisabled,
        Self::UntrustedContentInRun,
        Self::NoHumanAvailable,
        Self::ProfileCeiling,
        Self::NoMatchingRule,
        Self::PermittedByRule,
        Self::UnresolvedCanonicalInput,
    ];

    /// The TOML and audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelfModification => "SELF_MODIFICATION",
            Self::SensitivePath => "SENSITIVE_PATH",
            Self::SandboxEscapeVector => "SANDBOX_ESCAPE_VECTOR",
            Self::DestructiveInWorkspace => "DESTRUCTIVE_IN_WORKSPACE",
            Self::UnknownExecutable => "UNKNOWN_EXECUTABLE",
            Self::HostExecutionDisabled => "HOST_EXECUTION_DISABLED",
            Self::UntrustedContentInRun => "UNTRUSTED_CONTENT_IN_RUN",
            Self::NoHumanAvailable => "NO_HUMAN_AVAILABLE",
            Self::ProfileCeiling => "PROFILE_CEILING",
            Self::NoMatchingRule => "NO_MATCHING_RULE",
            Self::PermittedByRule => "PERMITTED_BY_RULE",
            Self::UnresolvedCanonicalInput => "UNRESOLVED_CANONICAL_INPUT",
        }
    }

    /// Parse the TOML spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == text)
    }

    /// Whether a rule author may write this reason.
    ///
    /// Two of them are the evaluator's own: `PERMITTED_BY_RULE` is what an
    /// `ALLOW` with no stated reason becomes, and `UNRESOLVED_CANONICAL_INPUT`
    /// describes a context the rule cannot know about. Letting a file claim
    /// either would put a decision the evaluator makes under the rule author's
    /// control.
    #[must_use]
    pub const fn is_authorable(self) -> bool {
        !matches!(self, Self::PermittedByRule | Self::UnresolvedCanonicalInput)
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Reason;

    #[test]
    fn spellings_are_distinct_and_round_trip() {
        let mut seen = Vec::new();
        for r in Reason::ALL {
            assert_eq!(Reason::parse(r.as_str()), Some(r));
            assert!(!seen.contains(&r.as_str()), "duplicate spelling {r}");
            seen.push(r.as_str());
        }
        assert_eq!(seen.len(), Reason::ALL.len());
    }

    #[test]
    fn parsing_is_exact() {
        for bad in [
            "self_modification",
            "SELF-MODIFICATION",
            "",
            " NO_MATCHING_RULE",
            "NO_CAPABILITY",
        ] {
            assert_eq!(Reason::parse(bad), None, "{bad} must not parse");
        }
    }

    #[test]
    fn the_evaluators_own_reasons_are_not_authorable() {
        assert!(!Reason::PermittedByRule.is_authorable());
        assert!(!Reason::UnresolvedCanonicalInput.is_authorable());
        let authorable = Reason::ALL
            .into_iter()
            .filter(|r| r.is_authorable())
            .count();
        assert_eq!(authorable, Reason::ALL.len() - 2);
    }
}
