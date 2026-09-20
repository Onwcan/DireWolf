//! [`Obligation`] — "yes, but under these conditions", as typed data.

use core::fmt;

use super::error::ValueError;
use super::limits;

/// How much of a tool's canonical arguments the audit record keeps.
///
/// A one-variant enum because [`POLICY.md`] defines exactly one level a rule
/// may ask for — `audit_level(full)` — and the default is not something a rule
/// *requests*. A `bool` would give the absent case two spellings.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditLevel {
    /// Record the full canonical arguments, not just their hash.
    Full,
}

impl AuditLevel {
    /// The TOML spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
        }
    }
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An identifier naming a sandbox profile or a redaction profile.
///
/// Bounded and lexically closed for the same reason a rule id is: it is a
/// machine identifier something will look up later, not prose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileRef(String);

impl ProfileRef {
    /// Accept `[a-z][a-z0-9-]*`, bounded, with no doubled or trailing `-`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        if super::rule::is_lower_kebab(text, limits::MAX_PROFILE_REF_CHARS) {
            Some(Self(text.to_owned()))
        } else {
            None
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A condition attached to a permission.
///
/// **A closed enum, validated at load.** [`POLICY.md`] §2 lists ten; all ten
/// are here and nothing else is. An obligation the loader does not recognise is
/// a load error, never a dropped element: silently discarding `netwok_deny`
/// would turn a typo into a permission.
///
/// **M3c produces these. It does not enforce them.** Returning
/// [`Obligation::NetworkDeny`] removes no egress route, and returning
/// [`Obligation::ForceEnvironment`] starts no sandbox. Enforcement belongs to
/// the broker and the execution environment, at M4 and M5.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Obligation {
    /// Execute in this sandbox profile whatever was requested.
    ForceEnvironment(ProfileRef),
    /// Cap output more tightly than the tool's own default.
    MaxOutputBytes(u64),
    /// Preserve the full output as an artifact even if it would fit inline.
    RequireArtifactCapture,
    /// Apply this redaction profile on the return path.
    RedactProfile(ProfileRef),
    /// Permit the execution, with no egress route.
    NetworkDeny,
    /// Mount the workspace read-only for this invocation.
    ReadOnlyWorkspace,
    /// Record the full canonical arguments.
    AuditLevel(AuditLevel),
    /// The resulting approval, if any, cannot be reused.
    SingleUseOnly,
    /// Deliver the result to a freshly-minted reader run with no side-effect
    /// capabilities; the requester gets a reference only.
    ForceQuarantinedRead,
    /// Neutralise interpreter auto-loaded configuration for this invocation.
    WorkspaceExecHygiene,
}

impl Obligation {
    /// The name half of the TOML spelling, without any parameter.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ForceEnvironment(_) => "force_environment",
            Self::MaxOutputBytes(_) => "max_output_bytes",
            Self::RequireArtifactCapture => "require_artifact_capture",
            Self::RedactProfile(_) => "redact_profile",
            Self::NetworkDeny => "network_deny",
            Self::ReadOnlyWorkspace => "read_only_workspace",
            Self::AuditLevel(_) => "audit_level",
            Self::SingleUseOnly => "single_use_only",
            Self::ForceQuarantinedRead => "force_quarantined_read",
            Self::WorkspaceExecHygiene => "workspace_exec_hygiene",
        }
    }

    /// Parse one TOML entry: `name` for the flags, `name=value` for the four
    /// that carry a parameter.
    ///
    /// # Errors
    ///
    /// [`ValueError::UnknownObligation`] for a name outside the ten, and
    /// [`ValueError::ObligationParameter`] when a parameter is missing, present
    /// where none is defined, or malformed — which includes a `max_output_bytes`
    /// that is negative, zero, or too large for a `u64`.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let (name, argument) = match text.split_once('=') {
            Some((n, a)) => (n, Some(a)),
            None => (text, None),
        };
        match name {
            "force_environment" => ProfileRef::new(require(argument)?)
                .map(Self::ForceEnvironment)
                .ok_or(ValueError::ObligationParameter),
            "redact_profile" => ProfileRef::new(require(argument)?)
                .map(Self::RedactProfile)
                .ok_or(ValueError::ObligationParameter),
            "max_output_bytes" => parse_byte_cap(require(argument)?).map(Self::MaxOutputBytes),
            "audit_level" => match require(argument)? {
                "full" => Ok(Self::AuditLevel(AuditLevel::Full)),
                _ => Err(ValueError::ObligationParameter),
            },
            "require_artifact_capture" => flag(argument, Self::RequireArtifactCapture),
            "network_deny" => flag(argument, Self::NetworkDeny),
            "read_only_workspace" => flag(argument, Self::ReadOnlyWorkspace),
            "single_use_only" => flag(argument, Self::SingleUseOnly),
            "force_quarantined_read" => flag(argument, Self::ForceQuarantinedRead),
            "workspace_exec_hygiene" => flag(argument, Self::WorkspaceExecHygiene),
            _ => Err(ValueError::UnknownObligation),
        }
    }
}

/// The parameter of an obligation that defines one.
fn require(argument: Option<&str>) -> Result<&str, ValueError> {
    argument.ok_or(ValueError::ObligationParameter)
}

/// An obligation that defines no parameter, refusing one that carries it.
fn flag(argument: Option<&str>, value: Obligation) -> Result<Obligation, ValueError> {
    match argument {
        None => Ok(value),
        Some(_) => Err(ValueError::ObligationParameter),
    }
}

/// A byte cap, written as a plain decimal.
///
/// Underscores are a TOML *integer* convenience and this is the inside of a
/// string, so accepting them would be inventing a second number grammar. Zero
/// is refused: a cap permitting no output at all is a denial written as a
/// permission, the same fail-closed reading that refuses an empty method set.
fn parse_byte_cap(raw: &str) -> Result<u64, ValueError> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValueError::ObligationParameter);
    }
    match raw.parse::<u64>() {
        Ok(0) | Err(_) => Err(ValueError::ObligationParameter),
        Ok(value) => Ok(value),
    }
}

impl fmt::Display for Obligation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        match self {
            Self::ForceEnvironment(p) | Self::RedactProfile(p) => write!(f, "={p}"),
            Self::MaxOutputBytes(n) => write!(f, "={n}"),
            Self::AuditLevel(level) => write!(f, "={level}"),
            Self::RequireArtifactCapture
            | Self::NetworkDeny
            | Self::ReadOnlyWorkspace
            | Self::SingleUseOnly
            | Self::ForceQuarantinedRead
            | Self::WorkspaceExecHygiene => Ok(()),
        }
    }
}

/// The obligations one decision carries: sorted, duplicate-free, bounded.
///
/// One representation per set, so two decisions imposing the same conditions
/// compare equal and render identically however the rules were written. The
/// approval binding hashes obligations ([`APPROVALS.md`] §2), and a set with
/// two spellings would be a set with two hashes.
///
/// [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Obligations(Vec<Obligation>);

impl Obligations {
    /// The empty set.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Build from a list, refusing duplicates.
    ///
    /// A duplicate is refused rather than collapsed. Two identical entries mean
    /// the author wrote one condition twice; two *different* parameterisations
    /// of one obligation — `max_output_bytes=1024` beside
    /// `max_output_bytes=4096` — mean the author does not know which cap
    /// applies, and that is not a question a loader should settle by picking.
    ///
    /// # Errors
    ///
    /// [`ValueError::DuplicateObligation`] if any obligation, or any
    /// parameterisation of one obligation, appears twice, and
    /// [`ValueError::TooManyObligations`] past the bound.
    pub fn new(mut obligations: Vec<Obligation>) -> Result<Self, ValueError> {
        if obligations.len() > limits::MAX_OBLIGATIONS_PER_RULE {
            return Err(ValueError::TooManyObligations);
        }
        obligations.sort();
        let ambiguous = obligations
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a.name() == b.name()));
        if ambiguous {
            return Err(ValueError::DuplicateObligation);
        }
        Ok(Self(obligations))
    }

    /// The obligations, in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[Obligation] {
        &self.0
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for Obligations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, obligation) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{obligation}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditLevel, Obligation, Obligations, ProfileRef};
    use crate::policy::error::ValueError;

    #[test]
    fn every_documented_obligation_parses_and_renders_back() {
        for text in [
            "force_environment=oci-strict",
            "max_output_bytes=262144",
            "require_artifact_capture",
            "redact_profile=strict",
            "network_deny",
            "read_only_workspace",
            "audit_level=full",
            "single_use_only",
            "force_quarantined_read",
            "workspace_exec_hygiene",
        ] {
            let Ok(obligation) = Obligation::parse(text) else {
                unreachable!("{text} must parse")
            };
            assert_eq!(obligation.to_string(), text);
        }
    }

    #[test]
    fn an_unknown_obligation_is_an_error_and_not_a_dropped_element() {
        for text in [
            "netwok_deny",
            "",
            "NETWORK_DENY",
            "Network_Deny",
            "network_den",
            "network_denyy",
        ] {
            assert_eq!(
                Obligation::parse(text),
                Err(ValueError::UnknownObligation),
                "{text}"
            );
        }
    }

    #[test]
    fn a_parameter_is_required_exactly_where_one_is_defined() {
        for text in [
            "max_output_bytes",
            "force_environment",
            "redact_profile",
            "audit_level",
        ] {
            assert_eq!(
                Obligation::parse(text),
                Err(ValueError::ObligationParameter),
                "{text} needs a parameter"
            );
        }
        for text in [
            "network_deny=1",
            "single_use_only=true",
            "read_only_workspace=",
        ] {
            assert_eq!(
                Obligation::parse(text),
                Err(ValueError::ObligationParameter),
                "{text} defines no parameter"
            );
        }
    }

    #[test]
    fn a_malformed_byte_cap_never_becomes_a_smaller_number() {
        for text in [
            "max_output_bytes=-1",
            "max_output_bytes=0",
            "max_output_bytes=1.5",
            "max_output_bytes=",
            "max_output_bytes=1_024",
            "max_output_bytes=0x400",
            "max_output_bytes= 1024",
            "max_output_bytes=+1024",
            // u64::MAX + 1 must not wrap, saturate or truncate.
            "max_output_bytes=18446744073709551616",
        ] {
            assert_eq!(
                Obligation::parse(text),
                Err(ValueError::ObligationParameter),
                "{text}"
            );
        }
        assert_eq!(
            Obligation::parse("max_output_bytes=18446744073709551615"),
            Ok(Obligation::MaxOutputBytes(u64::MAX))
        );
    }

    #[test]
    fn audit_level_is_closed() {
        assert_eq!(
            Obligation::parse("audit_level=full"),
            Ok(Obligation::AuditLevel(AuditLevel::Full))
        );
        for bad in [
            "audit_level=FULL",
            "audit_level=partial",
            "audit_level=none",
        ] {
            assert_eq!(
                Obligation::parse(bad),
                Err(ValueError::ObligationParameter),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_profile_reference_is_a_bounded_machine_identifier() {
        assert!(ProfileRef::new("oci-strict").is_some());
        for bad in [
            "",
            "OCI",
            "-x",
            "x-",
            "a--b",
            "has space",
            "a/b",
            "1abc",
            "a_b",
        ] {
            assert!(ProfileRef::new(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_set_is_sorted_deduplicated_and_refuses_ambiguity() {
        let (Ok(deny), Ok(read_only)) = (
            Obligation::parse("network_deny"),
            Obligation::parse("read_only_workspace"),
        ) else {
            unreachable!("both parse")
        };
        let (Ok(one), Ok(two)) = (
            Obligations::new(vec![read_only.clone(), deny.clone()]),
            Obligations::new(vec![deny.clone(), read_only]),
        ) else {
            unreachable!("both build")
        };
        assert_eq!(one, two, "order of writing must not change the value");
        assert_eq!(one.len(), 2);

        assert_eq!(
            Obligations::new(vec![deny.clone(), deny]),
            Err(ValueError::DuplicateObligation)
        );

        // Two caps is not a cap.
        let (Ok(small), Ok(large)) = (
            Obligation::parse("max_output_bytes=1024"),
            Obligation::parse("max_output_bytes=4096"),
        ) else {
            unreachable!("both parse")
        };
        assert_eq!(
            Obligations::new(vec![small, large]),
            Err(ValueError::DuplicateObligation)
        );
    }

    #[test]
    fn the_empty_set_is_representable_and_renders_to_nothing() {
        assert!(Obligations::none().is_empty());
        assert_eq!(Obligations::none().to_string(), "");
        assert_eq!(Obligations::none().len(), 0);
    }
}
