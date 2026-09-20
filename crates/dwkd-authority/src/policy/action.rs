//! [`CanonicalAction`] — what policy decides *about*.
//!
//! [`POLICY.md`] §1 rule 3: policy "evaluates on canonical actions only —
//! resolved inodes, resolved IPs, normalised argv — never on model-supplied
//! strings." This module is that sentence as a type. Every field is either a
//! value the canonicaliser produced or a classification it computed; there is
//! no free-form argument, no raw command string and no path spelling anywhere
//! in it.
//!
//! # What M3c cannot build, and does not try to
//!
//! The `capability` on an action names a resolved scope, and for `fs` and
//! `process` that is a canonical identity only `crate::resource` may create
//! ([ADR-0037]). So a real `fs.read` action cannot exist until M4's
//! canonicaliser does. That is a milestone boundary, not a gap in this type:
//! the policy semantics over those values exist and are tested with synthetic
//! identities in unit tests, and *deriving* the values from an OS resource is
//! M4's.
//!
//! [ADR-0037]: ../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use core::fmt;

use crate::capability::Capability;

/// Where an action would run.
///
/// [`POLICY.md`] §3 matches `when.environment = "sandbox"` and `"host"`, and
/// `deny-host-exec-unless-opted-in` is one of the load-bearing denials.
/// [`SANDBOX.md`](../../../../../docs/SANDBOX.md) §7 gives the sandbox a
/// profile identifier; policy matches the *kind*, and the identifier travels
/// so an explanation can name it.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Environment {
    /// Inside an execution environment. The profile id is for display and for
    /// the approval binding, never for matching.
    Sandbox,
    /// On the host, with the broker's own privileges.
    Host,
}

impl Environment {
    /// Every environment.
    pub const ALL: [Self; 2] = [Self::Sandbox, Self::Host];

    /// The TOML spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Host => "host",
        }
    }

    /// Parse the TOML spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == text)
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether an action's arguments would be *reinterpreted* by what runs them.
///
/// [`POLICY.md`] §3 is emphatic that this is **not** "contains no
/// metacharacters": `argv` is an array and never reaches a shell, so `$` and
/// `|` in a commit message are ordinary bytes. It is false only for argv that
/// would be reinterpreted — an element naming a shell (`sh -c`, `bash -c`), an
/// `--exec`-style flag on an allowlisted tool, or an element resolving to
/// another executable.
///
/// **The canonicaliser computes this; policy consumes it.** An enum rather
/// than a `bool` so the type says a classification was made, and so that the
/// absent case on an action with no argv at all is `None` rather than `false`.
/// M3c does no shell parsing, and TX004 is the check that it never starts.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgvSafety {
    /// Nothing in argv would be reinterpreted.
    Safe,
    /// Something in argv would be: a shell, an exec-style flag, or an element
    /// resolving to another executable.
    Reinterpreting,
}

impl ArgvSafety {
    /// The classification a rule's `argv_safe = <bool>` selects.
    #[must_use]
    pub const fn from_rule_flag(safe: bool) -> Self {
        if safe {
            Self::Safe
        } else {
            Self::Reinterpreting
        }
    }
}

/// Whether the run has reached this destination before.
///
/// Kernel-derived: it is a fact about what the authority has already brokered
/// for this run, which is exactly the kind of fact [ADR-0028] requires the
/// kernel to own. `approve-egress-when-tainted` turns on it.
///
/// [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Novelty {
    /// The run has not reached this destination before.
    Novel,
    /// It has.
    Seen,
}

impl Novelty {
    /// The value a rule's `destination_novel = <bool>` selects.
    #[must_use]
    pub const fn from_rule_flag(novel: bool) -> Self {
        if novel { Self::Novel } else { Self::Seen }
    }
}

/// A resolved IP address: four octets or sixteen.
///
/// **Deliberately not `std::net::IpAddr`.** The policy core imports no
/// `std::net` at all, so the ambient-effect rule over it (TX004) is the same
/// shape as the one over `dwk-proto` and the capability core, with no
/// exception carved out for a type that happens to be in the networking
/// module. An address here is a value somebody else resolved; nothing in this
/// crate can open a socket or ask a resolver, and that should be visible from
/// the imports rather than argued in a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddress {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

impl IpAddress {
    /// The address as big-endian octets.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        match self {
            Self::V4(o) => o,
            Self::V6(o) => o,
        }
    }

    /// How many bits an address of this family has.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        match self {
            Self::V4(_) => 32,
            Self::V6(_) => 128,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(o) => {
                for (index, byte) in o.iter().enumerate() {
                    if index > 0 {
                        f.write_str(".")?;
                    }
                    write!(f, "{byte}")?;
                }
                Ok(())
            }
            Self::V6(o) => {
                // Full form, no `::` elision: one address, one spelling. An
                // audit record that renders the same address two ways is an
                // audit record you cannot grep.
                for (index, pair) in o.chunks(2).enumerate() {
                    if index > 0 {
                        f.write_str(":")?;
                    }
                    match pair {
                        [high, low] => {
                            write!(f, "{:04x}", u16::from(*high) << 8 | u16::from(*low))?;
                        }
                        _ => return Err(fmt::Error),
                    }
                }
                Ok(())
            }
        }
    }
}

/// The action policy decides about: a resolved capability plus the facts the
/// canonicaliser derived alongside it.
///
/// Built through [`CanonicalAction::new`] and then narrowed with the `with_*`
/// methods, each of which consumes and returns the value — so an action is
/// assembled in one expression and is immutable once a reference to it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAction {
    capability: Capability,
    environment: Environment,
    argv_safety: Option<ArgvSafety>,
    byte_count: Option<u64>,
    destination_ip: Option<IpAddress>,
    destination_novelty: Option<Novelty>,
}

impl CanonicalAction {
    /// The action of doing what `capability` names, in `environment`.
    #[must_use]
    pub const fn new(capability: Capability, environment: Environment) -> Self {
        Self {
            capability,
            environment,
            argv_safety: None,
            byte_count: None,
            destination_ip: None,
            destination_novelty: None,
        }
    }

    /// The canonicaliser's argv classification.
    #[must_use]
    pub fn with_argv_safety(mut self, safety: ArgvSafety) -> Self {
        self.argv_safety = Some(safety);
        self
    }

    /// How many bytes the action would move.
    #[must_use]
    pub const fn with_byte_count(mut self, bytes: u64) -> Self {
        self.byte_count = Some(bytes);
        self
    }

    /// The destination address this decision is about.
    #[must_use]
    pub const fn with_destination_ip(mut self, address: IpAddress) -> Self {
        self.destination_ip = Some(address);
        self
    }

    /// Whether this run has reached the destination before.
    #[must_use]
    pub const fn with_destination_novelty(mut self, novelty: Novelty) -> Self {
        self.destination_novelty = Some(novelty);
        self
    }

    /// The capability this action requires.
    #[must_use]
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Where it would run.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// The argv classification, if the action has argv.
    #[must_use]
    pub const fn argv_safety(&self) -> Option<ArgvSafety> {
        self.argv_safety
    }

    /// The byte count, if the action moves bytes.
    #[must_use]
    pub const fn byte_count(&self) -> Option<u64> {
        self.byte_count
    }

    /// The destination address this decision is about, if it has one.
    ///
    /// # One address, not a set
    ///
    /// A security decision rather than a simplification. A set admits no
    /// single fail-closed reading of `ip_in`: "every address is in range" is
    /// fail-closed for an `ALLOW` and fail-open for a `DENY` — a host
    /// answering with one public and one loopback address would escape a rule
    /// denying the loopback — while "any address is in range" is fail-closed
    /// for a `DENY` and fail-open for an `ALLOW`. One predicate cannot be
    /// both, so the *action* is made unambiguous instead of the predicate.
    ///
    /// An action with no address is refused at evaluation rather than read as
    /// "no match" — see
    /// [`Reason::UnresolvedCanonicalInput`](super::Reason::UnresolvedCanonicalInput).
    ///
    /// # What this does NOT establish
    ///
    /// **The name is `destination_ip`, not `pinned_address`, because nothing
    /// here pins anything.** This type holds four or sixteen octets somebody
    /// else supplied. It carries no proof that the address came from a
    /// resolver, that DNS was pinned, or — the one that matters — that the
    /// connection the broker eventually opens will use *this* address.
    ///
    /// So M3c removes a **policy-evaluation ambiguity**. It does not provide
    /// end-to-end DNS-rebinding resistance, which additionally requires:
    ///
    /// ```text
    ///     IP evaluated by policy  ==  IP used for the authorised connection
    /// ```
    ///
    /// with no re-resolution or substitution in between. That invariant
    /// belongs to M4's network canonicalisation and the broker's execution
    /// path, alongside the CONNECT proxy's DNS pinning and SNI/host agreement
    /// ([`NETWORK_SECURITY.md`](../../../../../docs/NETWORK_SECURITY.md) §1,
    /// [ADR-0024](../../../../../docs/adr/0024-sandbox-network-topology.md)).
    /// Neither exists yet, and a reconnect or re-resolution must take a fresh
    /// authority decision rather than reuse this one.
    #[must_use]
    pub const fn destination_ip(&self) -> Option<IpAddress> {
        self.destination_ip
    }

    /// Whether the destination is novel to this run, if it has one.
    #[must_use]
    pub const fn destination_novelty(&self) -> Option<Novelty> {
        self.destination_novelty
    }
}

#[cfg(test)]
mod tests {
    use super::{ArgvSafety, Environment, IpAddress, Novelty};

    #[test]
    fn environments_round_trip_and_parse_exactly() {
        for environment in Environment::ALL {
            assert_eq!(Environment::parse(environment.as_str()), Some(environment));
        }
        for bad in ["Sandbox", "HOST", "", "container", "local"] {
            assert!(Environment::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn rule_flags_select_the_classification_they_name() {
        assert_eq!(ArgvSafety::from_rule_flag(true), ArgvSafety::Safe);
        assert_eq!(
            ArgvSafety::from_rule_flag(false),
            ArgvSafety::Reinterpreting
        );
        assert_eq!(Novelty::from_rule_flag(true), Novelty::Novel);
        assert_eq!(Novelty::from_rule_flag(false), Novelty::Seen);
    }

    #[test]
    fn addresses_carry_their_family_and_render_one_way() {
        let v4 = IpAddress::V4([10, 0, 0, 1]);
        assert_eq!(v4.bits(), 32);
        assert_eq!(v4.octets().len(), 4);
        assert_eq!(v4.to_string(), "10.0.0.1");

        let mut octets = [0u8; 16];
        let Some(last) = octets.last_mut() else {
            unreachable!("sixteen octets")
        };
        *last = 1;
        let v6 = IpAddress::V6(octets);
        assert_eq!(v6.bits(), 128);
        assert_eq!(v6.octets().len(), 16);
        assert_eq!(v6.to_string(), "0000:0000:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn an_action_starts_with_every_optional_fact_absent() {
        // The default for a fact nobody supplied is "absent", never a value a
        // predicate could match. A `false` default for argv safety would make
        // `when.argv_safe = false` fire on an action with no argv at all.
        let capability = crate::policy::testing::universal_capability("network.https");
        let action = super::CanonicalAction::new(capability, Environment::Sandbox);
        assert_eq!(action.argv_safety(), None);
        assert_eq!(action.byte_count(), None);
        assert_eq!(action.destination_novelty(), None);
        assert_eq!(action.destination_ip(), None);
    }
}
