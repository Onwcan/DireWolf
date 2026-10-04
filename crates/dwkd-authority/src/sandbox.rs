//! Execution environments, as the authority decides them (M5a, [ADR-0047]):
//! what an environment must be, and what level of assurance a measurement of
//! one earns.
//!
//! The broker prepares and measures; it judges nothing. Here the level is
//! judged, by one rule and no score:
//!
//! * The environment kind **declares** a level — `oci` declares
//!   `CONTAINER_ISOLATION` — which is a claim, never evidence.
//! * A measurement **measures** that level only if every invariant the
//!   profile requires is present exactly once and `PASS`. One `FAIL`, one
//!   `UNOBSERVABLE`, one missing, and the measured level is `NONE`: there is
//!   no partial credit and no weight.
//! * The **effective** level is the lower of the two: a measurement never
//!   raises what the kind claims, and a claim never raises what was measured.
//!
//! An environment whose effective level is below what it must have is
//! refused — never used "with a warning". Nothing in a configuration can
//! turn a required invariant off: the required set is the profile's, spelled
//! once in `dwk_proto::brokerp::sandbox`.
//!
//! `PROXY_ONLY` (M5b, [ADR-0048]) is configured with what only it needs —
//! the relay's digest and the egress budgets — through
//! [`SandboxConfig::proxy_only`]; `NO_NETWORK` remains the evidence
//! harness's. The destinations a `PROXY_ONLY` environment may reach are not
//! configuration: they are the run's own `network.https` grants, exactly
//! ([`egress_targets`]).
//!
//! [ADR-0047]: ../../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md
//! [ADR-0048]: ../../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md

use core::fmt;

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::egress::{
    EgressByteBudget, EgressGrant, EgressHost, EgressPort, EgressTarget, EgressTargets,
    EgressTunnelLimit, MAX_EGRESS_TARGETS,
};
use dwk_proto::brokerp::sandbox::{
    AssuranceLevel, ImageId, NetworkTopology, SandboxInvariant, Verdict, required_invariants,
};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use crate::capability::{
    Action, Capability, HostPattern, Namespace, PortSpec, Scope, SyntacticScope,
};

/// A kind of execution environment. M5a has one; `local` joins it when M5d
/// moves host execution under the same abstraction (SANDBOX.md §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentKind {
    /// An `oci-strict` container.
    Oci,
}

impl EnvironmentKind {
    /// What the kind claims before anything is measured.
    #[must_use]
    pub const fn declared(self) -> DeclaredAssurance {
        match self {
            Self::Oci => DeclaredAssurance(AssuranceLevel::ContainerIsolation),
        }
    }

    /// The level an environment of this kind must have to be used.
    #[must_use]
    pub const fn required(self) -> AssuranceLevel {
        match self {
            Self::Oci => AssuranceLevel::ContainerIsolation,
        }
    }
}

/// A level a kind claims. Not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredAssurance(pub AssuranceLevel);

/// A level a measurement earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredAssurance(pub AssuranceLevel);

/// The level an environment has: the lower of the declared and the measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveAssurance(pub AssuranceLevel);

impl EffectiveAssurance {
    /// `min(declared, measured)`.
    #[must_use]
    pub const fn of(declared: DeclaredAssurance, measured: MeasuredAssurance) -> Self {
        Self(declared.0.min(measured.0))
    }
}

/// What a measurement earned, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// The kind's claim.
    pub declared: DeclaredAssurance,
    /// What the measurement earned.
    pub measured: MeasuredAssurance,
    /// The lower of the two.
    pub effective: EffectiveAssurance,
    /// Required invariants that measured `FAIL`.
    pub failed: Vec<SandboxInvariant>,
    /// Required invariants that measured `UNOBSERVABLE`, were absent, or were
    /// reported more than once.
    pub unobservable: Vec<SandboxInvariant>,
}

impl Judgement {
    /// Whether the environment may be used: its effective level is the one
    /// its kind requires.
    #[must_use]
    pub fn usable(&self, kind: EnvironmentKind) -> bool {
        self.effective.0.rank() >= kind.required().rank()
            && self.failed.is_empty()
            && self.unobservable.is_empty()
    }

    /// The failure class of an unusable environment (ADR-0047 §6), most
    /// specific first. `None` for a usable one.
    #[must_use]
    pub fn failure(&self, kind: EnvironmentKind) -> Option<&'static str> {
        if self.usable(kind) {
            return None;
        }
        let failed = |i: SandboxInvariant| self.failed.contains(&i);
        Some(if failed(SandboxInvariant::HostProbeDigest) {
            "PROBE_MISMATCH"
        } else if failed(SandboxInvariant::HostImagePinned) {
            "IMAGE_MISMATCH"
        } else if failed(SandboxInvariant::HostRelayDigest) {
            "RELAY_MISMATCH"
        } else if [
            SandboxInvariant::HostNetworkIsolated,
            SandboxInvariant::HostProxyRelay,
            SandboxInvariant::ContainerNetworkIsolated,
            SandboxInvariant::ContainerProxyReachable,
            SandboxInvariant::ContainerDirectEgressRefused,
            SandboxInvariant::ContainerDirectDnsRefused,
            SandboxInvariant::ContainerRawSocketsRefused,
        ]
        .into_iter()
        .any(failed)
        {
            "NETWORK_TOPOLOGY_FAILED"
        } else if [
            SandboxInvariant::HostResourceLimits,
            SandboxInvariant::ContainerRlimits,
            SandboxInvariant::ContainerCgroupLimits,
        ]
        .into_iter()
        .any(failed)
        {
            "RESOURCE_LIMIT_FAILED"
        } else if !self.failed.is_empty() {
            "ASSURANCE_FAILED"
        } else {
            "ASSURANCE_UNOBSERVABLE"
        })
    }
}

/// Judge a measurement of an environment of `kind` with `topology`.
#[must_use]
pub fn judge(
    kind: EnvironmentKind,
    topology: NetworkTopology,
    checks: &[(SandboxInvariant, Verdict)],
) -> Judgement {
    let mut failed = Vec::new();
    let mut unobservable = Vec::new();
    for invariant in required_invariants(topology) {
        let found: Vec<Verdict> = checks
            .iter()
            .filter(|(i, _)| *i == invariant)
            .map(|(_, v)| *v)
            .collect();
        match found.as_slice() {
            [Verdict::Pass] => {}
            [Verdict::Fail] => failed.push(invariant),
            // Unobservable, absent, or said twice: nothing can be concluded.
            _ => unobservable.push(invariant),
        }
    }
    let measured = if failed.is_empty() && unobservable.is_empty() {
        MeasuredAssurance(kind.declared().0)
    } else {
        MeasuredAssurance(AssuranceLevel::None)
    };
    let declared = kind.declared();
    Judgement {
        declared,
        measured,
        effective: EffectiveAssurance::of(declared, measured),
        failed,
        unobservable,
    }
}

/// The failure class of a broker refusal of an environment operation.
#[must_use]
pub const fn refusal_class(refusal: BrokerRefusal) -> &'static str {
    match refusal {
        BrokerRefusal::ImageMissing => "IMAGE_MISSING",
        BrokerRefusal::RuntimeUnavailable => "RUNTIME_UNAVAILABLE",
        BrokerRefusal::RuntimeFailed => "RUNTIME_FAILED",
        BrokerRefusal::RuntimeOutputMalformed => "RUNTIME_OUTPUT_MALFORMED",
        BrokerRefusal::TopologyUnavailable => "TOPOLOGY_UNAVAILABLE",
        BrokerRefusal::ProxyUnavailable => "PROXY_UNAVAILABLE",
        BrokerRefusal::EnvironmentNotFound => "ENVIRONMENT_NOT_FOUND",
        BrokerRefusal::EnvironmentAmbiguous => "ENVIRONMENT_AMBIGUOUS",
        BrokerRefusal::ForeignEnvironment => "FOREIGN_ENVIRONMENT",
        BrokerRefusal::DigestMismatch | BrokerRefusal::ExecutableUntrusted => {
            "RUNTIME_CLIENT_CHANGED"
        }
        BrokerRefusal::Unsupported => "WORKSPACE_PATH_UNSUPPORTED",
        _ => "BROKER_EXECUTION_ERROR",
    }
}

/// The operator's sandbox configuration (M5a): which runtime client, which
/// socket, which image — by content digest — and which probe. There is no
/// field for a runtime flag, a capability, a device or a profile weaker
/// than `oci-strict`: the profile is not configurable.
///
/// A `PROXY_ONLY` configuration (M5b) adds the relay's digest and the egress
/// budgets, and nothing else: no destination, no resolver, no exception. The
/// destinations are the run's grants.
///
/// Only the evidence harness constructs one ([`crate::state::Authority::attach_sandbox`]);
/// `dwkd-authority serve` has no option that does, so no production
/// authority prepares an environment before M5d.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    runtime: String,
    socket: HostPath,
    image: ImageId,
    probe_sha256: ContentDigest,
    topology: NetworkTopology,
    egress: Option<EgressConfig>,
}

/// What a `PROXY_ONLY` configuration adds: the relay, by digest, and the
/// budgets every one of its environments gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressConfig {
    relay_sha256: ContentDigest,
    max_tunnels: EgressTunnelLimit,
    max_upload_bytes: EgressByteBudget,
    max_download_bytes: EgressByteBudget,
}

impl EgressConfig {
    /// A relay digest and budgets, checked.
    ///
    /// # Errors
    ///
    /// [`SandboxConfigError::RelayDigest`] for a digest that is not 64
    /// lowercase hexadecimal digits; [`SandboxConfigError::EgressBudget`] for
    /// a limit outside the protocol's bounds (1–64 tunnels, 1 byte–16 GiB).
    pub fn new(
        relay_sha256: &str,
        max_tunnels: u16,
        max_upload_bytes: u64,
        max_download_bytes: u64,
    ) -> Result<Self, SandboxConfigError> {
        let relay_sha256 = digest(relay_sha256).ok_or(SandboxConfigError::RelayDigest)?;
        Ok(Self {
            relay_sha256,
            max_tunnels: EgressTunnelLimit::new(max_tunnels)
                .ok_or(SandboxConfigError::EgressBudget)?,
            max_upload_bytes: EgressByteBudget::new(max_upload_bytes)
                .ok_or(SandboxConfigError::EgressBudget)?,
            max_download_bytes: EgressByteBudget::new(max_download_bytes)
                .ok_or(SandboxConfigError::EgressBudget)?,
        })
    }

    /// The relay's digest.
    #[must_use]
    pub const fn relay_sha256(&self) -> &ContentDigest {
        &self.relay_sha256
    }

    /// The grant for `targets`: these destinations, these budgets.
    #[must_use]
    pub fn grant(&self, targets: EgressTargets) -> EgressGrant {
        EgressGrant {
            targets,
            max_tunnels: self.max_tunnels,
            max_upload_bytes: self.max_upload_bytes,
            max_download_bytes: self.max_download_bytes,
        }
    }
}

/// The destinations a run's grants give a `PROXY_ONLY` environment: every
/// `network.https` capability whose host is **exact** — never a wildcard,
/// never `*`, never an address literal, which the proxy could not compare
/// with a TLS server name — on its port, or 443 when it names none. Nothing
/// else becomes a destination: not `network.http` (no plain HTTP through the
/// proxy), not `network.tcp` (no raw TCP). The probe's reserved name is never
/// one.
///
/// # Errors
///
/// `EGRESS_GRANT_TOO_LARGE` when more destinations are granted than one
/// grant can carry: refused, never truncated.
pub fn egress_targets<'a>(
    capabilities: impl IntoIterator<Item = &'a Capability>,
) -> Result<EgressTargets, &'static str> {
    let mut targets: Vec<EgressTarget> = Vec::new();
    for capability in capabilities {
        let verb = capability.verb();
        if verb.namespace() != Namespace::Network || verb.action() != Action::Https {
            continue;
        }
        let Scope::Syntactic(SyntacticScope::Endpoint(endpoint)) = capability.scope() else {
            continue;
        };
        let HostPattern::Exact(_) = endpoint.host() else {
            continue;
        };
        let host = endpoint.host().to_string();
        if host == dwk_sandbox_profile_probe_host() {
            continue;
        }
        let port = match endpoint.port() {
            PortSpec::Port(port) => port,
            PortSpec::Any => 443,
        };
        let (Some(host), Some(port)) = (EgressHost::new(host), EgressPort::new(port)) else {
            continue;
        };
        let target = EgressTarget { host, port };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.len() > MAX_EGRESS_TARGETS {
        return Err("EGRESS_GRANT_TOO_LARGE");
    }
    EgressTargets::new(targets).ok_or("EGRESS_GRANT_TOO_LARGE")
}

/// The name the probe asks the proxy for, which no grant may hold
/// (`dwk_sandbox_profile::PROXY_PROBE_HOST`; the authority does not link the
/// profile crate, so the reserved name is spelled here and checked against
/// it by the broker's refusal of any grant naming it).
const fn dwk_sandbox_profile_probe_host() -> &'static str {
    "direwolf-probe.invalid"
}

fn digest(text: &str) -> Option<ContentDigest> {
    ContentDigest::new(text.to_owned()).filter(|d| {
        d.as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Why a sandbox configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxConfigError {
    /// The runtime client is not an absolute path.
    RuntimePath,
    /// The socket is not an absolute path.
    SocketPath,
    /// The image is not named by `sha256:` and its content digest: a tag, a
    /// short id or anything else a registry could re-point.
    ImageNotPinned,
    /// The probe digest is not 64 lowercase hexadecimal digits.
    ProbeDigest,
    /// `PROXY_ONLY` named without its relay and budgets
    /// ([`SandboxConfig::proxy_only`] is how it is configured).
    EgressUnconfigured,
    /// The relay digest is not 64 lowercase hexadecimal digits.
    RelayDigest,
    /// An egress budget outside the protocol's bounds.
    EgressBudget,
}

impl SandboxConfigError {
    /// The stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimePath => "RUNTIME_PATH",
            Self::SocketPath => "SOCKET_PATH",
            Self::ImageNotPinned => "IMAGE_NOT_PINNED",
            Self::ProbeDigest => "PROBE_DIGEST",
            Self::EgressUnconfigured => "EGRESS_UNCONFIGURED",
            Self::RelayDigest => "RELAY_DIGEST",
            Self::EgressBudget => "EGRESS_BUDGET",
        }
    }
}

impl fmt::Display for SandboxConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for SandboxConfigError {}

fn absolute(path: &str) -> bool {
    path.starts_with('/') && !path.chars().any(char::is_control)
}

impl SandboxConfig {
    /// A `NO_NETWORK` configuration, checked. `PROXY_ONLY` is refused here:
    /// it needs [`Self::proxy_only`].
    ///
    /// # Errors
    ///
    /// [`SandboxConfigError`]: nothing in it is accepted approximately.
    pub fn new(
        runtime: &str,
        socket: &str,
        image: &str,
        probe_sha256: &str,
        topology: NetworkTopology,
    ) -> Result<Self, SandboxConfigError> {
        if topology != NetworkTopology::NoNetwork {
            return Err(SandboxConfigError::EgressUnconfigured);
        }
        Self::checked(runtime, socket, image, probe_sha256, topology, None)
    }

    /// A `PROXY_ONLY` configuration (M5b), checked.
    ///
    /// # Errors
    ///
    /// [`SandboxConfigError`]: nothing in it is accepted approximately.
    pub fn proxy_only(
        runtime: &str,
        socket: &str,
        image: &str,
        probe_sha256: &str,
        egress: EgressConfig,
    ) -> Result<Self, SandboxConfigError> {
        Self::checked(
            runtime,
            socket,
            image,
            probe_sha256,
            NetworkTopology::ProxyOnly,
            Some(egress),
        )
    }

    fn checked(
        runtime: &str,
        socket: &str,
        image: &str,
        probe_sha256: &str,
        topology: NetworkTopology,
        egress: Option<EgressConfig>,
    ) -> Result<Self, SandboxConfigError> {
        if !absolute(runtime) {
            return Err(SandboxConfigError::RuntimePath);
        }
        let socket = absolute(socket)
            .then(|| HostPath::new(socket.to_owned()))
            .flatten()
            .ok_or(SandboxConfigError::SocketPath)?;
        let image = ImageId::new(image.to_owned()).ok_or(SandboxConfigError::ImageNotPinned)?;
        let probe_sha256 = digest(probe_sha256).ok_or(SandboxConfigError::ProbeDigest)?;
        Ok(Self {
            runtime: runtime.to_owned(),
            socket,
            image,
            probe_sha256,
            topology,
            egress,
        })
    }

    /// The runtime client's path, as configured; resolved and hashed before
    /// every use.
    #[must_use]
    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    /// The runtime's control socket.
    #[must_use]
    pub const fn socket(&self) -> &HostPath {
        &self.socket
    }

    /// The image.
    #[must_use]
    pub const fn image(&self) -> &ImageId {
        &self.image
    }

    /// The probe's digest.
    #[must_use]
    pub const fn probe_sha256(&self) -> &ContentDigest {
        &self.probe_sha256
    }

    /// The topology.
    #[must_use]
    pub const fn topology(&self) -> NetworkTopology {
        self.topology
    }

    /// What `PROXY_ONLY` adds; `None` for `NO_NETWORK`.
    #[must_use]
    pub const fn egress(&self) -> Option<&EgressConfig> {
        self.egress.as_ref()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use dwk_proto::brokerp::sandbox::{AssuranceLevel, NetworkTopology, SandboxInvariant, Verdict};

    use super::{
        EgressConfig, EnvironmentKind, SandboxConfig, SandboxConfigError, egress_targets, judge,
    };

    fn all(verdict: Verdict) -> Vec<(SandboxInvariant, Verdict)> {
        SandboxInvariant::ALL
            .iter()
            .map(|i| (*i, verdict))
            .collect()
    }

    #[test]
    fn every_pass_earns_the_declared_level_and_no_more() {
        let j = judge(
            EnvironmentKind::Oci,
            NetworkTopology::NoNetwork,
            &all(Verdict::Pass),
        );
        assert_eq!(j.measured.0, AssuranceLevel::ContainerIsolation);
        assert_eq!(j.effective.0, AssuranceLevel::ContainerIsolation);
        assert!(j.usable(EnvironmentKind::Oci));
        assert_eq!(j.failure(EnvironmentKind::Oci), None);
        // A claim is never raised by what is measured: the effective level is
        // never above what the kind declares.
        assert!(j.effective.0.rank() <= EnvironmentKind::Oci.declared().0.rank());
    }

    #[test]
    fn one_fail_or_one_unobservable_or_one_missing_refuses_with_no_partial_credit() {
        for topology in [NetworkTopology::NoNetwork, NetworkTopology::ProxyOnly] {
            one_topology_refuses_with_no_partial_credit(topology);
        }
        // What only a proxy has does not bind an environment that has none.
        for invariant in [
            SandboxInvariant::HostRelayDigest,
            SandboxInvariant::ContainerProxyReachable,
        ] {
            let mut checks = all(Verdict::Pass);
            for check in &mut checks {
                if check.0 == invariant {
                    check.1 = Verdict::Fail;
                }
            }
            assert!(
                judge(EnvironmentKind::Oci, NetworkTopology::NoNetwork, &checks)
                    .usable(EnvironmentKind::Oci)
            );
            assert!(
                !judge(EnvironmentKind::Oci, NetworkTopology::ProxyOnly, &checks)
                    .usable(EnvironmentKind::Oci)
            );
        }
    }

    fn one_topology_refuses_with_no_partial_credit(topology: NetworkTopology) {
        for invariant in dwk_proto::brokerp::sandbox::required_invariants(topology) {
            for verdict in [Verdict::Fail, Verdict::Unobservable] {
                let mut checks = all(Verdict::Pass);
                for check in &mut checks {
                    if check.0 == invariant {
                        check.1 = verdict;
                    }
                }
                let j = judge(EnvironmentKind::Oci, topology, &checks);
                assert_eq!(
                    j.measured.0,
                    AssuranceLevel::None,
                    "{invariant:?} {verdict:?}"
                );
                assert_eq!(j.effective.0, AssuranceLevel::None);
                assert!(!j.usable(EnvironmentKind::Oci));
                assert!(j.failure(EnvironmentKind::Oci).is_some());
            }
            let missing: Vec<_> = all(Verdict::Pass)
                .into_iter()
                .filter(|(i, _)| *i != invariant)
                .collect();
            let j = judge(EnvironmentKind::Oci, topology, &missing);
            assert_eq!(j.unobservable, [invariant]);
            assert!(!j.usable(EnvironmentKind::Oci));
            // Said twice, even both PASS, is not a measurement.
            let mut twice = all(Verdict::Pass);
            twice.push((invariant, Verdict::Pass));
            let j = judge(EnvironmentKind::Oci, topology, &twice);
            assert_eq!(j.unobservable, [invariant]);
        }
    }

    #[test]
    fn the_failure_class_names_the_most_specific_cause() {
        use SandboxInvariant as I;
        let with = |pairs: &[(SandboxInvariant, Verdict)]| {
            let mut checks = all(Verdict::Pass);
            for (i, v) in pairs {
                for check in &mut checks {
                    if check.0 == *i {
                        check.1 = *v;
                    }
                }
            }
            judge(EnvironmentKind::Oci, NetworkTopology::NoNetwork, &checks)
                .failure(EnvironmentKind::Oci)
        };
        assert_eq!(
            with(&[
                (I::HostProbeDigest, Verdict::Fail),
                (I::HostImagePinned, Verdict::Fail)
            ]),
            Some("PROBE_MISMATCH")
        );
        assert_eq!(
            with(&[(I::HostImagePinned, Verdict::Fail)]),
            Some("IMAGE_MISMATCH")
        );
        assert_eq!(
            with(&[(I::ContainerCgroupLimits, Verdict::Fail)]),
            Some("RESOURCE_LIMIT_FAILED")
        );
        assert_eq!(
            with(&[(I::ContainerDirectDnsRefused, Verdict::Fail)]),
            Some("NETWORK_TOPOLOGY_FAILED")
        );
        assert_eq!(
            with(&[(I::HostProxyRelay, Verdict::Fail)]),
            Some("NETWORK_TOPOLOGY_FAILED")
        );
        assert_eq!(
            with(&[(I::HostRootReadOnly, Verdict::Fail)]),
            Some("ASSURANCE_FAILED")
        );
        assert_eq!(
            with(&[(I::ContainerSetnsBlocked, Verdict::Unobservable)]),
            Some("ASSURANCE_UNOBSERVABLE")
        );
    }

    #[test]
    fn a_configuration_is_pinned_and_proxy_only_needs_its_relay_and_budgets() {
        let digest = "a".repeat(64);
        let image = format!("sha256:{}", "b".repeat(64));
        let ok = SandboxConfig::new(
            "/usr/bin/docker",
            "/var/run/docker.sock",
            &image,
            &digest,
            NetworkTopology::NoNetwork,
        );
        assert!(ok.is_ok());
        for (runtime, socket, image, digest, topology, want) in [
            (
                "docker",
                "/s",
                image.as_str(),
                digest.as_str(),
                NetworkTopology::NoNetwork,
                SandboxConfigError::RuntimePath,
            ),
            (
                "/d",
                "s",
                image.as_str(),
                digest.as_str(),
                NetworkTopology::NoNetwork,
                SandboxConfigError::SocketPath,
            ),
            (
                "/d",
                "/s",
                "alpine:3",
                digest.as_str(),
                NetworkTopology::NoNetwork,
                SandboxConfigError::ImageNotPinned,
            ),
            (
                "/d",
                "/s",
                "alpine@sha256:00",
                digest.as_str(),
                NetworkTopology::NoNetwork,
                SandboxConfigError::ImageNotPinned,
            ),
            (
                "/d",
                "/s",
                image.as_str(),
                "ABC",
                NetworkTopology::NoNetwork,
                SandboxConfigError::ProbeDigest,
            ),
            (
                "/d",
                "/s",
                image.as_str(),
                digest.as_str(),
                NetworkTopology::ProxyOnly,
                SandboxConfigError::EgressUnconfigured,
            ),
        ] {
            assert_eq!(
                SandboxConfig::new(runtime, socket, image, digest, topology),
                Err(want)
            );
        }
    }

    #[test]
    fn a_proxy_only_configuration_is_exact_or_refused() {
        let digest = "a".repeat(64);
        let image = format!("sha256:{}", "b".repeat(64));
        let relay = "c".repeat(64);
        let egress = EgressConfig::new(&relay, 8, 1 << 30, 1 << 30).unwrap();
        let config =
            SandboxConfig::proxy_only("/usr/bin/docker", "/s", &image, &digest, egress).unwrap();
        assert_eq!(config.topology(), NetworkTopology::ProxyOnly);
        assert_eq!(config.egress().unwrap().relay_sha256().as_str(), relay);
        for (relay, tunnels, up, down, want) in [
            ("ABC", 8, 1, 1, SandboxConfigError::RelayDigest),
            (
                &"C".repeat(64)[..],
                8,
                1,
                1,
                SandboxConfigError::RelayDigest,
            ),
            (&relay[..], 0, 1, 1, SandboxConfigError::EgressBudget),
            (&relay[..], 65, 1, 1, SandboxConfigError::EgressBudget),
            (&relay[..], 8, 0, 1, SandboxConfigError::EgressBudget),
            (
                &relay[..],
                8,
                1,
                (16 << 30) + 1,
                SandboxConfigError::EgressBudget,
            ),
        ] {
            assert_eq!(EgressConfig::new(relay, tunnels, up, down), Err(want));
        }
    }

    fn capability(text: &str) -> crate::capability::Capability {
        crate::policy::testing::syntactic_capability(text)
    }

    #[test]
    fn only_exact_https_hosts_become_destinations() {
        let granted = [
            capability("network.https:pypi.org"),
            capability("network.https:files.pythonhosted.org:443"),
            capability("network.https:registry.example.com:8443"),
            capability("network.https:*.example.org"),
            crate::policy::testing::universal_capability("network.https"),
            capability("network.http:plain.example.com"),
            capability("network.tcp:db.example.com:5432"),
            capability("network.https:10.0.0.1"),
            capability("network.https:direwolf-probe.invalid"),
            capability("network.https:pypi.org:443"),
        ];
        let targets = egress_targets(&granted).unwrap();
        let named: Vec<String> = targets
            .iter()
            .map(|t| format!("{}:{}", t.host.as_str(), t.port.get()))
            .collect();
        assert_eq!(
            named,
            [
                "pypi.org:443",
                "files.pythonhosted.org:443",
                "registry.example.com:8443"
            ]
        );
        assert!(egress_targets(&[]).unwrap().is_empty());
        let many: Vec<_> = (0..65)
            .map(|n| capability(&format!("network.https:h{n}.example.com")))
            .collect();
        assert_eq!(egress_targets(&many), Err("EGRESS_GRANT_TOO_LARGE"));
    }
}
