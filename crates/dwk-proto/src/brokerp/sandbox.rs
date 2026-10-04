//! The sandbox's wire vocabulary (M5a, ADR-0047): what the private channel
//! and the assurance probe's report say about an execution environment — its
//! profile and topology by name, the closed set of invariants a measurement
//! reports and the verdicts on each, the assurance levels, the runtime's
//! identifiers, and the probe's report itself.
//!
//! **Vocabulary, not policy.** The values an `oci-strict` environment is
//! built with — its uid, limits, mounts, labels, device set and seccomp
//! filter — are the broker's and the probe's, in `dwk-sandbox-profile`,
//! which the authority does not link. What is here is only what crosses a
//! wire: a name for each fact, and the rule that `CONTAINER_ISOLATION` means
//! every one of them passed.

use crate::error::{ProtocolError, Violation};
use crate::json::{self, Number, ParseOptions, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{wire_enum, wire_int, wire_text};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

use super::KernelNumber;

// ---------------------------------------------------------------------------
// The closed vocabulary.
// ---------------------------------------------------------------------------

wire_enum! {
    /// An execution-environment profile. One exists: `oci-strict`. A weaker
    /// environment, if one is ever supported, is a different profile with
    /// its own honest assurance — never `oci-strict` with a setting changed.
    EnvironmentProfile {
        /// SANDBOX.md §2.
        OciStrict = "OCI_STRICT",
    }
}

impl EnvironmentProfile {
    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OciStrict => "oci-strict",
        }
    }
}

wire_enum! {
    /// An environment's network topology: an authority-owned property of the
    /// environment, never a runtime flag a caller supplies (ADR-0024,
    /// ADR-0047 §9). A network mode, not an assurance level.
    NetworkTopology {
        /// ADR-0024's production topology, as ADR-0048 builds it (M5b): a
        /// network namespace with no interface but loopback, no route and no
        /// resolver, whose one reachable peer is the broker's CONNECT proxy at
        /// `169.254.7.1:8080` — an address on that loopback, served by the
        /// environment's relay and forwarded to the broker.
        ProxyOnly = "PROXY_ONLY",
        /// No interface but loopback, and no proxy. M5a's **evidence**
        /// topology only: the broker accepts it only when its operator started
        /// it with `--allow-evidence-topology`, and no production path
        /// requests it.
        NoNetwork = "NO_NETWORK",
    }
}

wire_enum! {
    /// What a DireWolf container is to its environment (M5b, ADR-0048). Every
    /// container an environment owns carries its role as a label, so a relay
    /// is never mistaken for the environment, or for its twin.
    ContainerRole {
        /// The environment itself: the trusted probe, holding.
        Environment = "ENVIRONMENT",
        /// A `PROXY_ONLY` environment's relay: unprivileged, in the
        /// environment's network namespace, forwarding each connection to
        /// `169.254.7.1:8080` to the broker's proxy.
        Relay = "RELAY",
        /// A `PROXY_ONLY` environment's one-shot setup: adds the proxy address
        /// to the namespace's loopback, and exits. Never kept.
        Setup = "SETUP",
    }
}

impl ContainerRole {
    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Relay => "relay",
            Self::Setup => "setup",
        }
    }

    /// The role a label value names.
    #[must_use]
    pub fn from_label(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.label() == value)
    }
}

wire_enum! {
    /// How strongly an environment isolates what runs in it (SANDBOX.md §1).
    /// Ordered: [`AssuranceLevel::rank`].
    AssuranceLevel {
        /// No isolation: the host.
        None = "NONE",
        /// A process on the host with its own restrictions.
        ProcessIsolation = "PROCESS_ISOLATION",
        /// An OCI container meeting every required invariant.
        ContainerIsolation = "CONTAINER_ISOLATION",
        /// A virtual machine. No implementation exists.
        VmIsolation = "VM_ISOLATION",
    }
}

impl AssuranceLevel {
    /// Its position: a higher rank isolates more.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ProcessIsolation => 1,
            Self::ContainerIsolation => 2,
            Self::VmIsolation => 3,
        }
    }

    /// The lower of two levels.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

wire_enum! {
    /// One measured fact. There is no weighted score: each required
    /// invariant passes or the environment is not `CONTAINER_ISOLATION`.
    Verdict {
        /// The invariant holds, as observed.
        Pass = "PASS",
        /// The invariant does not hold.
        Fail = "FAIL",
        /// It could not be observed. **Never a pass.**
        Unobservable = "UNOBSERVABLE",
    }
}

/// Where an invariant is observed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vantage {
    /// The broker, from the runtime's record of the container.
    Host,
    /// The trusted probe, from inside the environment.
    Container,
}

wire_enum! {
    /// Every invariant `oci-strict` requires, each named once (ADR-0047 §6).
    /// `HOST_*` are observed by the broker from the runtime's own record of
    /// the running container; `CONTAINER_*` by the trusted probe from inside
    /// it. Where a fact can be seen from both sides it is measured from both.
    SandboxInvariant {
        /// The container runs the pinned image, named by content digest.
        HostImagePinned = "HOST_IMAGE_PINNED",
        /// The probe inside the image hashes to the authority's digest.
        HostProbeDigest = "HOST_PROBE_DIGEST",
        /// Not privileged.
        HostNotPrivileged = "HOST_NOT_PRIVILEGED",
        /// Configured user `10001:10001`.
        HostUserNonRoot = "HOST_USER_NON_ROOT",
        /// A read-only root filesystem.
        HostRootReadOnly = "HOST_ROOT_READ_ONLY",
        /// Every capability dropped and none added.
        HostCapabilitiesDropped = "HOST_CAPABILITIES_DROPPED",
        /// `no-new-privileges`.
        HostNoNewPrivileges = "HOST_NO_NEW_PRIVILEGES",
        /// DireWolf's seccomp profile, byte for byte.
        HostSeccompProfile = "HOST_SECCOMP_PROFILE",
        /// A private PID namespace.
        HostPidNamespacePrivate = "HOST_PID_NAMESPACE_PRIVATE",
        /// A private IPC namespace.
        HostIpcNamespacePrivate = "HOST_IPC_NAMESPACE_PRIVATE",
        /// A private UTS namespace.
        HostUtsNamespacePrivate = "HOST_UTS_NAMESPACE_PRIVATE",
        /// Not the host's user namespace mode.
        HostUsernsNotHost = "HOST_USERNS_NOT_HOST",
        /// A private cgroup namespace.
        HostCgroupNamespacePrivate = "HOST_CGROUP_NAMESPACE_PRIVATE",
        /// The environment's network topology, and never the host's network.
        HostNetworkIsolated = "HOST_NETWORK_ISOLATED",
        /// Exactly the workspace, the two temporary mounts and nothing else.
        HostMountsExact = "HOST_MOUNTS_EXACT",
        /// No container runtime socket anywhere in the mounts.
        HostNoRuntimeSocket = "HOST_NO_RUNTIME_SOCKET",
        /// No device mapped in, no device cgroup rule added.
        HostNoDevices = "HOST_NO_DEVICES",
        /// Every resource limit exactly as the profile states it.
        HostResourceLimits = "HOST_RESOURCE_LIMITS",
        /// Exactly DireWolf's labels for this environment.
        HostLabelsExact = "HOST_LABELS_EXACT",
        /// The container is running.
        HostRunning = "HOST_RUNNING",
        /// The mounted workspace is the object the authority pinned.
        HostWorkspaceIdentity = "HOST_WORKSPACE_IDENTITY",
        /// The environment's proxy variables are exactly the broker's fixed
        /// endpoint (`PROXY_ONLY`), or absent (`NO_NETWORK`): nothing inherited
        /// from the host, nothing a caller chose (M5b).
        HostProxyEnvironment = "HOST_PROXY_ENVIRONMENT",
        /// The environment's network peers are exactly its topology's. For
        /// `PROXY_ONLY`: one relay in the environment's own network namespace
        /// — the pinned image, unprivileged, a read-only root, exactly the
        /// broker's egress socket mounted, labelled as this environment's
        /// relay — the broker's proxy for it open, and no setup container
        /// left. For `NO_NETWORK`: no relay, no setup container and no proxy
        /// at all (M5b).
        HostProxyRelay = "HOST_PROXY_RELAY",
        /// The relay inside the image hashes to the authority's digest (M5b).
        HostRelayDigest = "HOST_RELAY_DIGEST",
        /// Real, effective and saved uid and gid are `10001`, no
        /// supplementary group.
        ContainerUidGid = "CONTAINER_UID_GID",
        /// Every capability set is empty.
        ContainerCapabilitiesEmpty = "CONTAINER_CAPABILITIES_EMPTY",
        /// `no_new_privs` is set.
        ContainerNoNewPrivileges = "CONTAINER_NO_NEW_PRIVILEGES",
        /// A seccomp filter is in force.
        ContainerSeccompFilter = "CONTAINER_SECCOMP_FILTER",
        /// DireWolf's filter, not merely some filter: `ptrace` and
        /// `process_vm_readv` of the probe's own processes — which the
        /// runtime's default profile allows — are refused.
        ContainerSeccompProfileActive = "CONTAINER_SECCOMP_PROFILE_ACTIVE",
        /// `/`, `/etc` and `/usr` cannot be written.
        ContainerRootReadOnly = "CONTAINER_ROOT_READ_ONLY",
        /// `/workspace` can be written.
        ContainerWorkspaceWritable = "CONTAINER_WORKSPACE_WRITABLE",
        /// `/tmp` and `/var/tmp` can be written.
        ContainerTmpWritable = "CONTAINER_TMP_WRITABLE",
        /// `/tmp` and `/var/tmp` held nothing when the measurement began: no
        /// state carried over from any earlier environment.
        ContainerTmpFresh = "CONTAINER_TMP_FRESH",
        /// No runtime socket is reachable.
        ContainerNoRuntimeSocket = "CONTAINER_NO_RUNTIME_SOCKET",
        /// Every mount point is one the profile expects.
        ContainerMountsExpected = "CONTAINER_MOUNTS_EXPECTED",
        /// Only [`ALLOWED_DEVICES`] exist, and no block device.
        ContainerDevicesMinimal = "CONTAINER_DEVICES_MINIMAL",
        /// PID 1 is the environment's own holder: a private PID namespace.
        ContainerPidNamespacePrivate = "CONTAINER_PID_NAMESPACE_PRIVATE",
        /// The network topology holds from inside: the only interface is
        /// loopback, no route leaves it, and a virtual socket cannot be made.
        ContainerNetworkIsolated = "CONTAINER_NETWORK_ISOLATED",
        /// `PROXY_ONLY`: `169.254.7.1:8080` accepts a connection and answers
        /// as DireWolf's proxy (M5b).
        ContainerProxyReachable = "CONTAINER_PROXY_REACHABLE",
        /// Attempted, every direct path out is refused by the topology — TCP
        /// and UDP over IPv4 and IPv6 to an external, a host, a LAN, a
        /// metadata and a link-local address, and the proxy address on any
        /// port but the proxy's (M5b).
        ContainerDirectEgressRefused = "CONTAINER_DIRECT_EGRESS_REFUSED",
        /// Attempted, no DNS query leaves: UDP and TCP to the configured and
        /// to well-known resolvers get no answer (M5b).
        ContainerDirectDnsRefused = "CONTAINER_DIRECT_DNS_REFUSED",
        /// Raw and packet sockets cannot be made, and an ICMP socket, where
        /// one can be made, reaches nothing (M5b).
        ContainerRawSocketsRefused = "CONTAINER_RAW_SOCKETS_REFUSED",
        /// The process limits are the profile's.
        ContainerRlimits = "CONTAINER_RLIMITS",
        /// The cgroup limits are the profile's, as the kernel enforces them.
        ContainerCgroupLimits = "CONTAINER_CGROUP_LIMITS",
        /// `/proc`'s escape surfaces are masked or read-only.
        ContainerProcRestricted = "CONTAINER_PROC_RESTRICTED",
        /// `mount` and `umount2` are refused.
        ContainerMountBlocked = "CONTAINER_MOUNT_BLOCKED",
        /// `unshare` is refused, for every namespace.
        ContainerUnshareBlocked = "CONTAINER_UNSHARE_BLOCKED",
        /// `setns` is refused.
        ContainerSetnsBlocked = "CONTAINER_SETNS_BLOCKED",
        /// The kernel keyring calls are refused.
        ContainerKeyringBlocked = "CONTAINER_KEYRING_BLOCKED",
    }
}

impl SandboxInvariant {
    /// Which side observes it.
    #[must_use]
    pub const fn vantage(self) -> Vantage {
        match self {
            Self::HostImagePinned
            | Self::HostProbeDigest
            | Self::HostNotPrivileged
            | Self::HostUserNonRoot
            | Self::HostRootReadOnly
            | Self::HostCapabilitiesDropped
            | Self::HostNoNewPrivileges
            | Self::HostSeccompProfile
            | Self::HostPidNamespacePrivate
            | Self::HostIpcNamespacePrivate
            | Self::HostUtsNamespacePrivate
            | Self::HostUsernsNotHost
            | Self::HostCgroupNamespacePrivate
            | Self::HostNetworkIsolated
            | Self::HostMountsExact
            | Self::HostNoRuntimeSocket
            | Self::HostNoDevices
            | Self::HostResourceLimits
            | Self::HostLabelsExact
            | Self::HostRunning
            | Self::HostWorkspaceIdentity
            | Self::HostProxyEnvironment
            | Self::HostProxyRelay
            | Self::HostRelayDigest => Vantage::Host,
            _ => Vantage::Container,
        }
    }

    /// Whether the invariant concerns the proxy itself, and so exists only
    /// in a `PROXY_ONLY` environment.
    #[must_use]
    pub const fn proxy_only(self) -> bool {
        matches!(self, Self::HostRelayDigest | Self::ContainerProxyReachable)
    }
}

/// Every invariant `CONTAINER_ISOLATION` requires of an `oci-strict`
/// environment with `topology`. Each must be `PASS`; absent, `FAIL` and
/// `UNOBSERVABLE` alike deny the level.
///
/// `PROXY_ONLY` requires every invariant. `NO_NETWORK` requires every one but
/// the two that concern the proxy itself (ADR-0048): it has no proxy to hash
/// or reach. Its peers are still judged — none — and the direct-egress, DNS
/// and raw-socket attempts hold there too.
#[must_use]
pub fn required_invariants(topology: NetworkTopology) -> Vec<SandboxInvariant> {
    SandboxInvariant::ALL
        .iter()
        .copied()
        .filter(|i| topology == NetworkTopology::ProxyOnly || !i.proxy_only())
        .collect()
}

/// The invariants the probe reports, in declaration order.
#[must_use]
pub fn probe_invariants() -> Vec<SandboxInvariant> {
    SandboxInvariant::ALL
        .iter()
        .copied()
        .filter(|i| i.vantage() == Vantage::Container)
        .collect()
}

// ---------------------------------------------------------------------------
// Identifiers the runtime owns, spelled once.
// ---------------------------------------------------------------------------

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

wire_text! {
    /// An image, by content: `sha256:` and 64 lowercase hexadecimal digits.
    /// Never a tag: a tag names whatever was last pushed under it.
    ImageId,
    max_chars = 71,
    pattern = Some("^sha256:[0-9a-f]{64}$"),
    format = None,
    validate = |s| s.len() == 71 && s.strip_prefix("sha256:").is_some_and(lower_hex)
}

wire_text! {
    /// A container, as the runtime names it: 64 lowercase hexadecimal digits.
    /// The runtime's name for it, never DireWolf's: an environment is named
    /// by its `EnvironmentId`.
    ContainerRef,
    max_chars = 64,
    pattern = Some("^[0-9a-f]{64}$"),
    format = None,
    validate = |s| s.len() == 64 && lower_hex(s)
}

wire_text! {
    /// The authority store an environment belongs to: its instance, 1 to 32
    /// lowercase hexadecimal digits. A second DireWolf on the same host
    /// labels with its own and is never mistaken for this one.
    StoreInstance,
    max_chars = 32,
    pattern = Some("^[0-9a-f]{1,32}$"),
    format = None,
    validate = |s| !s.is_empty() && s.len() <= 32 && lower_hex(s)
}

wire_text! {
    /// A container runtime's own version text, for evidence only.
    RuntimeVersion,
    max_chars = 64,
    pattern = Some("^[0-9A-Za-z.+~_-]{1,64}$"),
    format = None,
    validate = |s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'_' | b'-'))
}

wire_int! {
    /// A duration in milliseconds, up to an hour: evidence of how long a
    /// lifecycle step took.
    Milliseconds(u32), min = 0, max = 3_600_000
}

impl Milliseconds {
    /// `elapsed`, in whole milliseconds, capped at the bound.
    #[must_use]
    pub fn of(elapsed: core::time::Duration) -> Self {
        Self(
            u32::try_from(elapsed.as_millis())
                .unwrap_or(Self::MAX)
                .min(Self::MAX),
        )
    }
}

// ---------------------------------------------------------------------------
// The probe's report.
// ---------------------------------------------------------------------------

wire_enum! {
    /// What the probe's output is.
    ProbeReportKind {
        /// The one kind.
        Report = "sandbox.probe_report",
    }
}

wire_int! {
    /// The probe report's schema version: 2 since M5b added the `PROXY_ONLY`
    /// and direct-egress invariants (ADR-0048). A version-1 report — a probe
    /// built before them — is not a report.
    ProbeReportVersion(u16), min = 2, max = 2
}

wire_struct! {
    /// One invariant and what was found.
    InvariantCheck: reject {
        /// Which.
        required invariant: SandboxInvariant,
        /// What.
        required verdict: Verdict,
    }
}

/// A measurement's checks: at most one per invariant.
pub type InvariantChecks = BoundedList<InvariantCheck, 64>;

wire_struct! {
    /// The trusted probe's whole output (ADR-0047 §8): a closed schema, and
    /// nothing else — no free text, no diagnostic blob. Anything that does not
    /// decode as exactly this, with nothing before or after it, is not a
    /// report, and a measurement without one is `UNOBSERVABLE`.
    ProbeReport: reject {
        /// Always `sandbox.probe_report`.
        required kind: ProbeReportKind,
        /// Always 1.
        required version: ProbeReportVersion,
        /// Every `CONTAINER_*` invariant, once each.
        required checks: InvariantChecks,
        /// `st_dev` of `/workspace`, as the probe found it.
        optional workspace_device: KernelNumber,
        /// `st_ino` of `/workspace`, as the probe found it.
        optional workspace_inode: KernelNumber,
    }
}

/// The most bytes a probe report may be.
pub const MAX_PROBE_REPORT_BYTES: usize = 16 * 1024;

impl ProbeReport {
    /// Decode a report: exactly one strict JSON value, within
    /// [`MAX_PROBE_REPORT_BYTES`], of exactly this schema, naming each
    /// invariant at most once and only `CONTAINER_*` ones.
    ///
    /// # Errors
    ///
    /// Anything else.
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let report: Self = super::decode_bytes(bytes, MAX_PROBE_REPORT_BYTES)?;
        let mut seen = Vec::new();
        for check in &report.checks {
            if seen.contains(&check.invariant) || check.invariant.vantage() != Vantage::Container {
                return Err(ProtocolError::schema(
                    crate::error::Violation::Inconsistent,
                    "/checks",
                    "a probe report names each container invariant once",
                ));
            }
            seen.push(check.invariant);
        }
        Ok(report)
    }

    /// Encode as the probe prints it: canonical JSON, and a newline.
    ///
    /// # Errors
    ///
    /// The report does not survive its own round trip.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let value = self.encode()?;
        let mut bytes = json::to_canonical_bytes(&value);
        let back: Self = Self::decode(json::parse(&bytes, ParseOptions::dwkp())?, &mut Cx::new())?;
        if &back != self {
            return Err(ProtocolError::schema(
                crate::error::Violation::Inconsistent,
                "",
                "a probe report does not survive its own round trip",
            ));
        }
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "test fixtures: a fixture that cannot be built is a failed test"
)]
mod tests {
    use super::*;

    #[test]
    fn assurance_is_ordered_and_min_takes_the_weaker() {
        assert_eq!(
            AssuranceLevel::ContainerIsolation.min(AssuranceLevel::None),
            AssuranceLevel::None
        );
        assert_eq!(
            AssuranceLevel::VmIsolation.min(AssuranceLevel::ContainerIsolation),
            AssuranceLevel::ContainerIsolation
        );
    }

    #[test]
    fn a_probe_report_is_closed() {
        let checks = InvariantChecks::new(
            probe_invariants()
                .into_iter()
                .map(|invariant| InvariantCheck {
                    invariant,
                    verdict: Verdict::Pass,
                })
                .collect(),
        )
        .unwrap();
        let report = ProbeReport {
            kind: ProbeReportKind::Report,
            version: ProbeReportVersion::new(2).unwrap(),
            checks,
            workspace_device: Some(KernelNumber::from_u64(64)),
            workspace_inode: Some(KernelNumber::from_u64(2)),
        };
        let bytes = report.to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            ProbeReport::decode_bytes(text.trim_end().as_bytes()).unwrap(),
            report
        );
        // Unknown field, trailing data, truncation, a duplicate, a host
        // invariant: none is a report.
        let body = text.trim_end();
        let extra = body.replacen('{', "{\"note\":\"x\",", 1);
        let trailing = format!("{body}{body}");
        let truncated = &body[..body.len() / 2];
        let host = body.replacen("CONTAINER_UID_GID", "HOST_RUNNING", 1);
        let twice = body.replacen("CONTAINER_CAPABILITIES_EMPTY", "CONTAINER_UID_GID", 1);
        for bad in [
            extra.as_str(),
            trailing.as_str(),
            truncated,
            host.as_str(),
            twice.as_str(),
        ] {
            assert!(ProbeReport::decode_bytes(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn each_topology_requires_its_own_invariants() {
        let proxy = required_invariants(NetworkTopology::ProxyOnly);
        let none = required_invariants(NetworkTopology::NoNetwork);
        assert_eq!(proxy, SandboxInvariant::ALL.to_vec(), "PROXY_ONLY: all");
        for proxy_only in [
            SandboxInvariant::HostRelayDigest,
            SandboxInvariant::ContainerProxyReachable,
        ] {
            assert!(proxy.contains(&proxy_only) && !none.contains(&proxy_only));
        }
        // The peers, the bypass attempts and the proxy variables bind both
        // topologies.
        for both in [
            SandboxInvariant::HostProxyEnvironment,
            SandboxInvariant::HostProxyRelay,
            SandboxInvariant::HostNetworkIsolated,
            SandboxInvariant::ContainerNetworkIsolated,
            SandboxInvariant::ContainerDirectEgressRefused,
            SandboxInvariant::ContainerDirectDnsRefused,
            SandboxInvariant::ContainerRawSocketsRefused,
        ] {
            assert!(proxy.contains(&both) && none.contains(&both), "{both:?}");
        }
        assert_eq!(none.len() + 2, proxy.len());
        // Roles round-trip through their labels.
        for role in ContainerRole::ALL {
            assert_eq!(ContainerRole::from_label(role.label()), Some(*role));
        }
        assert_eq!(ContainerRole::from_label("Relay"), None);
    }

    #[test]
    fn identifiers_have_one_spelling() {
        let digest = "a".repeat(64);
        assert!(ImageId::new(format!("sha256:{digest}")).is_some());
        for bad in [
            digest.clone(),
            format!("sha256:{}", "A".repeat(64)),
            "busybox:latest".to_owned(),
            format!("sha256:{}", "a".repeat(63)),
        ] {
            assert!(ImageId::new(bad.clone()).is_none(), "{bad}");
        }
        assert!(ContainerRef::new(digest.clone()).is_some());
        assert!(ContainerRef::new(&digest[..12]).is_none(), "no short ids");
        assert!(StoreInstance::new("").is_none());
    }
}
