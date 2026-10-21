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
//!
//! **The workspace contract** (M5d.4, ADR-0052 §§6, 10) is the exception that
//! proves the rule: what a workspace must be -- its group, its root's mode,
//! a filesystem of its own within the operator's quota -- is checked by the
//! authority on its pinned root as well as by the probe and the broker, so
//! the values all three share are spelled here, once.

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
        /// The mounted workspace's root is the authority's or root's -- never
        /// the workload's, which could change its mode -- its group is the
        /// workspace group and its mode exactly [`WORKSPACE_ROOT_MODE`], as
        /// the authority found it on its side; and the broker is a member of
        /// the group (M5d.4, OD-3(a)). Judged by the broker from the probe's
        /// [`WorkspaceFacts`].
        HostWorkspaceOwnership = "HOST_WORKSPACE_OWNERSHIP",
        /// The mounted workspace is the root of a filesystem of its own,
        /// mounted `nosuid` and `nodev`, whose capacity is the one the
        /// authority measured on its side and lies within the operator's
        /// quota (M5d.4, OD-6). Judged by the broker from the probe's
        /// [`WorkspaceFacts`].
        HostWorkspaceCapacity = "HOST_WORKSPACE_CAPACITY",
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
        /// `/workspace` can be written. A full filesystem is still writable:
        /// space, not permission, is what it lacks.
        ContainerWorkspaceWritable = "CONTAINER_WORKSPACE_WRITABLE",
        /// Attempted: a directory made in `/workspace` takes the workspace
        /// group and the set-group-id bit, and a file made there the group --
        /// so what a workload makes, the authority and the broker can reach
        /// (M5d.4, OD-3(a)).
        ContainerWorkspaceGroupInherited = "CONTAINER_WORKSPACE_GROUP_INHERITED",
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
            | Self::HostWorkspaceOwnership
            | Self::HostWorkspaceCapacity
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

    /// Whether the invariant is the workspace contract's (M5d.4): its
    /// ownership, its bounded filesystem and its group's inheritance. Every
    /// bounded environment -- every production one -- requires them; only
    /// the evidence harness's [`WorkspaceContract::UnverifiedEvidence`] does
    /// not.
    #[must_use]
    pub const fn workspace_contract(self) -> bool {
        matches!(
            self,
            Self::HostWorkspaceOwnership
                | Self::HostWorkspaceCapacity
                | Self::ContainerWorkspaceGroupInherited
        )
    }
}

/// Every invariant `CONTAINER_ISOLATION` requires of an `oci-strict`
/// environment with `topology` and `workspace`. Each must be `PASS`; absent,
/// `FAIL` and `UNOBSERVABLE` alike deny the level.
///
/// `PROXY_ONLY` requires every invariant. `NO_NETWORK` requires every one but
/// the two that concern the proxy itself (ADR-0048): it has no proxy to hash
/// or reach. Its peers are still judged — none — and the direct-egress, DNS
/// and raw-socket attempts hold there too.
///
/// A bounded workspace (M5d.4) requires the workspace contract's three. Only
/// the evidence harness's unverified workspace -- which a broker builds only
/// when its operator acknowledged it (`--allow-unverified-workspace`), never
/// in production -- requires them not, and is reported so.
#[must_use]
pub fn required_invariants(
    topology: NetworkTopology,
    workspace: WorkspaceContract,
) -> Vec<SandboxInvariant> {
    SandboxInvariant::ALL
        .iter()
        .copied()
        .filter(|i| topology == NetworkTopology::ProxyOnly || !i.proxy_only())
        .filter(|i| workspace == WorkspaceContract::Bounded || !i.workspace_contract())
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
    /// and direct-egress invariants (ADR-0048); 3 since M5d.4 replaced the
    /// workspace's identity with its whole [`WorkspaceFacts`] and added the
    /// group's inheritance. A report of an earlier version — a probe built
    /// before them — is not a report.
    ProbeReportVersion(u16), min = 3, max = 3
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
        /// What the mounted workspace is, as the probe found it -- all of it,
        /// or nothing when any part could not be read.
        optional workspace: WorkspaceFacts,
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

// ---------------------------------------------------------------------------
// The workspace contract (M5d.4, ADR-0052 §§6, 10; OD-3(a), OD-6).
// ---------------------------------------------------------------------------
//
// What a workspace must be before anything runs in it, shared by the three
// programs that check it: the authority, on its pinned root; the probe, which
// reports what is mounted; and the broker, which judges the one against the
// other. The values are a contract between them, not the broker's profile,
// so they are here rather than in `dwk-sandbox-profile`, which the authority
// does not link -- the broker asserts they are the profile's.

/// The group a workspace is shared through (OD-3(a)): `10001`, the gid
/// every workload runs as. The workload reaches the workspace through its
/// own primary group -- no group is added to it, no runtime flag changes --
/// and the authority and the broker through being the group's members.
pub const WORKSPACE_GROUP: u32 = 10_001;

/// The uid every workload runs as. It may never own a workspace root: an
/// owner can change the root's mode, and so open it to anyone.
pub const WORKLOAD_UID: u32 = 10_001;

/// A workspace root's mode, exactly: set-group-id -- every name made in it
/// takes the group, every directory made in it the bit -- owner and group
/// `rwx`, and nothing for anyone else, so no identity outside the group
/// reaches anything beneath it.
pub const WORKSPACE_ROOT_MODE: u32 = 0o2770;

/// The umask every workload runs with: what it makes is the group's to read
/// and write (`0660` files, `2770` directories beneath a set-group-id root)
/// and nobody else's.
pub const WORKLOAD_UMASK: u32 = 0o007;

/// Whether a filesystem of `capacity` bytes is the workspace a quota of
/// `quota` bytes declares: never larger -- a larger one is unbounded against
/// the declaration -- and no more than a quarter smaller, which is more than
/// a filesystem's own metadata (its journal, its inode tables) takes; a
/// smaller one means the declaration does not describe the filesystem.
#[must_use]
pub const fn capacity_within_quota(capacity: u64, quota: u64) -> bool {
    capacity <= quota && capacity >= quota - (quota >> 2)
}

/// What the operator says a run's workspace is (M5d.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceContract {
    /// The operator's bounded filesystem, shared through the workspace group:
    /// every production environment's. Ownership, the filesystem and its
    /// capacity are measured, and required.
    Bounded,
    /// The evidence harness's own scratch directory, for the evidence of
    /// what is not the workspace: neither its group nor its bound is proved.
    /// Built only by a broker whose operator acknowledged it
    /// (`--allow-unverified-workspace`, logged `REDUCED ASSURANCE`); never
    /// production's.
    UnverifiedEvidence,
}

impl WorkspaceContract {
    /// The stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bounded => "BOUNDED",
            Self::UnverifiedEvidence => "UNVERIFIED_EVIDENCE",
        }
    }
}

wire_int! {
    /// A workspace quota the operator declares, in bytes: 16 MiB to 16 TiB.
    WorkspaceQuota(u64), min = 16 << 20, max = 16 << 40
}

wire_struct! {
    /// A bounded workspace, as the authority found it on its side (M5d.4):
    /// the operator's quota, and the capacity and owner it measured on the
    /// root it pinned. The probe's facts from inside must agree with it.
    WorkspaceBound: reject {
        /// The quota the operator declared.
        required quota_bytes: WorkspaceQuota,
        /// The filesystem's capacity in bytes, `f_blocks × f_frsize` of the
        /// authority's `fstatvfs` of its pinned root.
        required capacity_bytes: KernelNumber,
        /// The root's owner, as the authority's `fstat` found it.
        required owner: KernelNumber,
    }
}

wire_struct! {
    /// What the probe found the mounted workspace to be (M5d.4): its
    /// identity, its root's owner, group and mode, the mount it is, and the
    /// filesystem's size from `statvfs`. Facts, never verdicts: the broker
    /// judges them against what the authority found ([`WorkspaceBound`]).
    WorkspaceFacts: reject {
        /// `st_dev` of `/workspace`.
        required device: KernelNumber,
        /// `st_ino` of `/workspace`.
        required inode: KernelNumber,
        /// Its owner.
        required uid: KernelNumber,
        /// Its group.
        required gid: KernelNumber,
        /// `st_mode & 0o7777`: the permission, set-id and sticky bits.
        required mode: KernelNumber,
        /// Whether `/workspace` is its filesystem's root -- the mount's root
        /// within the filesystem is `/` -- so that nothing on the filesystem
        /// lies outside the workspace.
        required filesystem_root: bool,
        /// Whether the mount is `nosuid`.
        required nosuid: bool,
        /// Whether the mount is `nodev`.
        required nodev: bool,
        /// `f_frsize`: the unit of the block counts.
        required block_size: KernelNumber,
        /// `f_blocks`: the filesystem's size, in those units.
        required blocks: KernelNumber,
        /// `f_bavail`: the units an unprivileged writer may still use.
        required blocks_available: KernelNumber,
        /// `f_files`: how many inodes the filesystem has.
        required files: KernelNumber,
    }
}

impl WorkspaceFacts {
    /// `(st_dev, st_ino)`.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.device.value(), self.inode.value())
    }

    /// The filesystem's capacity, `f_blocks × f_frsize`, counted without
    /// overflow.
    #[must_use]
    pub fn capacity(&self) -> Capacity {
        capacity(
            self.block_size.value(),
            self.blocks.value(),
            self.blocks_available.value(),
        )
    }
}

/// A filesystem's capacity from its `statvfs` facts -- `f_frsize`,
/// `f_blocks`, `f_bavail` -- counted without overflow: the one rule the
/// authority's vantage and the probe's are both held to.
#[must_use]
pub const fn capacity(unit: u64, blocks: u64, available: u64) -> Capacity {
    if unit == 0 || blocks == 0 || available > blocks {
        return Capacity::Contradictory;
    }
    match unit.checked_mul(blocks) {
        Some(bytes) => Capacity::Bytes(bytes),
        None => Capacity::Uncountable,
    }
}

/// A filesystem's capacity, as its `statvfs` facts give it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capacity {
    /// The facts cannot all be true of one filesystem: no unit, no blocks,
    /// more available than there are.
    Contradictory,
    /// More bytes than a `u64` counts: larger than any quota.
    Uncountable,
    /// This many bytes.
    Bytes(u64),
}

/// `HOST_WORKSPACE_OWNERSHIP`'s workspace half (M5d.4): the mounted root is
/// the owner the authority found -- never the workload's uid -- of the
/// workspace group, with exactly [`WORKSPACE_ROOT_MODE`]. The broker adds its
/// own membership of the group.
#[must_use]
pub fn workspace_ownership(facts: &WorkspaceFacts, bound: &WorkspaceBound) -> Verdict {
    let uid = facts.uid.value();
    if uid == bound.owner.value()
        && uid != u64::from(WORKLOAD_UID)
        && facts.gid.value() == u64::from(WORKSPACE_GROUP)
        && facts.mode.value() == u64::from(WORKSPACE_ROOT_MODE)
    {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

/// `HOST_WORKSPACE_CAPACITY` (M5d.4): the mounted workspace is its
/// filesystem's root, `nosuid` and `nodev`, and the filesystem's capacity is
/// exactly the one the authority measured and within the operator's quota.
/// Facts that contradict themselves prove nothing (`UNOBSERVABLE`); a
/// capacity too large to count is unbounded (`FAIL`).
#[must_use]
pub fn workspace_capacity(facts: &WorkspaceFacts, bound: &WorkspaceBound) -> Verdict {
    if !facts.filesystem_root || !facts.nosuid || !facts.nodev {
        return Verdict::Fail;
    }
    match facts.capacity() {
        Capacity::Contradictory => Verdict::Unobservable,
        Capacity::Uncountable => Verdict::Fail,
        Capacity::Bytes(capacity) => {
            if capacity == bound.capacity_bytes.value()
                && capacity_within_quota(capacity, bound.quota_bytes.get())
            {
                Verdict::Pass
            } else {
                Verdict::Fail
            }
        }
    }
}

wire_enum! {
    /// What the probe's `workspace` command prints.
    WorkspaceReportKind {
        /// The one kind.
        Report = "sandbox.workspace_report",
    }
}

wire_int! {
    /// The workspace report's schema version.
    WorkspaceReportVersion(u16), min = 1, max = 1
}

wire_struct! {
    /// The probe's `workspace` command's whole output (M5d.4): the mounted
    /// workspace's facts, read -- never written -- before every workload, so
    /// that a workspace changed since the environment was measured is seen
    /// before anything more runs in it. A closed schema, as the measurement's.
    WorkspaceReport: reject {
        /// Always `sandbox.workspace_report`.
        required kind: WorkspaceReportKind,
        /// Always 1.
        required version: WorkspaceReportVersion,
        /// The facts.
        required workspace: WorkspaceFacts,
    }
}

/// The most bytes a workspace report may be.
pub const MAX_WORKSPACE_REPORT_BYTES: usize = 4 * 1024;

impl WorkspaceReport {
    /// Decode a report: exactly one strict JSON value, within
    /// [`MAX_WORKSPACE_REPORT_BYTES`], of exactly this schema.
    ///
    /// # Errors
    ///
    /// Anything else.
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        super::decode_bytes(bytes, MAX_WORKSPACE_REPORT_BYTES)
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
                "a workspace report does not survive its own round trip",
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
    fn the_workspace_contracts_numbers_are_spelled_here_and_are_these() {
        // TX058 keeps every other crate naming these, never spelling them.
        assert_eq!(WORKSPACE_GROUP, 10_001);
        assert_eq!(WORKLOAD_UID, 10_001);
        assert_eq!(WORKSPACE_ROOT_MODE, 0o2770);
        assert_eq!(WORKLOAD_UMASK, 0o007);
    }

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
            version: ProbeReportVersion::new(3).unwrap(),
            checks,
            workspace: Some(facts()),
        };
        let bytes = report.to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            ProbeReport::decode_bytes(text.trim_end().as_bytes()).unwrap(),
            report
        );
        // Unknown field, trailing data, truncation, a duplicate, a host
        // invariant, a workspace fact twice or missing, an older version:
        // none is a report.
        let body = text.trim_end();
        let extra = body.replacen('{', "{\"note\":\"x\",", 1);
        let trailing = format!("{body}{body}");
        let truncated = &body[..body.len() / 2];
        let host = body.replacen("CONTAINER_UID_GID", "HOST_RUNNING", 1);
        let twice = body.replacen("CONTAINER_CAPABILITIES_EMPTY", "CONTAINER_UID_GID", 1);
        let fact_twice = body.replacen("\"gid\":\"10001\"", "\"gid\":\"10001\",\"gid\":\"0\"", 1);
        let fact_missing = body.replacen("\"nodev\":true,", "", 1);
        let older = body.replacen("\"version\":3", "\"version\":2", 1);
        assert_ne!(fact_twice, body);
        assert_ne!(fact_missing, body);
        assert_ne!(older, body);
        for bad in [
            extra.as_str(),
            trailing.as_str(),
            truncated,
            host.as_str(),
            twice.as_str(),
            fact_twice.as_str(),
            fact_missing.as_str(),
            older.as_str(),
        ] {
            assert!(ProbeReport::decode_bytes(bad.as_bytes()).is_err(), "{bad}");
        }
        // The workspace report is as closed.
        let workspace = WorkspaceReport {
            kind: WorkspaceReportKind::Report,
            version: WorkspaceReportVersion::new(1).unwrap(),
            workspace: facts(),
        };
        let text = String::from_utf8(workspace.to_bytes().unwrap()).unwrap();
        let body = text.trim_end();
        assert_eq!(
            WorkspaceReport::decode_bytes(body.as_bytes()).unwrap(),
            workspace
        );
        for bad in [
            body.replacen('{', "{\"note\":\"x\",", 1),
            body.replacen("\"files\":\"16384\",", "", 1),
            body.replacen("\"filesystem_root\":true", "\"filesystem_root\":1", 1),
            format!("{body}{body}"),
        ] {
            assert!(
                WorkspaceReport::decode_bytes(bad.as_bytes()).is_err(),
                "{bad}"
            );
        }
    }

    /// A 64 MiB filesystem the operator bounded at 64 MiB, as both sides
    /// see it: the authority's uid 1000 owns its root.
    fn facts() -> WorkspaceFacts {
        WorkspaceFacts {
            device: KernelNumber::from_u64(64),
            inode: KernelNumber::from_u64(1),
            uid: KernelNumber::from_u64(1000),
            gid: KernelNumber::from_u64(u64::from(WORKSPACE_GROUP)),
            mode: KernelNumber::from_u64(u64::from(WORKSPACE_ROOT_MODE)),
            filesystem_root: true,
            nosuid: true,
            nodev: true,
            block_size: KernelNumber::from_u64(4096),
            blocks: KernelNumber::from_u64(16_384),
            blocks_available: KernelNumber::from_u64(16_000),
            files: KernelNumber::from_u64(16_384),
        }
    }

    fn bound(quota: u64, capacity: u64, owner: u64) -> WorkspaceBound {
        WorkspaceBound {
            quota_bytes: WorkspaceQuota::new(quota).unwrap(),
            capacity_bytes: KernelNumber::from_u64(capacity),
            owner: KernelNumber::from_u64(owner),
        }
    }

    #[test]
    fn a_capacity_is_within_its_quota_or_contradicts_it() {
        let mib = 1u64 << 20;
        // Exactly the quota, and down to a quarter below it.
        assert!(capacity_within_quota(64 * mib, 64 * mib));
        assert!(capacity_within_quota(48 * mib, 64 * mib));
        // A byte over is unbounded against the declaration; more than a
        // quarter under does not describe the filesystem.
        assert!(!capacity_within_quota(64 * mib + 1, 64 * mib));
        assert!(!capacity_within_quota(48 * mib - 1, 64 * mib));
        assert!(!capacity_within_quota(u64::MAX, WorkspaceQuota::MAX));
        assert!(capacity_within_quota(
            WorkspaceQuota::MAX,
            WorkspaceQuota::MAX
        ));
        // The quota's own range.
        assert!(WorkspaceQuota::new((16 << 20) - 1).is_none());
        assert!(WorkspaceQuota::new((16 << 40) + 1).is_none());
        assert!(WorkspaceQuota::new(5 << 30).is_some());
    }

    #[test]
    fn the_workspace_capacity_is_the_authoritys_measure_within_the_quota() {
        let mib = 1u64 << 20;
        let ok = bound(64 * mib, 64 * mib, 1000);
        assert_eq!(facts().capacity(), Capacity::Bytes(64 * mib));
        assert_eq!(workspace_capacity(&facts(), &ok), Verdict::Pass);
        // The two vantages disagree: another filesystem is mounted.
        assert_eq!(
            workspace_capacity(&facts(), &bound(64 * mib, 63 * mib, 1000)),
            Verdict::Fail
        );
        // A quota the capacity is above: unbounded against it.
        assert_eq!(
            workspace_capacity(&facts(), &bound(32 * mib, 64 * mib, 1000)),
            Verdict::Fail
        );
        // A quota far above the capacity: the declaration describes another.
        assert_eq!(
            workspace_capacity(&facts(), &bound(128 * mib, 64 * mib, 1000)),
            Verdict::Fail
        );
        // Not the filesystem's root, not nosuid, not nodev: refused whatever
        // the numbers say.
        for weaken in [
            |f: &mut WorkspaceFacts| f.filesystem_root = false,
            |f: &mut WorkspaceFacts| f.nosuid = false,
            |f: &mut WorkspaceFacts| f.nodev = false,
        ] {
            let mut facts = facts();
            weaken(&mut facts);
            assert_eq!(workspace_capacity(&facts, &ok), Verdict::Fail);
        }
        // Facts that contradict themselves prove nothing.
        for (unit, blocks, available) in [(0, 16_384, 0), (4096, 0, 0), (4096, 10, 11)] {
            let mut facts = facts();
            facts.block_size = KernelNumber::from_u64(unit);
            facts.blocks = KernelNumber::from_u64(blocks);
            facts.blocks_available = KernelNumber::from_u64(available);
            assert_eq!(facts.capacity(), Capacity::Contradictory);
            assert_eq!(workspace_capacity(&facts, &ok), Verdict::Unobservable);
        }
        // A capacity that overflows a u64 is larger than any quota.
        let mut huge = facts();
        huge.block_size = KernelNumber::from_u64(1 << 32);
        huge.blocks = KernelNumber::from_u64(1 << 32);
        huge.blocks_available = KernelNumber::from_u64(0);
        assert_eq!(huge.capacity(), Capacity::Uncountable);
        assert_eq!(
            workspace_capacity(&huge, &bound(WorkspaceQuota::MAX, u64::MAX, 1000)),
            Verdict::Fail
        );
    }

    #[test]
    fn the_workspace_root_is_the_groups_and_nobody_elses() {
        let ok = bound(64 << 20, 64 << 20, 1000);
        assert_eq!(workspace_ownership(&facts(), &ok), Verdict::Pass);
        // Root may own it too, when the authority found root.
        let mut by_root = facts();
        by_root.uid = KernelNumber::from_u64(0);
        assert_eq!(
            workspace_ownership(&by_root, &bound(64 << 20, 64 << 20, 0)),
            Verdict::Pass
        );
        // Another owner than the authority found; the workload's uid even
        // when the authority found it; another group; any other mode.
        let mut other = facts();
        other.uid = KernelNumber::from_u64(1001);
        assert_eq!(workspace_ownership(&other, &ok), Verdict::Fail);
        let mut workload = facts();
        workload.uid = KernelNumber::from_u64(u64::from(WORKLOAD_UID));
        assert_eq!(
            workspace_ownership(&workload, &bound(64 << 20, 64 << 20, 10_001)),
            Verdict::Fail
        );
        let mut group = facts();
        group.gid = KernelNumber::from_u64(1000);
        assert_eq!(workspace_ownership(&group, &ok), Verdict::Fail);
        for mode in [0o770, 0o2775, 0o2777, 0o3770, 0o6770, 0o2700, 0o2750, 0o777] {
            let mut facts = facts();
            facts.mode = KernelNumber::from_u64(mode);
            assert_eq!(workspace_ownership(&facts, &ok), Verdict::Fail, "{mode:o}");
        }
    }

    #[test]
    fn each_topology_requires_its_own_invariants() {
        let bounded = WorkspaceContract::Bounded;
        let proxy = required_invariants(NetworkTopology::ProxyOnly, bounded);
        let none = required_invariants(NetworkTopology::NoNetwork, bounded);
        assert_eq!(proxy, SandboxInvariant::ALL.to_vec(), "PROXY_ONLY: all");
        for proxy_only in [
            SandboxInvariant::HostRelayDigest,
            SandboxInvariant::ContainerProxyReachable,
        ] {
            assert!(proxy.contains(&proxy_only) && !none.contains(&proxy_only));
        }
        // The workspace contract binds every bounded environment, whatever
        // its topology; only the evidence harness's unverified workspace is
        // free of it.
        let evidence = WorkspaceContract::UnverifiedEvidence;
        let unverified = required_invariants(NetworkTopology::NoNetwork, evidence);
        let unverified_proxy = required_invariants(NetworkTopology::ProxyOnly, evidence);
        for contract in SandboxInvariant::ALL
            .iter()
            .filter(|i| i.workspace_contract())
        {
            assert!(proxy.contains(contract) && none.contains(contract));
            assert!(!unverified.contains(contract) && !unverified_proxy.contains(contract));
        }
        assert_eq!(unverified.len() + 3, none.len());
        assert_eq!(unverified_proxy.len() + 3, proxy.len());
        assert_eq!(
            SandboxInvariant::HostWorkspaceIdentity.vantage(),
            Vantage::Host
        );
        // The workspace's identity binds every environment, verified or not.
        assert!(unverified.contains(&SandboxInvariant::HostWorkspaceIdentity));
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
