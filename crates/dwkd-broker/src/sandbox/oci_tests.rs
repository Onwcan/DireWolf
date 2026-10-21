//! `oci.rs`'s own tests (M5d.4): the workspace's three host-judged
//! invariants from the probe's facts against the authority's bound, and what
//! a clean measurement requires of each workspace contract.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use dwk_proto::brokerp::sandbox::{
    EnvironmentProfile, ImageId, NetworkTopology, SandboxInvariant as I, StoreInstance, Verdict,
    WORKSPACE_ROOT_MODE, WorkspaceBound, WorkspaceContract, WorkspaceFacts, WorkspaceQuota,
    required_invariants,
};
use dwk_proto::brokerp::{EnvironmentSpec, KernelNumber};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use super::{clean, contract, workspace_checks};

const MIB: u64 = 1 << 20;

/// An environment whose workspace is `(64, 1)` and, when `bound`, the
/// authority's 64 MiB filesystem owned by its uid 1000.
fn spec(bound: bool) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        run_id: RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        store: StoreInstance::new("0a1b").unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network: NetworkTopology::NoNetwork,
        image: ImageId::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
        probe_sha256: ContentDigest::new("d".repeat(64)).unwrap(),
        workspace_path: HostPath::new("/srv/ws").unwrap(),
        workspace: (64, 1),
        workspace_bound: bound.then(|| WorkspaceBound {
            quota_bytes: WorkspaceQuota::new(64 * MIB).unwrap(),
            capacity_bytes: KernelNumber::from_u64(64 * MIB),
            owner: KernelNumber::from_u64(1000),
        }),
        relay_sha256: None,
        egress: None,
    }
}

/// What the probe would find mounted for `spec(true)`.
fn facts() -> WorkspaceFacts {
    let n = KernelNumber::from_u64;
    WorkspaceFacts {
        device: n(64),
        inode: n(1),
        uid: n(1000),
        gid: n(10_001),
        mode: n(u64::from(WORKSPACE_ROOT_MODE)),
        filesystem_root: true,
        nosuid: true,
        nodev: true,
        block_size: n(4096),
        blocks: n(16_384),
        blocks_available: n(16_000),
        files: n(16_384),
    }
}

fn verdicts(checks: [(I, Verdict); 3]) -> [Verdict; 3] {
    assert_eq!(
        checks.map(|(i, _)| i),
        [
            I::HostWorkspaceIdentity,
            I::HostWorkspaceOwnership,
            I::HostWorkspaceCapacity
        ]
    );
    checks.map(|(_, v)| v)
}

#[test]
fn a_bounded_workspace_passes_only_as_the_authority_found_it_with_the_broker_in_its_group() {
    let (pass, fail, unobservable) = (Verdict::Pass, Verdict::Fail, Verdict::Unobservable);
    let bounded = spec(true);
    assert_eq!(
        verdicts(workspace_checks(Some(&facts()), &bounded, Some(true))),
        [pass, pass, pass]
    );
    // The broker outside the group writes nothing there; unable to say, it
    // proves nothing.
    assert_eq!(
        verdicts(workspace_checks(Some(&facts()), &bounded, Some(false))),
        [pass, fail, pass]
    );
    assert_eq!(
        verdicts(workspace_checks(Some(&facts()), &bounded, None)),
        [pass, unobservable, pass]
    );
    // Another directory mounted: its identity, and its capacity, are not
    // the authority's.
    let mut other = facts();
    other.inode = KernelNumber::from_u64(2);
    assert_eq!(
        verdicts(workspace_checks(Some(&other), &bounded, Some(true))),
        [fail, pass, pass]
    );
    let mut bigger = facts();
    bigger.blocks = KernelNumber::from_u64(32_768);
    assert_eq!(
        verdicts(workspace_checks(Some(&bigger), &bounded, Some(true))),
        [pass, pass, fail]
    );
    // A root the workload could open to anyone.
    let mut opened = facts();
    opened.mode = KernelNumber::from_u64(0o2777);
    assert_eq!(
        verdicts(workspace_checks(Some(&opened), &bounded, Some(true))),
        [pass, fail, pass]
    );
    // Nothing believable from the probe: nothing is concluded.
    assert_eq!(
        verdicts(workspace_checks(None, &bounded, Some(true))),
        [unobservable, unobservable, unobservable]
    );
}

#[test]
fn an_unverified_workspace_is_judged_for_its_identity_alone_and_said_so() {
    let unverified = spec(false);
    assert_eq!(contract(&unverified), WorkspaceContract::UnverifiedEvidence);
    assert_eq!(contract(&spec(true)), WorkspaceContract::Bounded);
    // The evidence harness's scratch directory: a plain directory on the
    // host's filesystem, world-writable, nothing like the contract.
    let mut scratch = facts();
    scratch.gid = KernelNumber::from_u64(1000);
    scratch.mode = KernelNumber::from_u64(0o777);
    scratch.filesystem_root = false;
    scratch.blocks = KernelNumber::from_u64(263_940_717);
    assert_eq!(
        verdicts(workspace_checks(Some(&scratch), &unverified, Some(false))),
        [Verdict::Pass, Verdict::Unobservable, Verdict::Unobservable]
    );
    // Its identity still binds it.
    scratch.device = KernelNumber::from_u64(65);
    assert_eq!(
        verdicts(workspace_checks(Some(&scratch), &unverified, Some(false)))[0],
        Verdict::Fail
    );
}

#[test]
fn a_clean_measurement_is_every_invariant_its_contract_requires() {
    let all =
        |verdict: Verdict| -> Vec<(I, Verdict)> { I::ALL.iter().map(|i| (*i, verdict)).collect() };
    let bounded = spec(true);
    let unverified = spec(false);
    assert!(clean(&all(Verdict::Pass), &bounded));
    assert!(clean(&all(Verdict::Pass), &unverified));
    for invariant in [
        I::HostWorkspaceOwnership,
        I::HostWorkspaceCapacity,
        I::ContainerWorkspaceGroupInherited,
    ] {
        let mut checks = all(Verdict::Pass);
        for check in &mut checks {
            if check.0 == invariant {
                check.1 = Verdict::Unobservable;
            }
        }
        // A bounded workspace needs it; the evidence harness's does not.
        assert!(!clean(&checks, &bounded), "{invariant:?}");
        assert!(clean(&checks, &unverified), "{invariant:?}");
    }
    // The workspace's identity binds both.
    let mut checks = all(Verdict::Pass);
    for check in &mut checks {
        if check.0 == I::HostWorkspaceIdentity {
            check.1 = Verdict::Fail;
        }
    }
    assert!(!clean(&checks, &bounded) && !clean(&checks, &unverified));
    assert_eq!(
        required_invariants(NetworkTopology::NoNetwork, WorkspaceContract::Bounded).len(),
        required_invariants(
            NetworkTopology::NoNetwork,
            WorkspaceContract::UnverifiedEvidence
        )
        .len()
            + 3
    );
}
