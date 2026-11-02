//! `oci.rs`'s own tests (M5d.4): the workspace's three host-judged
//! invariants from the probe's facts against the authority's bound, and what
//! a clean measurement requires of each workspace contract -- what a
//! preparation answers for an environment it did not keep, and what proves a
//! container gone.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use dwk_proto::brokerp::sandbox::{
    ContainerRef, EnvironmentProfile, ImageId, Milliseconds, NetworkTopology,
    SandboxInvariant as I, StoreInstance, Verdict, WORKSPACE_ROOT_MODE, WorkspaceBound,
    WorkspaceContract, WorkspaceFacts, WorkspaceQuota, required_invariants,
};
use dwk_proto::brokerp::{
    BrokerRefusal, ContainerState, EnvironmentSpec, KernelNumber, OwnedEnvironment,
};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use crate::process::run::{self, Completed, Ended};

use super::super::environment::{EnvFailure, EnvHandle, Measured, Prepared};
use super::{accounted, clean, contract, kept_or_taken_down, recorded_or_gone, workspace_checks};

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

#[test]
fn an_environment_not_kept_is_refused_only_once_its_teardown_proved_it_gone() {
    let spec = spec(true);
    let handle = || EnvHandle {
        environment: spec.environment_id.clone(),
        container: ContainerRef::new("e".repeat(64)).unwrap(),
    };
    let measured = |verdict: Verdict| Measured {
        state: ContainerState::Running,
        checks: Some(
            I::ALL
                .iter()
                .map(|i| {
                    let failed = *i == I::HostProbeDigest;
                    (*i, if failed { verdict } else { Verdict::Pass })
                })
                .collect(),
        ),
        runtime_version: None,
        measure_ms: Milliseconds::of(std::time::Duration::ZERO),
    };
    // Clean: kept, and nothing is taken down.
    let kept = kept_or_taken_down(handle(), measured(Verdict::Pass), &spec, || {
        unreachable!("a clean environment is kept")
    });
    assert!(
        matches!(kept, Ok(Prepared { retained: true, .. })),
        "{kept:?}"
    );
    // Not clean, and proved gone: not kept, with what was found.
    for verdict in [Verdict::Fail, Verdict::Unobservable] {
        let gone = kept_or_taken_down(handle(), measured(verdict), &spec, || Ok(()));
        assert!(
            matches!(
                gone,
                Ok(Prepared {
                    retained: false,
                    measured: Some(_),
                    ..
                })
            ),
            "{verdict:?}: {gone:?}"
        );
    }
    // Not clean, and its teardown did not finish: one of its steps refused
    // -- it may have run after others acted, or left the rest standing -- or
    // acted unconfirmed. Nothing proves it gone, so nothing may say so: a
    // refusal would tell the authority none of it remains (`REFUSED`).
    for failed in [
        EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable),
        EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed),
        EnvFailure::Refused(BrokerRefusal::EnvironmentAmbiguous),
        EnvFailure::Refused(BrokerRefusal::ForeignEnvironment),
        EnvFailure::Refused(BrokerRefusal::DigestMismatch),
        EnvFailure::Unconfirmed,
    ] {
        let answer = kept_or_taken_down(handle(), measured(Verdict::Fail), &spec, || Err(failed));
        assert!(
            matches!(answer, Err(EnvFailure::Unconfirmed)),
            "{failed:?}: {answer:?}"
        );
    }
}

/// The runtime's client, having run to `ended` and printed `stdout`.
fn completed(ended: Ended, stdout: &[u8]) -> Completed {
    Completed {
        ended,
        stdout: stdout.to_vec(),
        stdout_cut: false,
        stdout_observed: u64::try_from(stdout.len()).unwrap(),
        stderr: Vec::new(),
        stderr_observed: 0,
        redactions: 0,
    }
}

#[test]
fn a_container_is_gone_only_when_a_listing_the_runtime_answered_says_so() {
    let container = ContainerRef::new("e".repeat(64)).unwrap();
    let unavailable = EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable);
    let malformed = EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed);
    // What the runtime's client answers an inspection of a container the
    // runtime does not hold -- and, byte for byte and exit status alike, of
    // any container when it could not reach the runtime (Docker's CLI
    // 29.9.2: `[]`, exit 1, the reason on stderr only).
    let empty = || Ok(completed(Ended::Exited(1), b"[]\n"));
    let gone = |listing: Result<bool, EnvFailure>| {
        recorded_or_gone(&container, empty(), || listing).map(|record| record.is_some())
    };
    // The runtime's own listing does not hold it: gone.
    assert_eq!(gone(Ok(false)), Ok(false));
    // The listing still holds it, or could not be had: nothing is gone, and
    // nothing says so.
    assert_eq!(gone(Ok(true)), Err(unavailable));
    assert_eq!(gone(Err(unavailable)), Err(unavailable));
    assert_eq!(gone(Err(malformed)), Err(malformed));
    assert_eq!(
        gone(Err(EnvFailure::Unconfirmed)),
        Err(EnvFailure::Unconfirmed)
    );
    // A record is the runtime's own word: no listing is asked for.
    let one = format!(r#"[{{"Id":"{}"}}]"#, container.as_str());
    let found = recorded_or_gone(
        &container,
        Ok(completed(Ended::Exited(0), one.as_bytes())),
        || unreachable!("a record needs no listing"),
    );
    assert_eq!(found.map(|record| record.is_some()), Ok(true));
    // Any other answer proves nothing either way, and asks nothing more.
    let other = format!(r#"[{{"Id":"{}"}}]"#, "f".repeat(64));
    for (inspected, refused) in [
        (Ok(completed(Ended::Exited(0), b"[]\n")), malformed),
        (Ok(completed(Ended::Exited(0), other.as_bytes())), malformed),
        (Ok(completed(Ended::Exited(1), b"")), unavailable),
        (Ok(completed(Ended::Signaled(9), b"")), unavailable),
        (Err(run::Failure::Unconfirmed), unavailable),
        (
            Err(run::Failure::Refused(BrokerRefusal::DigestMismatch)),
            EnvFailure::Refused(BrokerRefusal::DigestMismatch),
        ),
    ] {
        let answer = recorded_or_gone(&container, inspected, || unreachable!("no listing"));
        assert_eq!(answer.map(|record| record.is_some()), Err(refused));
    }
}

#[test]
fn a_listing_is_complete_only_when_each_container_it_named_was_inspected_or_proved_gone() {
    let (a, b) = (
        ContainerRef::new("a".repeat(64)).unwrap(),
        ContainerRef::new("b".repeat(64)).unwrap(),
    );
    let ids = [a.clone(), b.clone()];
    let owned = |container: &ContainerRef| OwnedEnvironment {
        container: container.clone(),
        state: ContainerState::Running,
        image: None,
        environment_id: None,
        run_id: None,
        labels_exact: false,
        role: None,
    };
    let none = || -> Option<Vec<ContainerRef>> { unreachable!("nothing to account for") };
    // Each inspected: complete, however the client ended, and nothing more
    // is asked.
    for ended in [Ended::Exited(0), Ended::Exited(1)] {
        assert!(accounted(&ids, &[owned(&a), owned(&b)], ended, none));
    }
    // What the client answers when it could not reach the runtime: nothing
    // inspected, and a failure. Never a store with no environment in it.
    assert!(!accounted(&ids, &[], Ended::Exited(1), || None));
    // Short and failed, as for a container removed since the listing: gone
    // only when the runtime's own second listing no longer holds it.
    assert!(accounted(&ids, &[owned(&a)], Ended::Exited(1), || Some(
        vec![a.clone()]
    )));
    assert!(accounted(&ids, &[], Ended::Exited(1), || Some(Vec::new())));
    assert!(!accounted(&ids, &[], Ended::Exited(1), || Some(vec![
        b.clone()
    ])));
    assert!(!accounted(&ids, &[owned(&a)], Ended::Exited(1), || {
        Some(vec![a.clone(), b.clone()])
    }));
    assert!(!accounted(&ids, &[owned(&a)], Ended::Exited(1), || None));
    // Short, yet answered as whole: nothing explains it.
    assert!(!accounted(&ids, &[owned(&a)], Ended::Exited(0), none));
}
