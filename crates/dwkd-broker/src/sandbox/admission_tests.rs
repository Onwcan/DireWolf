//! What the supervisor builds at all (M5d.4): an environment without the
//! authority's workspace bound -- the evidence harness's unverified scratch
//! directory -- only where the operator acknowledged it, whatever its
//! topology; and the evidence topology only where acknowledged, as before.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::path::PathBuf;
use std::sync::Arc;

use dwk_proto::brokerp::sandbox::{
    EnvironmentProfile, ImageId, NetworkTopology, StoreInstance, WorkspaceBound, WorkspaceQuota,
};
use dwk_proto::brokerp::{BrokerGeneration, BrokerRefusal, EnvironmentSpec, KernelNumber};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use super::{Sandbox, SandboxFiles};

fn sandbox(evidence_topology: bool, unverified_workspace: bool) -> Sandbox {
    Sandbox::new(
        PathBuf::from("/nonexistent/dwkd-broker"),
        0,
        SandboxFiles {
            seccomp: PathBuf::from("/nonexistent/seccomp.json"),
            client_config: PathBuf::from("/nonexistent/client"),
        },
        (
            evidence_topology,
            unverified_workspace,
            BrokerGeneration::new("a".repeat(32)).unwrap(),
        ),
        Arc::new(crate::egress::proxy::Proxies::without_root(
            Arc::new(crate::egress::resolve::SystemResolver),
            crate::egress::Limits::PRODUCTION,
        )),
    )
}

fn spec(network: NetworkTopology, bounded: bool) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        run_id: RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        store: StoreInstance::new("0a1b").unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network,
        image: ImageId::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
        probe_sha256: ContentDigest::new("d".repeat(64)).unwrap(),
        workspace_path: HostPath::new("/srv/ws").unwrap(),
        workspace: (64, 1),
        workspace_bound: bounded.then(|| WorkspaceBound {
            quota_bytes: WorkspaceQuota::new(64 << 20).unwrap(),
            capacity_bytes: KernelNumber::from_u64(64 << 20),
            owner: KernelNumber::from_u64(1000),
        }),
        relay_sha256: None,
        egress: None,
    }
}

#[test]
fn an_unbounded_workspace_is_built_only_where_its_operator_acknowledged_it() {
    let production = sandbox(false, false);
    let evidence = sandbox(true, false);
    let unverified = sandbox(true, true);
    let unverified_production = sandbox(false, true);
    let proxy = NetworkTopology::ProxyOnly;
    let none = NetworkTopology::NoNetwork;
    // A bounded workspace: the topology alone decides, as before.
    assert_eq!(production.admissible(&spec(proxy, true)), Ok(()));
    assert_eq!(
        production.admissible(&spec(none, true)),
        Err(BrokerRefusal::TopologyUnavailable)
    );
    assert_eq!(evidence.admissible(&spec(none, true)), Ok(()));
    // No bound: refused unless acknowledged -- the evidence topology's
    // acknowledgement is not this one.
    for (broker, network) in [(&production, proxy), (&evidence, proxy), (&evidence, none)] {
        assert_eq!(
            broker.admissible(&spec(network, false)),
            Err(BrokerRefusal::WorkspaceUnverified),
            "{network:?}"
        );
    }
    assert_eq!(unverified.admissible(&spec(none, false)), Ok(()));
    assert_eq!(unverified.admissible(&spec(proxy, false)), Ok(()));
    assert_eq!(
        unverified_production.admissible(&spec(proxy, false)),
        Ok(())
    );
    // The topology is still judged first.
    assert_eq!(
        unverified_production.admissible(&spec(none, false)),
        Err(BrokerRefusal::TopologyUnavailable)
    );
}
