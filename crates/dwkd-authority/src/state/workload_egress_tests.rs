//! The decision's pure parts (F-17, ADR-0061, Proposed). The decision over
//! a real store -- novelty, exposure, recording, settlement, recovery and
//! the tripwire -- is held by `workload_route_tests.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test assertions"
)]

use dwk_proto::brokerp::egress::{
    EgressAddressUses, EgressCount, EgressCountList, EgressCountValue, EgressCounters,
    EgressDisposition, WorkloadEgress, WorkloadEgressReport, WorkloadEgressTargetReport,
    WorkloadEgressTargetReports,
};
use dwk_proto::wire::scalar::ByteCount;

use super::{Verdict, meet, required, within_counters};

fn v(allowed: bool, cap: Option<u64>, rule: &str) -> Verdict {
    Verdict {
        allowed,
        cap,
        rule: rule.to_owned(),
    }
}

#[test]
fn a_cell_allows_a_piece_only_where_every_part_allows_it_at_the_tightest_bound() {
    // Two parts (two taints, say), three pieces.
    let first = vec![
        v(true, Some(100), "allow-a"),
        v(true, None, "allow-a"),
        v(false, None, "deny-b"),
    ];
    let second = vec![
        v(true, Some(50), "allow-c"),
        v(false, None, "approve-d"),
        v(true, None, "allow-c"),
    ];
    let (cell, rules) = meet(&[&first, &second], 3).unwrap();
    assert!(cell.allowed.get(0));
    assert!(!cell.allowed.get(1));
    assert!(!cell.allowed.get(2));
    // The bound is the tightest of every allowed piece's parts.
    assert_eq!(
        cell.max_tunnel_download_bytes
            .map(dwk_proto::brokerp::egress::EgressByteBudget::get),
        Some(50)
    );
    // The deciding rule is the first part that refused, else the first.
    assert_eq!(rules, ["allow-a", "approve-d", "deny-b"]);
    // One part is itself.
    let (alone, _) = meet(&[&first], 3).unwrap();
    assert!(alone.allowed.get(0) && alone.allowed.get(1) && !alone.allowed.get(2));
    // A refused piece's bound does not tighten the cell.
    let third = vec![
        v(false, Some(1), "deny"),
        v(true, None, "a"),
        v(true, None, "a"),
    ];
    let (loose, _) = meet(&[&third], 3).unwrap();
    assert_eq!(loose.max_tunnel_download_bytes, None);
}

#[test]
fn a_tunnel_requires_its_destination_unconstrained() {
    // So a grant that carries a constraint does not cover it: the capability
    // gate itself keeps F-19's rule, whatever derived the ceiling.
    let tunnel = required("api.example.com", 443).unwrap();
    assert_eq!(
        tunnel.to_canonical_string(),
        "network.https:api.example.com:443"
    );
    for (grant, covers) in [
        ("network.https:api.example.com", true),
        ("network.https:api.example.com:443", true),
        ("network.https:*.example.com", true),
        ("network.https:api.example.com?methods=GET", false),
        ("network.https:api.example.com:443?max_requests=5", false),
        ("network.https:api.example.com:8443", false),
        ("network.http:api.example.com", false),
    ] {
        let grant = crate::policy::testing::syntactic_capability(grant);
        assert_eq!(grant.contains(&tunnel), covers, "{grant}");
    }
}

fn counts(items: &[(EgressDisposition, u64)]) -> EgressCountList {
    EgressCountList::new(
        items
            .iter()
            .map(|(disposition, n)| EgressCount {
                disposition: *disposition,
                count: EgressCountValue::new(*n).unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

/// One workload's report: one destination, reached, `closed` tunnels
/// closed, `bytes` each way; `unattributed` CONNECTs that named nothing.
fn report(closed: u64, bytes: u64, unattributed: u64) -> WorkloadEgressReport {
    let egress = WorkloadEgress::uniform(&[("api.example.com", 443)], true, false).unwrap();
    let report = WorkloadEgressReport {
        exposed: true,
        targets: WorkloadEgressTargetReports::new(vec![WorkloadEgressTargetReport {
            reached: true,
            dispositions: counts(&[(EgressDisposition::Closed, closed)]),
            bytes_upstream: ByteCount::new(bytes).unwrap(),
            bytes_downstream: ByteCount::new(bytes).unwrap(),
            addresses: EgressAddressUses::new(Vec::new()).unwrap(),
            addresses_omitted: EgressCountValue::new(0).unwrap(),
        }])
        .unwrap(),
        unattributed: counts(&[(EgressDisposition::TargetNotGranted, unattributed)]),
    };
    assert!(report.consistent_with(&egress));
    report
}

fn counters(items: &[(EgressDisposition, u64)], up: u64, down: u64) -> EgressCounters {
    EgressCounters {
        dispositions: counts(items),
        bytes_upstream: ByteCount::new(up).unwrap(),
        bytes_downstream: ByteCount::new(down).unwrap(),
    }
}

/// ADR-0061's A8: what an environment's workloads reported fits within what
/// its proxy counted -- summed over every workload -- and a report claiming
/// more than the proxy saw does not.
#[test]
fn the_workloads_reports_reconcile_with_the_proxys_counters() {
    use EgressDisposition::{Closed, TargetNotGranted};
    let two = [report(2, 100, 1), report(1, 50, 0)];
    // The proxy counted every workload's, and its own probe's question.
    let proxy = counters(&[(Closed, 3), (TargetNotGranted, 2)], 150, 150);
    assert!(within_counters(&two, &proxy));
    assert!(within_counters(&[], &proxy));
    // One tunnel more than the proxy closed.
    assert!(!within_counters(
        &two,
        &counters(&[(Closed, 2), (TargetNotGranted, 2)], 150, 150)
    ));
    // A disposition the proxy never counted.
    assert!(!within_counters(&two, &counters(&[(Closed, 3)], 150, 150)));
    // A byte more, either way.
    assert!(!within_counters(
        &two,
        &counters(&[(Closed, 3), (TargetNotGranted, 2)], 149, 150)
    ));
    assert!(!within_counters(
        &two,
        &counters(&[(Closed, 3), (TargetNotGranted, 2)], 150, 149)
    ));
}
