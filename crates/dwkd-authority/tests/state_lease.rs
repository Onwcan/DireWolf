//! Leases and epoch fencing, against real `kernel.db` files.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;

mod state_support;

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::wire::scalar::{RefusalReason, RefusedOperation};
use dwkd_authority::state::{AuditEvent, AuthorityError, MAX_EPOCH, Reply};
use proptest::prelude::*;
use state_support::{
    Harness, acquire_msg, audit_records, epoch, heartbeat_msg, raw, release_lease_msg, session,
    text,
};

const TTL: u64 = dwkd_authority::state::DEFAULT_LEASE_TTL_MS;

#[test]
fn the_first_acquire_issues_epoch_one_and_a_second_holder_is_refused() {
    let mut h = Harness::new("first");
    let s = session(1);
    let a = h.connect(1000);
    assert_eq!(h.lease(&a, &s).get(), 1);
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
}

#[test]
fn the_same_subject_on_a_new_connection_does_not_inherit_the_live_lease() {
    // A retrying or restarted process under the same uid is not evidence that
    // it is the same single writer. It waits.
    let mut h = Harness::new("same-subject");
    let s = session(1);
    let first = h.connect(1000);
    let e = h.lease(&first, &s);
    let second = h.connect(1000);
    assert_eq!(first.subject(), second.subject());
    assert_ne!(first.holder(), second.holder());
    assert_eq!(
        h.authority().acquire_lease(&second, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    // And it cannot act with the first connection's epoch either.
    assert_eq!(
        h.authority().heartbeat(&second, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
}

#[test]
fn the_holder_asking_again_gets_a_fresh_epoch_that_fences_its_old_one() {
    let mut h = Harness::new("reissue");
    let s = session(1);
    let a = h.connect(1000);
    let first = h.lease(&a, &s);
    let second = h.lease(&a, &s);
    assert!(second > first);
    assert_eq!(
        h.authority().heartbeat(&a, &s, first).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch),
        "its own old epoch is fenced"
    );
    assert_eq!(
        h.authority().heartbeat(&a, &s, second).unwrap(),
        Reply::Done(())
    );
}

#[test]
fn every_fence_failure_is_the_same_stale_epoch_and_reveals_nothing() {
    let mut h = Harness::new("fence");
    let s = session(1);
    let holder = h.connect(1000);
    let current = h.lease(&holder, &s);
    let stranger = h.connect(2000);
    let mut refusals = Vec::new();
    // Wrong holder, right epoch.
    refusals.push(h.authority().heartbeat(&stranger, &s, current).unwrap());
    // Right holder, old epoch (and a future one).
    refusals.push(
        h.authority()
            .heartbeat(&holder, &s, epoch(current.get() + 1))
            .unwrap(),
    );
    // No lease at all for this session.
    refusals.push(
        h.authority()
            .heartbeat(&holder, &session(99), current)
            .unwrap(),
    );
    // Expired.
    h.clock.advance(TTL + 1);
    refusals.push(h.authority().heartbeat(&holder, &s, current).unwrap());
    for refusal in refusals {
        assert_eq!(
            refusal,
            Reply::Refused(RefusalReason::StaleEpoch),
            "one answer for every way a fence fails"
        );
    }
    // The refusal is a closed pair with no payload: there is nowhere to put
    // the current epoch, and the audit record does not carry it either.
    for record in audit_records(&h.state(), AuditEvent::LeaseRefused.as_str()) {
        assert!(
            record.get("epoch").is_none(),
            "a refusal record names no current epoch"
        );
    }
}

#[test]
fn a_heartbeat_extends_by_one_ttl_and_an_expired_lease_cannot_be_renewed() {
    let mut h = Harness::new("heartbeat");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    h.clock.advance(TTL - 1);
    assert_eq!(h.authority().heartbeat(&a, &s, e).unwrap(), Reply::Done(()));
    h.clock.advance(TTL - 1);
    assert_eq!(
        h.authority().heartbeat(&a, &s, e).unwrap(),
        Reply::Done(()),
        "the first heartbeat moved the expiry"
    );
    h.clock.advance(TTL);
    assert_eq!(
        h.authority().heartbeat(&a, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch),
        "exactly TTL after the last renewal it has expired"
    );
}

#[test]
fn an_expired_lease_goes_to_the_next_acquirer_at_a_new_epoch() {
    let mut h = Harness::new("expiry");
    let s = session(1);
    let a = h.connect(1000);
    let old = h.lease(&a, &s);
    let b = h.connect(2000);
    h.clock.advance(TTL);
    let new = h.lease(&b, &s);
    assert!(new > old);
    assert_eq!(
        h.authority().heartbeat(&a, &s, old).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch),
        "the zombie is fenced"
    );
}

#[test]
fn a_backwards_clock_jump_prolongs_a_lease_but_never_makes_two_holders() {
    let mut h = Harness::new("clock-back");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    h.clock.set(state_support::START_MS - 3_600_000);
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "still one holder"
    );
    assert_eq!(h.authority().heartbeat(&a, &s, e).unwrap(), Reply::Done(()));
}

#[test]
fn release_surrenders_the_lease_and_a_retry_by_the_same_holder_is_acknowledged() {
    let mut h = Harness::new("release");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    assert_eq!(
        h.authority().release_lease(&a, &s, e).unwrap(),
        Reply::Done(())
    );
    assert_eq!(
        h.authority().release_lease(&a, &s, e).unwrap(),
        Reply::Done(()),
        "a retry of a release that happened is indistinguishable from success"
    );
    let b = h.connect(2000);
    assert_eq!(
        h.authority().release_lease(&b, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch),
        "another connection's release of the same epoch is not its to acknowledge"
    );
    let next = h.lease(&b, &s);
    assert!(next > e, "released: the next tenure is a new epoch");
    assert_eq!(
        h.authority().heartbeat(&a, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
}

#[test]
fn a_restart_invalidates_every_live_holder_and_never_resets_an_epoch() {
    let mut h = Harness::new("restart");
    let s = session(1);
    let a = h.connect(1000);
    let before = h.lease(&a, &s);
    let report = h.restart().clone();
    assert_eq!(report.leases_invalidated, 1);

    // The old connection belonged to a process that no longer exists.
    assert_eq!(
        h.authority().heartbeat(&a, &s, before).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // Its holder cannot come back through a new incarnation either: every
    // holder minted now is from incarnation 2.
    let b = h.connect(1000);
    assert_eq!(b.holder().incarnation(), report.incarnation);
    assert_ne!(b.holder(), a.holder());
    let after = h.lease(&b, &s);
    assert!(after > before, "{after:?} must be newer than {before:?}");
}

#[test]
fn epoch_exhaustion_fails_closed_and_never_wraps() {
    let mut h = Harness::new("exhausted");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    h.authority().release_lease(&a, &s, e).unwrap();
    raw(&h.state())
        .execute(
            "UPDATE session_lease SET epoch = ?1",
            [i64::try_from(MAX_EPOCH).unwrap()],
        )
        .unwrap();
    assert_eq!(
        h.authority().acquire_lease(&a, &s),
        Err(AuthorityError::EpochExhausted)
    );
    let conn = raw(&h.state());
    let stored: i64 = conn
        .query_row("SELECT epoch FROM session_lease", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        u64::try_from(stored).unwrap(),
        MAX_EPOCH,
        "not wrapped, not reset"
    );
}

#[test]
fn the_database_refuses_a_new_tenure_at_an_old_epoch() {
    // The Rust bumps the epoch; the trigger is the second, independent
    // statement of the rule.
    let mut h = Harness::new("trigger");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    h.authority().release_lease(&a, &s, e).unwrap();
    let conn = raw(&h.state());
    let refused = conn.execute(
        "UPDATE session_lease SET state = 'HELD', holder_subject = 'uid:1', holder_incarnation = 9, \
         holder_connection = 9, expires_ms = 1",
        [],
    );
    assert!(refused.is_err(), "a new holder without a new epoch");
}

#[test]
fn the_wire_answers_are_the_committed_shapes() {
    let mut h = Harness::new("wire");
    let s = session(1);
    let a = h.connect(1000);
    let DwkpBody::LeaseGrant(grant) = h.authority().dispatch(&a, &acquire_msg(&s)).unwrap() else {
        panic!("a LeaseGrant")
    };
    assert_eq!(grant.session_id, s);
    let e = grant.epoch;
    let b = h.connect(2000);
    let DwkpBody::AuthorityRefused(refusal) = h.authority().dispatch(&b, &acquire_msg(&s)).unwrap()
    else {
        panic!("a refusal")
    };
    assert_eq!(refusal.operation, RefusedOperation::AcquireLease);
    assert_eq!(refusal.reason, RefusalReason::LeaseHeld);
    assert!(matches!(
        h.authority().dispatch(&a, &heartbeat_msg(&s, e)).unwrap(),
        DwkpBody::Ack(_)
    ));
    let DwkpBody::AuthorityRefused(refusal) =
        h.authority().dispatch(&b, &heartbeat_msg(&s, e)).unwrap()
    else {
        panic!("a refusal")
    };
    assert_eq!(
        (refusal.operation, refusal.reason),
        (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
    );
    assert!(matches!(
        h.authority()
            .dispatch(&a, &release_lease_msg(&s, e))
            .unwrap(),
        DwkpBody::Ack(_)
    ));
}

#[test]
fn acquisitions_and_releases_are_audited_and_heartbeats_are_not() {
    let mut h = Harness::new("audit");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    for _ in 0..5 {
        h.authority().heartbeat(&a, &s, e).unwrap();
    }
    h.authority().release_lease(&a, &s, e).unwrap();
    let acquired = audit_records(&h.state(), AuditEvent::LeaseAcquired.as_str());
    assert_eq!(acquired.len(), 1);
    assert_eq!(text(&acquired[0], "session_id"), Some(s.as_str()));
    assert_eq!(text(&acquired[0], "subject"), Some("uid:1000"));
    assert_eq!(
        audit_records(&h.state(), AuditEvent::LeaseReleased.as_str()).len(),
        1
    );
    let events = state_support::audit_events(&h.state());
    assert!(!events.iter().any(|e| e.contains("heartbeat")));
}

// ---------------------------------------------------------------------------
// Epoch monotonicity, over long generated sequences with restarts.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Acquire(u8),
    Release(u8),
    Heartbeat(u8),
    Expire,
    Restart,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0u8..3).prop_map(Step::Acquire),
        2 => (0u8..3).prop_map(Step::Release),
        2 => (0u8..3).prop_map(Step::Heartbeat),
        1 => Just(Step::Expire),
        1 => Just(Step::Restart),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn every_new_tenure_is_strictly_newer_than_every_earlier_one(
        steps in proptest::collection::vec(step(), 1..40)
    ) {
        let mut h = Harness::new("prop-epoch");
        let s = session(7);
        // Three connections, each with the last epoch it was granted.
        let mut callers = vec![h.connect(1), h.connect(1), h.connect(2)];
        let mut held: Vec<Option<dwk_proto::wire::scalar::Epoch>> = vec![None; 3];
        let mut highest = 0u64;
        for step in steps {
            match step {
                Step::Acquire(i) => {
                    let i = usize::from(i);
                    if let Reply::Done(e) = h.authority().acquire_lease(&callers[i], &s).unwrap() {
                        prop_assert!(e.get() > highest, "epoch {} after {highest}", e.get());
                        highest = e.get();
                        held = vec![None; 3];
                        held[i] = Some(e);
                    }
                }
                Step::Release(i) => {
                    let i = usize::from(i);
                    if let Some(e) = held[i] {
                        let _ = h.authority().release_lease(&callers[i], &s, e).unwrap();
                        held[i] = None;
                    }
                }
                Step::Heartbeat(i) => {
                    let i = usize::from(i);
                    let e = held[i].unwrap_or_else(|| epoch(highest.max(1)));
                    let reply = h.authority().heartbeat(&callers[i], &s, e).unwrap();
                    if held[i].is_none() {
                        prop_assert_eq!(reply, Reply::Refused(RefusalReason::StaleEpoch));
                    }
                }
                Step::Expire => {
                    h.clock.advance(TTL + 1);
                    held = vec![None; 3];
                }
                Step::Restart => {
                    h.restart();
                    callers = vec![h.connect(1), h.connect(1), h.connect(2)];
                    held = vec![None; 3];
                }
            }
        }
        let stored: i64 = raw(&h.state())
            .query_row("SELECT coalesce(max(epoch), 0) FROM session_lease", [], |r| r.get(0))
            .unwrap();
        prop_assert_eq!(u64::try_from(stored).unwrap(), highest, "never reset by a restart");
    }
}
