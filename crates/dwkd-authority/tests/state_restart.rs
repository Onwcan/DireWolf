//! `AdmitRun` across a tenure change: a lost response, a dead authority, a
//! restart, a re-acquired lease, and a retry of the same key (ADR-0040).
//!
//! The contract under test, for one `(subject, session_id, idempotency_key)`:
//!
//! * **duplicate suppression** holds for ever — there is never a second
//!   logical admission;
//! * **same-response replay** holds only within the tenure that admitted the
//!   run, while the run is active;
//! * **run resumption** is not provided: after the lease ends, a retry of the
//!   same request is `ADMISSION_ENDED`, and authority comes back only through
//!   a new admission under a new key.
//!
//! The first test kills a real authority process after the admission is
//! committed and its audit record durable, but before anything could have
//! carried the response back — the lost response in its purest form — and
//! then restarts on the files it left.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

use std::path::Path;
use std::sync::{Arc, Barrier};

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::wire::scalar::{RefusalReason, RefusedOperation};
use dwkd_authority::state::{Admission, AuditEvent, CallerContext, ManualClock, Reply};
use state_support::{
    Harness, START_MS, TempDir, admit_msg, admit_simple, audit_records, balanced, count,
    install_fixtures, raw, session, start, subject, text,
};

/// The admission the child makes and never answers.
const KEY: &str = "k-lost-response";
const CAPS: &[&str] = &["model.call:*", "memory.read:*"];

/// The child half. Runs only when the parent sets `DW_RESTART_DIR`: it admits
/// a run — committed, audited, `fsync`ed — and then dies without returning
/// the grant to anyone. `DW_RESTART_MODE=released` releases the run first.
#[test]
#[ignore = "executed as a child process by the restart tests"]
fn restart_child() {
    let Ok(dir) = std::env::var("DW_RESTART_DIR") else {
        return;
    };
    let released = std::env::var("DW_RESTART_MODE").is_ok_and(|m| m == "released");
    let clock = Arc::new(ManualClock::new(START_MS));
    let (mut authority, _) =
        start(Path::new(&dir), &balanced(), &clock, None).expect("the child starts");
    install_fixtures(&mut authority);
    let caller = authority.connect(subject(1000));
    let s = session(1);
    let Reply::Done(e) = authority.acquire_lease(&caller, &s).unwrap() else {
        panic!("leased")
    };
    let Reply::Done(admission) = authority
        .admit_run(&caller, &admit_simple(&s, e, KEY, CAPS))
        .unwrap()
    else {
        panic!("admitted")
    };
    if released {
        let Reply::Done(()) = authority
            .release_run(&caller, &s, admission.run_id(), e)
            .unwrap()
        else {
            panic!("released")
        };
    }
    // The grant exists only in kernel.db and audit.log now. No destructors,
    // no clean shutdown: the process is simply gone.
    std::process::abort();
}

/// Admit in a child process that then dies; return a harness restarted on
/// the files it left.
fn after_a_dead_authority(tag: &str, mode: &str) -> Harness {
    let dir = TempDir::new(tag);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "restart_child", "--test-threads=1"])
        .env("DW_RESTART_DIR", dir.state())
        .env("DW_RESTART_MODE", mode)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("the child runs");
    assert!(!status.success(), "the child must have died ({status})");
    let clock = Arc::new(ManualClock::new(START_MS));
    let config = balanced();
    let (authority, report) = start(&dir.state(), &config, &clock, None).expect("the restart");
    assert_eq!(report.leases_invalidated, 1, "the dead process's lease");
    Harness {
        dir,
        clock,
        config,
        authority: Some(authority),
        report,
    }
}

fn run_ids(state: &Path) -> Vec<(String, String)> {
    let conn = raw(state);
    let mut statement = conn
        .prepare("SELECT run_id, state FROM run ORDER BY admitted_ms, run_id")
        .unwrap();
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn a_lost_response_then_authority_death_then_restart_then_the_same_retry_is_admission_ended() {
    // 1. admit  2. commit  3. the response is lost  4. the authority dies
    let mut h = after_a_dead_authority("seven-steps", "admitted");
    // 5. restart (above): the dead process's run was reaped with its lease.
    assert_eq!(h.report.runs_reaped, 1);
    let before = run_ids(&h.state());
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].1, "REAPED");
    let grants_before = count(&raw(&h.state()), "SELECT count(*) FROM run_grant");

    // 6. re-acquire: a new connection, a new epoch.
    let a = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    assert_eq!(e.get(), 2, "the epoch moved past the dead process's");

    // 7. retry the SAME subject, session, key and payload.
    let retry = admit_simple(&s, e, KEY, CAPS);
    assert_eq!(
        h.authority().admit_run(&a, &retry).unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    // The same answer on the wire, as the M3e server sends it.
    let DwkpBody::AuthorityRefused(refusal) = h.authority().dispatch(&a, &retry).unwrap() else {
        panic!("a refusal")
    };
    assert_eq!(
        (refusal.operation, refusal.reason),
        (RefusedOperation::AdmitRun, RefusalReason::AdmissionEnded)
    );

    // NO SECOND LOGICAL ADMISSION: one run, one record, no new cap_id, and
    // the reaped run stays reaped.
    let conn = raw(&h.state());
    assert_eq!(run_ids(&h.state()), before);
    assert_eq!(
        count(&conn, "SELECT count(*) FROM admission_idempotency"),
        1
    );
    assert_eq!(
        count(&conn, "SELECT count(*) FROM run_grant"),
        grants_before
    );
    let refused = audit_records(&h.state(), AuditEvent::RunAdmitRefused.as_str());
    let last = refused.last().unwrap();
    assert_eq!(text(last, "reason"), Some("ADMISSION_ENDED"));
    assert_eq!(text(last, "original_run_id"), Some(before[0].0.as_str()));
    assert_eq!(text(last, "original_run_state"), Some("REAPED"));
    assert!(
        audit_records(&h.state(), AuditEvent::RunAdmitReplayed.as_str()).is_empty(),
        "nothing was replayed as if it were usable"
    );

    // The remedy: a new key is a new logical admission, with new identities.
    let Reply::Done(fresh) = h
        .authority()
        .admit_run(&a, &admit_simple(&s, e, "k-new", CAPS))
        .unwrap()
    else {
        panic!("a new admission")
    };
    assert_ne!(fresh.run_id().as_str(), before[0].0);
    assert_eq!(fresh.epoch(), e);
    assert_eq!(run_ids(&h.state()).len(), 2);
}

#[test]
fn after_a_restart_the_same_key_with_a_changed_payload_is_a_conflict() {
    let mut h = after_a_dead_authority("changed-payload", "admitted");
    let a = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, KEY, &["model.call:*"]))
            .unwrap(),
        Reply::Refused(RefusalReason::IdempotencyConflict)
    );
    assert_eq!(run_ids(&h.state()).len(), 1);
}

#[test]
fn after_a_restart_another_subject_with_the_same_key_has_a_scope_of_its_own() {
    let mut h = after_a_dead_authority("other-subject", "admitted");
    let original = run_ids(&h.state());
    let b = h.connect(2000);
    let s = session(1);
    let e = h.lease(&b, &s);
    // Neither a replay of the dead admission nor a collision with it: a first
    // admission in B's own scope.
    let Reply::Done(admission) = h
        .authority()
        .admit_run(&b, &admit_simple(&s, e, KEY, CAPS))
        .unwrap()
    else {
        panic!("B's own admission")
    };
    assert_ne!(admission.run_id().as_str(), original[0].0);
    let conn = raw(&h.state());
    assert_eq!(
        count(
            &conn,
            "SELECT count(DISTINCT subject) FROM admission_idempotency"
        ),
        2
    );
    // A's admission is exactly as it was.
    let states = run_ids(&h.state());
    assert!(states.contains(&(original[0].0.clone(), "REAPED".to_owned())));
    // And it never lent B anything: B's grant has B's own cap ids.
    let shared: i64 = conn
        .query_row(
            "SELECT count(*) FROM run_grant a JOIN run_grant b ON a.cap_id = b.cap_id \
             WHERE a.run_id = ?1 AND b.run_id = ?2",
            [original[0].0.as_str(), admission.run_id().as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(shared, 0);
}

#[test]
fn a_released_run_then_restart_then_the_same_key_is_admission_ended() {
    let mut h = after_a_dead_authority("released-restart", "released");
    assert_eq!(h.report.runs_reaped, 0, "it had already been released");
    let a = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, KEY, CAPS))
            .unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    let runs = run_ids(&h.state());
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].1, "RELEASED", "released, never resurrected");
}

#[test]
fn a_stale_holder_or_an_old_epoch_after_a_restart_meets_the_fence_first() {
    // In process, so the pre-restart connection object survives the restart
    // exactly as a zombie runtime's would.
    let mut h = Harness::new("stale-after-restart");
    let old = h.connect(1000);
    let s = session(1);
    let e1 = h.lease(&old, &s);
    let msg = admit_simple(&s, e1, KEY, CAPS);
    let Reply::Done(_) = h.authority().admit_run(&old, &msg).unwrap() else {
        panic!("admitted")
    };
    h.restart();
    // The zombie with its valid old key: fenced, before the key is looked at.
    assert_eq!(
        h.authority().admit_run(&old, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    let fresh = h.connect(1000);
    let e2 = h.lease(&fresh, &s);
    // The zombie presenting the new epoch it never received: still fenced.
    assert_eq!(
        h.authority()
            .admit_run(&old, &admit_simple(&s, e2, KEY, CAPS))
            .unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // The new holder presenting the old epoch: fenced.
    assert_eq!(
        h.authority().admit_run(&fresh, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // The new holder at its own epoch: the key is spent.
    assert_eq!(
        h.authority()
            .admit_run(&fresh, &admit_simple(&s, e2, KEY, CAPS))
            .unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    assert_eq!(run_ids(&h.state()).len(), 1);
}

#[test]
fn concurrent_retries_after_a_restart_are_all_admission_ended() {
    let mut h = after_a_dead_authority("concurrent-retries", "admitted");
    let a: CallerContext = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|i| {
            let mut handle = h.authority().handle().unwrap();
            let barrier = barrier.clone();
            let message = admit_msg(
                &s,
                e,
                KEY,
                "researcher",
                &[],
                CAPS,
                u64::try_from(i).unwrap(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                handle.admit_run(&a, &message)
            })
        })
        .collect();
    for result in workers.into_iter().map(|w| w.join().unwrap()) {
        assert_eq!(
            result.unwrap(),
            Reply::Refused(RefusalReason::AdmissionEnded)
        );
    }
    assert_eq!(run_ids(&h.state()).len(), 1, "no second logical admission");
    assert_eq!(
        count(
            &raw(&h.state()),
            "SELECT count(*) FROM admission_idempotency"
        ),
        1
    );
}

#[test]
fn within_the_admitting_tenure_a_lost_response_is_replayed_exactly() {
    // The other half of the contract: before the lease ends, the retry gets
    // the grant the lost response carried -- the same run, epoch, revision,
    // cap ids and withheld list -- and nothing is minted.
    let mut h = Harness::new("same-tenure");
    let a = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    let msg = admit_simple(&s, e, KEY, &["model.call:*", "secret.use:github"]);
    let Reply::Done(first) = h.authority().admit_run(&a, &msg).unwrap() else {
        panic!("admitted")
    };
    let grants = count(&raw(&h.state()), "SELECT count(*) FROM run_grant");
    let Reply::Done(again) = h.authority().admit_run(&a, &msg).unwrap() else {
        panic!("replayed")
    };
    assert_eq!(again, first);
    assert_eq!(
        count(&raw(&h.state()), "SELECT count(*) FROM run_grant"),
        grants
    );
}

#[test]
fn a_holder_rotating_its_own_lease_ends_its_runs_and_spends_their_keys() {
    let mut h = Harness::new("rotation");
    let a = h.connect(1000);
    let s = session(1);
    let e1 = h.lease(&a, &s);
    let msg = admit_simple(&s, e1, KEY, CAPS);
    let Reply::Done(run) = h.authority().admit_run(&a, &msg).unwrap() else {
        panic!("admitted")
    };
    // The same connection acquires again: a deliberate rotation.
    let e2 = h.lease(&a, &s);
    assert_eq!(e2.get(), e1.get() + 1);
    // The old epoch is unusable at once, for everything.
    assert_eq!(
        h.authority().heartbeat(&a, &s, e1).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    assert_eq!(
        h.authority().admit_run(&a, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // The run admitted under it was reaped, audited with its cause.
    let reaped = audit_records(&h.state(), AuditEvent::RunReaped.as_str());
    assert_eq!(reaped.len(), 1);
    assert_eq!(text(&reaped[0], "run_id"), Some(run.run_id().as_str()));
    assert_eq!(text(&reaped[0], "cause"), Some("lease_reacquired"));
    assert_eq!(
        h.authority()
            .query_authority(&a, &s, run.run_id(), e2, None)
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
    // Its key is spent at the new epoch.
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e2, KEY, CAPS))
            .unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    // There is still exactly one holder.
    let b = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    let conn = raw(&h.state());
    assert_eq!(
        count(
            &conn,
            "SELECT count(*) FROM session_lease WHERE state = 'HELD'"
        ),
        1
    );
}

#[test]
fn after_a_lease_expires_and_is_reacquired_the_key_is_spent() {
    let mut h = Harness::new("expiry");
    let a = h.connect(1000);
    let s = session(1);
    let e1 = h.lease(&a, &s);
    let Reply::Done(_) = h
        .authority()
        .admit_run(&a, &admit_simple(&s, e1, KEY, CAPS))
        .unwrap()
    else {
        panic!("admitted")
    };
    h.clock
        .advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
    let b = h.connect(1000);
    let e2 = h.lease(&b, &s);
    assert_eq!(
        h.authority()
            .admit_run(&b, &admit_simple(&s, e2, KEY, CAPS))
            .unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    assert_eq!(run_ids(&h.state()).len(), 1);
}

#[test]
fn every_admission_answer_is_one_of_the_documented_ones() {
    // A small exhaustive walk: for each of the documented situations, the
    // answer ADR-0040 names, and never a RunGrant for a run that is not active
    // under the caller's current epoch.
    let mut h = Harness::new("table");
    let a = h.connect(1000);
    let s = session(1);
    let e = h.lease(&a, &s);
    let first = |h: &mut Harness, key: &str| -> Admission {
        let Reply::Done(admission) = h
            .authority()
            .admit_run(&a, &admit_simple(&s, e, key, CAPS))
            .unwrap()
        else {
            panic!("admitted")
        };
        admission
    };
    let live = first(&mut h, "live");
    let released = first(&mut h, "released");
    h.authority()
        .release_run(&a, &s, released.run_id(), e)
        .unwrap();
    for (key, caps, want) in [
        ("live", CAPS, None),
        ("released", CAPS, Some(RefusalReason::AdmissionEnded)),
        (
            "live",
            &["model.call:*"][..],
            Some(RefusalReason::IdempotencyConflict),
        ),
        (
            "released",
            &["model.call:*"][..],
            Some(RefusalReason::IdempotencyConflict),
        ),
    ] {
        let answer = h
            .authority()
            .admit_run(&a, &admit_simple(&s, e, key, caps))
            .unwrap();
        match want {
            None => assert_eq!(answer, Reply::Done(live.clone()), "{key}"),
            Some(reason) => assert_eq!(answer, Reply::Refused(reason), "{key}"),
        }
    }
}
