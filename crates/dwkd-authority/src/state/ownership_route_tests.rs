//! F-18 (ADR-0063, Proposed) in this crate's unit tests: a revocation's two
//! phases against the route tests' **fake broker**, which contains nothing
//! and runs nothing -- so "destroyed" here is the authority's record and the
//! order it sent. What these prove is the authority's: that a revocation's
//! first phase ends the subject's lease, runs and environments durably
//! before the broker hears of it; that its report says `REVOKED` until the
//! broker confirmed every environment gone and nothing of the runs still
//! runs, and `COMPLETE` only after; that a broker it cannot reach, a parked
//! workload, and a crash on either side of the broker leave it safe and are
//! completed later; and that a revoked run is never answered with what its
//! workload produced. Real containers are the evidence tasks'.

use dwk_proto::wire::scalar::RefusalReason;

use super::*;
use crate::state::{AuditEvent, ConfigError, RevocationReport, RevocationStatus};

const DELEGATE: u32 = 2000;

/// uid:2000 holds the fixture's session as the operator's delegate: the
/// workspace's sharing acknowledged, uid:2000 a principal of it and of the
/// fixture's profile, uid:1000's lease released, and uid:2000's taken.
fn delegated(fx: &mut Fixture) {
    let ws = WorkspaceId::new("ws").unwrap();
    let two = AuthenticatedSubject::unix_uid(DELEGATE);
    let session = fx.session.clone();
    {
        let mut operator = fx.authority().operator();
        operator.acknowledge_root_share(&ws).unwrap();
        operator.grant_workspace_principal(&ws, two).unwrap();
        operator
            .grant_profile_principal(&AgentProfileName::new("operator").unwrap(), two)
            .unwrap();
        operator.add_session_delegate(&session, two).unwrap();
    }
    let (owner, epoch) = (fx.caller.unwrap(), fx.epoch);
    assert!(matches!(
        fx.authority()
            .release_lease(&owner, &session, epoch)
            .unwrap(),
        Reply::Done(())
    ));
    let caller = fx.authority().connect(two);
    let Reply::Done(epoch) = fx.authority().acquire_lease(&caller, &session).unwrap() else {
        panic!("the delegate's lease")
    };
    fx.caller = Some(caller);
    fx.epoch = epoch;
}

fn revoke(fx: &mut Fixture) -> Result<RevocationReport, ConfigError> {
    let session = fx.session.clone();
    fx.authority()
        .operator()
        .revoke_session_delegate(&session, AuthenticatedSubject::unix_uid(DELEGATE))
}

fn status(fx: &mut Fixture, revocation: i64) -> RevocationReport {
    fx.authority()
        .revocation_status(revocation)
        .unwrap()
        .expect("a recorded revocation")
}

fn environment_state(fx: &Fixture, environment: &EnvironmentId) -> String {
    fx.one(&format!(
        "SELECT state FROM environment WHERE environment_id = '{}'",
        environment.as_str()
    ))
}

#[test]
fn f18_a_revocation_ends_a_parked_workloads_environment_and_answers_nothing_it_produced() {
    let mut fx = fixture();
    delegated(&mut fx);
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake.running(1);
    let Dispatched::Parked(parked) = fx.exec(&run, "w1", &call(FIXTURE, &["workload-daemon"]))
    else {
        panic!("a running launch is parked")
    };
    let report = revoke(&mut fx).unwrap();
    // Phase A: the lease, the run and the environment's destruction, in one
    // transaction; Phase B: the broker removed it -- while the workload was
    // still launching. The workload is not settled yet: REVOKED.
    assert_eq!((report.leases_invalidated, report.runs_reaped), (1, 1));
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM run WHERE run_id = '{}'",
            run.as_str()
        )),
        "REAPED"
    );
    let destroy = fx.fake.asked_for("environment.destroy");
    assert_eq!(destroy.len(), 1);
    assert_eq!(destroy[0].launching, 1, "ordered while the workload ran");
    assert_eq!(environment_state(&fx, &environment), "DESTROYED");
    assert_eq!(report.status, RevocationStatus::Revoked);
    assert_eq!((report.environments_live, report.workloads_running), (0, 1));
    // The workload ended as the broker says, and is recorded so -- but the
    // revoked run is told nothing it produced.
    let body = fx.settle(parked);
    let (reason, destroyed) = failed(&body);
    assert_eq!(reason, F::OutcomeUnknown);
    assert_eq!(destroyed, Some(true));
    assert_eq!(
        fx.one("SELECT state FROM workload WHERE idempotency_key = 'w1'"),
        "COMPLETED",
        "the durable outcome is the broker's"
    );
    let report = status(&mut fx, report.revocation);
    assert_eq!(report.status, RevocationStatus::Complete);
    // Nothing the revoked holder sends passes the fence again.
    let session = fx.session.clone();
    let caller = fx.caller.unwrap();
    assert_eq!(
        {
            let epoch = fx.epoch;
            fx.authority().heartbeat(&caller, &session, epoch)
        }
        .unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    let starts = fx.fake.asked_for("workload.start").len();
    let body = fx.answered(&run, "w2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::StaleEpoch);
    assert_eq!(
        fx.fake.asked_for("workload.start").len(),
        starts,
        "nothing launched"
    );
}

#[test]
fn f18_a_revocation_the_broker_cannot_confirm_stays_revoked_until_a_start_completes_it() {
    let mut fx = fixture();
    delegated(&mut fx);
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake.destroys.lock().unwrap().push_back((
        false,
        Err(BrokerError::before_sending(BrokerFailure::Unreachable(
            Unreachable::Connect,
        ))),
    ));
    let report = revoke(&mut fx).unwrap();
    // CW3: the grant, the lease and the run ended; the environment did not,
    // and the report does not say it did.
    assert_eq!(report.status, RevocationStatus::Revoked);
    assert_eq!(report.environments_live, 1);
    assert_eq!(environment_state(&fx, &environment), "DESTROYING");
    assert!(
        fx.events()
            .iter()
            .any(|e| e == AuditEvent::EnvironmentDestroyFailed.as_str()),
        "the failure is audited"
    );
    // Nothing can run in it meanwhile.
    let session = fx.session.clone();
    let caller = fx.caller.unwrap();
    assert_eq!(
        {
            let epoch = fx.epoch;
            fx.authority().heartbeat(&caller, &session, epoch)
        }
        .unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // The next start's reconciliation removes it: COMPLETE.
    fx.restart(Some(IMAGE));
    assert_eq!(environment_state(&fx, &environment), "DESTROYED");
    assert_eq!(
        status(&mut fx, report.revocation).status,
        RevocationStatus::Complete
    );
    let two = fx
        .authority()
        .connect(AuthenticatedSubject::unix_uid(DELEGATE));
    assert_eq!(
        fx.authority().acquire_lease(&two, &session).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "the restart gave nothing back"
    );
}

#[test]
fn f18_a_crash_between_a_revocations_commit_and_the_broker_is_completed_at_the_next_start() {
    let mut fx = Fixture::with(custom(), Some(stop_at(CrashPoint::ReapAfterIntent)));
    fx.attach(IMAGE);
    delegated(&mut fx);
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    let destroys = fx.fake.asked_for("environment.destroy").len();
    // CW1: the first phase committed; the process died before the broker.
    assert!(matches!(revoke(&mut fx), Err(ConfigError::Authority(_))));
    assert_eq!(fx.fake.asked_for("environment.destroy").len(), destroys);
    assert_eq!(environment_state(&fx, &environment), "DESTROYING");
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM run WHERE run_id = '{}'",
            run.as_str()
        )),
        "REAPED"
    );
    assert_eq!(fx.count("SELECT count(*) FROM ownership_revocation"), 1);
    fx.restart(Some(IMAGE));
    assert_eq!(environment_state(&fx, &environment), "DESTROYED");
    let revocation = fx.count("SELECT revocation_id FROM ownership_revocation");
    assert_eq!(
        status(&mut fx, revocation).status,
        RevocationStatus::Complete
    );
    let session = fx.session.clone();
    let two = fx
        .authority()
        .connect(AuthenticatedSubject::unix_uid(DELEGATE));
    assert_eq!(
        fx.authority().acquire_lease(&two, &session).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
}

#[test]
fn f18_a_crash_after_the_broker_removed_an_environment_is_settled_as_gone_at_the_next_start() {
    let mut fx = Fixture::with(
        custom(),
        Some(stop_at(CrashPoint::EnvironmentDestroyAfterBroker)),
    );
    fx.attach(IMAGE);
    delegated(&mut fx);
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    // CW2: the broker removed it; the process died before recording so.
    assert!(matches!(revoke(&mut fx), Err(ConfigError::Authority(_))));
    assert!(fx.fake.live.lock().unwrap().is_empty(), "removed");
    assert_eq!(environment_state(&fx, &environment), "DESTROYING");
    fx.restart(Some(IMAGE));
    assert_ne!(environment_state(&fx, &environment), "DESTROYING");
    let revocation = fx.count("SELECT revocation_id FROM ownership_revocation");
    assert_eq!(
        status(&mut fx, revocation).status,
        RevocationStatus::Complete
    );
    let _ = run;
}

#[test]
fn f18_a_revocation_of_nothing_writes_nothing() {
    let mut fx = fixture();
    let before = fx.events().len();
    assert!(matches!(revoke(&mut fx), Err(ConfigError::Invalid(_))));
    assert_eq!(fx.events().len(), before, "no record, no change");
    assert_eq!(fx.count("SELECT count(*) FROM ownership_revocation"), 0);
}
