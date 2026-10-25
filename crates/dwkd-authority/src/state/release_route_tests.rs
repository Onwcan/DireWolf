//! A run's release ends its execution environment (M5d.6, ADR-0052 §8) in
//! this crate's unit tests: the real authority and store, and the route
//! tests' **fake broker**, which contains nothing and runs nothing -- so a
//! "destroyed" here is the authority's record and the order it sent, never a
//! container removed. What these prove is the authority's: who may end a
//! run's environment, what is durable before the broker is told, which
//! environment the order names, that an unconfirmed answer stays pending
//! until reconciliation ends it, that a preparation the release overtakes
//! keeps nothing, and that nothing the run did runs again. Real containers
//! are `make sandbox-release-evidence`'s.

use dwk_proto::wire::scalar::RefusalReason;

use super::*;
use crate::state::AuditEvent;

/// One line of `make sandbox-release-evidence`'s in-process half, printed
/// only after the assertions before it held. A fake broker: not containment.
fn evidence(case: &str, outcome: &str, enforcement: &str) {
    println!(
        "SANDBOX-EVIDENCE {{\"suite\":\"authority-release\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"level\":\"fake-broker\",\"enforcement\":\"{enforcement}\"}}"
    );
}

fn count(events: &[String], event: AuditEvent) -> usize {
    events
        .iter()
        .filter(|e| e.as_str() == event.as_str())
        .count()
}

fn unreachable() -> Answer {
    Err(BrokerError::before_sending(BrokerFailure::Unreachable(
        Unreachable::Connect,
    )))
}

impl Fixture {
    /// `ReleaseRun` for `run`, by the lease's holder at its epoch.
    fn release(&mut self, run: &RunId) -> Reply<()> {
        let (caller, session, epoch) = (self.caller.unwrap(), self.session.clone(), self.epoch);
        self.authority()
            .release_run(&caller, &session, run, epoch)
            .unwrap()
    }

    fn state_of(&self, environment: &EnvironmentId) -> String {
        self.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{}'",
            environment.as_str()
        ))
    }

    fn run_state(&self, run: &RunId) -> String {
        self.one(&format!(
            "SELECT state FROM run WHERE run_id = '{}'",
            run.as_str()
        ))
    }

    fn container_of(&self, environment: &EnvironmentId) -> String {
        self.one(&format!(
            "SELECT container FROM environment WHERE environment_id = '{}'",
            environment.as_str()
        ))
    }
}

#[test]
fn a_release_destroys_its_runs_environment_durably_first_and_nothing_else() {
    let mut fx = fixture();
    let a = fx.run("ra", &[GRANT]);
    let b = fx.run("rb", &[GRANT]);
    let body = fx.ran(&a, "a1", &call(FIXTURE, &[]));
    let mine = result(&body).1.environment_id.clone();
    let body = fx.ran(&b, "b1", &call(FIXTURE, &[]));
    let theirs = result(&body).1.environment_id.clone();
    let container = fx.container_of(&mine);
    assert!(matches!(fx.release(&a), Reply::Done(())));

    assert_eq!(fx.run_state(&a), "RELEASED");
    assert_eq!(
        fx.one(&format!(
            "SELECT state || ':' || failure FROM environment WHERE environment_id = '{}'",
            mine.as_str()
        )),
        "DESTROYED:RELEASED"
    );
    assert!(
        !fx.fake
            .live
            .lock()
            .unwrap()
            .iter()
            .any(|(id, ..)| *id == mine)
    );
    evidence(
        "release-destroys-the-runs-environment",
        "DESTROYED",
        "authority-release-teardown",
    );
    // The order named exactly this environment, its run and its recorded
    // container, and arrived with the run released and the destruction
    // durable.
    let destroyed = fx.fake.destroyed.lock().unwrap().clone();
    assert_eq!(destroyed.len(), 1, "{destroyed:?}");
    assert_eq!(destroyed[0].environment, mine);
    assert_eq!(destroyed[0].run, a);
    assert_eq!(
        destroyed[0].container.as_ref().map(ContainerRef::as_str),
        Some(container.as_str())
    );
    assert_eq!(
        destroyed[0].states,
        ("DESTROYING".to_owned(), "RELEASED".to_owned())
    );
    evidence(
        "release-intent-durable-before-the-broker",
        "DESTROYING-and-RELEASED-at-the-order",
        "authority-ledger-intent-first",
    );
    evidence(
        "release-names-only-its-environment",
        "exact-environment-run-container",
        "authority-recorded-identity",
    );
    let events = fx.events();
    let at = |event: AuditEvent| events.iter().position(|e| e == event.as_str()).unwrap();
    assert!(at(AuditEvent::RunReleased) < at(AuditEvent::EnvironmentDestroyIntent));
    assert!(at(AuditEvent::EnvironmentDestroyIntent) < at(AuditEvent::EnvironmentDestroyed));
    evidence(
        "release-audited-in-order",
        "run.released-then-destroy_intent-then-destroyed",
        "authority-audit",
    );

    // Another run of the same session keeps its environment, and runs in it.
    assert_eq!(fx.state_of(&theirs), "READY");
    assert!(
        fx.fake
            .live
            .lock()
            .unwrap()
            .iter()
            .any(|(id, ..)| *id == theirs)
    );
    let body = fx.ran(&b, "b2", &call(FIXTURE, &[]));
    let (_, out) = result(&body);
    assert_eq!(out.environment_id, theirs);
    assert_eq!(out.residue, ResidueVerdict::Pass);
    evidence(
        "release-spares-another-runs-environment",
        "READY-and-ran",
        "authority-run-association",
    );

    // A repeat is acknowledged and does nothing more.
    let intents = count(&fx.events(), AuditEvent::EnvironmentDestroyIntent);
    assert!(matches!(fx.release(&a), Reply::Done(())));
    assert_eq!(fx.fake.destroyed.lock().unwrap().len(), 1);
    assert_eq!(
        count(&fx.events(), AuditEvent::EnvironmentDestroyIntent),
        intents
    );
    assert_eq!(count(&fx.events(), AuditEvent::RunReleased), 1);
    assert_eq!(fx.state_of(&theirs), "READY");
    evidence(
        "release-repeated-no-second-effect",
        "ACK-nothing-destroyed",
        "authority-release-idempotent",
    );

    // A released run regains nothing: its launch is refused before anything
    // is prepared or started, and its keys never run again in another run.
    let prepares = fx.fake.asked_for("environment.prepare").len();
    let starts = fx.fake.asked_for("workload.start").len();
    let workloads = fx.count("SELECT count(*) FROM workload");
    let body = fx.answered(&a, "a2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::UnknownRun);
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), prepares);
    assert_eq!(fx.fake.asked_for("workload.start").len(), starts);
    assert_eq!(fx.count("SELECT count(*) FROM workload"), workloads);
    evidence(
        "released-run-launch-refused-nothing-prepared",
        "UNKNOWN_RUN",
        "authority-run-held-check",
    );
    let body = fx.answered(&b, "a1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::IdempotencyKeyReused);
    assert_eq!(fx.fake.asked_for("workload.start").len(), starts);
    evidence(
        "released-runs-key-never-runs-again",
        "IDEMPOTENCY_KEY_REUSED",
        "authority-shared-idempotency-namespace",
    );
    // What the run was charged stays charged.
    assert_eq!(
        fx.count(&format!(
            "SELECT count(*) FROM workload WHERE run_id = '{}'",
            a.as_str()
        )),
        1
    );
    evidence(
        "release-keeps-the-runs-ledger",
        "charged-never-refunded",
        "authority-ledger",
    );
}

#[test]
fn a_release_with_no_environment_destroys_nothing() {
    let mut fx = fixture();
    let run = fx.run("r0", &[GRANT]);
    assert!(matches!(fx.release(&run), Reply::Done(())));
    assert_eq!(fx.run_state(&run), "RELEASED");
    assert!(fx.fake.asked_for("environment.destroy").is_empty());
    assert!(fx.fake.destroyed.lock().unwrap().is_empty());
    assert_eq!(count(&fx.events(), AuditEvent::EnvironmentDestroyIntent), 0);
    assert_eq!(count(&fx.events(), AuditEvent::RunReleased), 1);
    evidence(
        "release-without-an-environment-destroys-nothing",
        "ACK-nothing-destroyed",
        "authority-release-teardown",
    );
    // With no execution environment attached, a release is M3's, unchanged:
    // the broker is asked nothing.
    let mut bare = Fixture::new(custom());
    let run = bare.run("r0", &[GRANT]);
    assert!(matches!(bare.release(&run), Reply::Done(())));
    assert!(
        bare.fake.operations().is_empty(),
        "{:?}",
        bare.fake.operations()
    );
    evidence(
        "release-without-a-sandbox-unchanged",
        "ACK-broker-asked-nothing",
        "authority-release-teardown",
    );
}

#[test]
fn a_fenced_or_foreign_release_ends_no_environment() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);

    // Another session's run, with an environment of its own.
    let workspace = WorkspaceId::new("ws").unwrap();
    let other_session = SessionId::from_uuid(uuid(2)).unwrap();
    fx.authority()
        .operator()
        .bind_session_workspace(&other_session, &workspace)
        .unwrap();
    fx.session = other_session.clone();
    fx.lease();
    let foreign = fx.run("f1", &[GRANT]);
    let foreign_environment = fx.ready(&foreign);
    let foreign_caller = fx.caller.unwrap();
    fx.session = session.clone();
    fx.caller = Some(caller);
    fx.epoch = epoch;

    let later = Epoch::new(epoch.get() + 1).unwrap();
    let reply = fx
        .authority()
        .release_run(&caller, &session, &run, later)
        .unwrap();
    assert!(matches!(reply, Reply::Refused(RefusalReason::StaleEpoch)));
    evidence(
        "release-stale-epoch-refused-nothing-destroyed",
        "STALE_EPOCH",
        "authority-lease-fence",
    );
    // Another connection of the same subject is not the lease's holder.
    let stranger = fx.authority().connect(AuthenticatedSubject::unix_uid(1000));
    let reply = fx
        .authority()
        .release_run(&stranger, &session, &run, epoch)
        .unwrap();
    assert!(matches!(reply, Reply::Refused(RefusalReason::StaleEpoch)));
    evidence(
        "release-other-holder-refused-nothing-destroyed",
        "STALE_EPOCH",
        "authority-lease-fence",
    );
    // A run of another session, named under this caller's own lease:
    // acknowledged, as a run it does not hold always is, and nothing ends.
    let reply = fx
        .authority()
        .release_run(&caller, &session, &foreign, epoch)
        .unwrap();
    assert!(matches!(reply, Reply::Done(())));
    let unknown = RunId::from_uuid(uuid(77_777)).unwrap();
    let reply = fx
        .authority()
        .release_run(&caller, &session, &unknown, epoch)
        .unwrap();
    assert!(matches!(reply, Reply::Done(())));
    assert_eq!(fx.state_of(&environment), "READY");
    assert_eq!(fx.state_of(&foreign_environment), "READY");
    assert_eq!(fx.run_state(&run), "ACTIVE");
    assert_eq!(fx.run_state(&foreign), "ACTIVE");
    assert!(fx.fake.destroyed.lock().unwrap().is_empty());
    assert_eq!(count(&fx.events(), AuditEvent::EnvironmentDestroyIntent), 0);
    evidence(
        "release-of-a-run-not-held-destroys-nothing",
        "ACK-nothing-destroyed",
        "authority-run-ownership",
    );

    // Its own holder's release ends it -- and only it.
    assert!(matches!(fx.release(&run), Reply::Done(())));
    assert_eq!(fx.state_of(&environment), "DESTROYED");
    assert_eq!(fx.state_of(&foreign_environment), "READY");
    let _ = foreign_caller;
}

#[test]
fn a_release_ends_the_environment_an_in_flight_workload_runs_in_and_it_never_runs_again() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake.running(1);
    let Dispatched::Parked(parked) = fx.exec(&run, "w1", &call(FIXTURE, &["workload-daemon"]))
    else {
        panic!("a running launch is parked")
    };
    assert_eq!(
        fx.one("SELECT state FROM workload WHERE idempotency_key = 'w1'"),
        "LAUNCHING"
    );
    assert!(matches!(fx.release(&run), Reply::Done(())));
    // Nothing waited for the workload: its environment's destruction was
    // ordered while it was launching.
    let destroy = fx.fake.asked_for("environment.destroy");
    assert_eq!(destroy.len(), 1);
    assert_eq!(destroy[0].launching, 1);
    assert_eq!(fx.state_of(&environment), "DESTROYED");
    evidence(
        "release-ends-an-in-flight-workloads-environment",
        "DESTROYED-while-LAUNCHING",
        "authority-release-teardown",
    );
    // Its collection cannot say how it ended: UNKNOWN, answered so, and the
    // ended environment is not ordered destroyed again.
    fx.fake.then_collect(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    )));
    let body = fx.settle(parked);
    let (reason, _) = failed(&body);
    assert_eq!(reason, F::OutcomeUnknown);
    assert_eq!(
        fx.one("SELECT state FROM workload WHERE idempotency_key = 'w1'"),
        "UNKNOWN"
    );
    assert_eq!(fx.state_of(&environment), "DESTROYED");
    assert_eq!(fx.fake.asked_for("environment.destroy").len(), 1);
    evidence(
        "release-in-flight-workload-settled-unknown",
        "OUTCOME_UNKNOWN",
        "authority-ledger",
    );
    let other = fx.run("r2", &[GRANT]);
    let starts = fx.fake.asked_for("workload.start").len();
    let body = fx.answered(&other, "w1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::IdempotencyKeyReused);
    assert_eq!(fx.fake.asked_for("workload.start").len(), starts);
    evidence(
        "release-in-flight-workload-never-rerun",
        "IDEMPOTENCY_KEY_REUSED",
        "authority-shared-idempotency-namespace",
    );
}

#[test]
fn a_run_released_while_its_environment_is_prepared_never_keeps_it() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    // Another handle onto the same store releases the run while the broker
    // prepares its environment: the interleaving one worker never makes,
    // which the store does not forbid.
    let mut other = fx.authority().handle().unwrap();
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    let released = run.clone();
    let seen = Arc::new(Mutex::new(None));
    let saw = Arc::clone(&seen);
    *fx.fake.during_prepare.lock().unwrap() = Some(Meanwhile(Box::new(move || {
        let reply = other
            .release_run(&caller, &session, &released, epoch)
            .unwrap();
        *saw.lock().unwrap() = Some(matches!(reply, Reply::Done(())));
    })));
    let body = fx.answered(&run, "p1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentUnavailable);
    assert_eq!(
        *seen.lock().unwrap(),
        Some(true),
        "the release went through"
    );
    assert_eq!(fx.run_state(&run), "RELEASED");
    // The release found the preparation in flight and left it to its
    // outcome; the outcome found the run ended and destroyed what it made.
    assert_eq!(
        fx.one(&format!(
            "SELECT state || ':' || failure FROM environment WHERE run_id = '{}'",
            run.as_str()
        )),
        "DESTROYED:RUN_ENDED"
    );
    assert!(fx.fake.live.lock().unwrap().is_empty());
    evidence(
        "release-during-preparation-environment-destroyed",
        "RUN_ENDED",
        "authority-preparation-outcome-check",
    );
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
    evidence(
        "release-during-preparation-nothing-ran",
        "ENVIRONMENT_UNAVAILABLE",
        "authority-route",
    );
}

#[test]
fn a_release_whose_destruction_is_unconfirmed_stays_pending_until_it_is_completed() {
    for (case, removed, answer) in [
        ("broker-unreachable", false, unreachable()),
        (
            "answer-lost",
            true,
            Err(BrokerError::after_sending(BrokerFailure::Indeterminate(
                Indeterminate::EnvironmentUnconfirmed,
            ))),
        ),
    ] {
        let mut fx = fixture();
        let run = fx.run("r1", &[GRANT]);
        let environment = fx.ready(&run);
        fx.fake
            .destroys
            .lock()
            .unwrap()
            .push_back((removed, answer));
        assert!(matches!(fx.release(&run), Reply::Done(())), "{case}");
        assert_eq!(fx.run_state(&run), "RELEASED", "{case}");
        assert_eq!(fx.state_of(&environment), "DESTROYING", "{case}");
        assert_eq!(
            count(&fx.events(), AuditEvent::EnvironmentDestroyFailed),
            1,
            "{case}"
        );
        assert_eq!(
            count(&fx.events(), AuditEvent::EnvironmentDestroyed),
            0,
            "{case}"
        );
        evidence(
            &format!("release-{case}-destruction-pending"),
            "DESTROYING",
            "authority-unconfirmed-is-pending",
        );
        // The next start reconciles it by label: removed now, or found gone.
        fx.restart(Some(IMAGE));
        assert_eq!(fx.state_of(&environment), "DESTROYED", "{case}");
        assert!(fx.fake.live.lock().unwrap().is_empty(), "{case}");
        evidence(
            &format!("release-{case}-completed-at-restart"),
            "DESTROYED",
            "authority-reconciliation",
        );
    }
    // Within one incarnation the next preparation completes it first.
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake
        .destroys
        .lock()
        .unwrap()
        .push_back((false, unreachable()));
    assert!(matches!(fx.release(&run), Reply::Done(())));
    assert_eq!(fx.state_of(&environment), "DESTROYING");
    let next = fx.run("r2", &[GRANT]);
    let body = fx.ran(&next, "n1", &call(FIXTURE, &[]));
    assert_eq!(result(&body).1.residue, ResidueVerdict::Pass);
    assert_eq!(fx.state_of(&environment), "DESTROYED");
    evidence(
        "release-pending-destruction-completed-by-the-next-preparation",
        "DESTROYED",
        "authority-reclamation",
    );
}

#[test]
fn a_release_completes_its_runs_own_pending_destruction() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    // An uncertain workload costs its environment, and the broker cannot be
    // reached for the destruction: it stays pending.
    fx.fake.then_collect(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    )));
    fx.fake
        .destroys
        .lock()
        .unwrap()
        .push_back((false, unreachable()));
    let body = fx.ran(&run, "u1", &call(FIXTURE, &[]));
    assert_eq!(failed(&body).0, F::OutcomeUnknown);
    assert_eq!(fx.state_of(&environment), "DESTROYING");
    // The run's release tries it again, and completes it.
    assert!(matches!(fx.release(&run), Reply::Done(())));
    assert_eq!(fx.state_of(&environment), "DESTROYED");
    assert!(fx.fake.live.lock().unwrap().is_empty());
    evidence(
        "release-completes-its-runs-pending-destruction",
        "DESTROYED",
        "authority-release-teardown",
    );
}

/// W12 and W6-W7 through a release (ADR-0052 §9): a crash at each window,
/// then a restart -- the run still released, its environment destroyed by
/// reconciliation, and nothing the run did run again.
#[test]
fn a_crash_in_every_window_of_a_release_is_completed_at_restart_and_nothing_reruns() {
    for point in [
        CrashPoint::ReleaseAfterIntent,
        CrashPoint::EnvironmentDestroyAfterIntent,
        CrashPoint::EnvironmentDestroyAfterBroker,
    ] {
        let mut fx = Fixture::with(custom(), Some(stop_at(point)));
        fx.attach(IMAGE);
        let run = fx.run("r1", &[GRANT]);
        let body = fx.ran(&run, "w1", &call(FIXTURE, &[]));
        let environment = result(&body).1.environment_id.clone();
        let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
        assert!(
            fx.authority()
                .release_run(&caller, &session, &run, epoch)
                .is_err(),
            "{point}: the hook stopped it"
        );
        assert_eq!(fx.run_state(&run), "RELEASED", "{point}");
        assert_eq!(fx.state_of(&environment), "DESTROYING", "{point}");
        assert_eq!(
            fx.fake.asked_for("environment.destroy").len(),
            usize::from(point == CrashPoint::EnvironmentDestroyAfterBroker),
            "{point}"
        );
        let starts = fx.fake.asked_for("workload.start").len();
        fx.restart(Some(IMAGE));
        assert_eq!(fx.state_of(&environment), "DESTROYED", "{point}");
        assert_eq!(
            fx.run_state(&run),
            "RELEASED",
            "{point}: never active again"
        );
        assert!(fx.fake.live.lock().unwrap().is_empty(), "{point}");
        evidence(
            &format!(
                "release-crash-{}-environment-destroyed-at-restart",
                point.letter()
            ),
            "DESTROYED",
            "authority-reconciliation",
        );
        let again = fx.run("r2", &[GRANT]);
        let body = fx.answered(&again, "w1", &call(FIXTURE, &[]));
        assert_eq!(refused(&body), R::IdempotencyKeyReused, "{point}");
        assert_eq!(fx.fake.asked_for("workload.start").len(), starts, "{point}");
        assert_eq!(
            fx.one("SELECT state FROM workload WHERE idempotency_key = 'w1'"),
            "COMPLETED",
            "{point}"
        );
        evidence(
            &format!("release-crash-{}-never-rerun", point.letter()),
            "IDEMPOTENCY_KEY_REUSED",
            "authority-shared-idempotency-namespace",
        );
    }
}
