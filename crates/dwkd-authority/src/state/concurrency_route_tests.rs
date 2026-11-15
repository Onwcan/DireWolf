//! F-02 (ADR-0064, Proposed) in this crate's unit tests: an end of authority
//! on one handle against an effect another handle has decided.
//!
//! The production server's one worker never lets a request in between an
//! effect's intent and its broker hand-off; the store does, and before F-02
//! a second handle could revoke a delegate, take a lease over or release a
//! run in that window -- the broker then performed the effect for a run
//! already ended, the old holder was answered as if nothing had happened,
//! and a revocation reported `COMPLETE` with the revoked subject's effect
//! still to come. Each test here stops an effect at the crash point right
//! after its intent, has another handle end its authority (`Meantime`), and
//! proves the end waited at the gate: the effect reached the broker while
//! its run was `ACTIVE`, its outcome is recorded before the end, and nothing
//! the end ended reaches the broker after it. The fake broker contains and
//! runs nothing; these are the authority's orderings, not real-process
//! evidence.

use std::sync::Barrier;
use std::sync::mpsc;

use super::workspace::{WRITES, write, write_done, writing};
use super::*;
use crate::state::interleave::{Hold, Meantime, until};
use crate::state::{ConfigError, DEFAULT_LEASE_TTL_MS, RevocationReport, RevocationStatus};

const DELEGATE: u32 = 2000;

/// uid:2000 holds the fixture's session as the operator's delegate (as the
/// F-18 route tests set it up).
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

/// A fixture whose policy allows brokered writes, stopping at `at`.
fn writer_at(meantime: &Meantime, at: CrashPoint) -> Fixture {
    let mut fx = Fixture::with_declared(writing(), Some(meantime.hook(at)), WRITES);
    fx.attach(IMAGE);
    meantime.watch(fx.authority().gate());
    fx
}

/// A fixture whose policy allows sandboxed launches, stopping at `at`.
fn launcher_at(meantime: &Meantime, at: CrashPoint) -> Fixture {
    let mut fx = Fixture::with(custom(), Some(meantime.hook(at)));
    fx.attach(IMAGE);
    meantime.watch(fx.authority().gate());
    fx
}

fn revoke_delegate(
    mut other: Authority,
    session: &SessionId,
) -> Result<RevocationReport, ConfigError> {
    other
        .operator()
        .revoke_session_delegate(session, AuthenticatedSubject::unix_uid(DELEGATE))
}

fn position(events: &[String], event: &str) -> usize {
    events
        .iter()
        .position(|e| e == event)
        .unwrap_or_else(|| panic!("no {event} in {events:?}"))
}

fn refused_as(body: &DwkpBody) -> String {
    match body {
        DwkpBody::ToolRefusedV2(r) => format!("{:?}", r.reason),
        other => panic!("not refused: {other:?}"),
    }
}

#[test]
fn f02_a_revocation_waits_for_a_decided_write_and_nothing_it_ended_follows() {
    let meantime = Meantime::default();
    let mut fx = writer_at(&meantime, CrashPoint::ToolAfterIntent);
    delegated(&mut fx);
    let run = fx.run("r1", WRITES);
    let other = fx.authority().handle().unwrap();
    let session = fx.session.clone();
    let (tx, rx) = mpsc::channel();
    meantime.then(move || tx.send(revoke_delegate(other, &session)).unwrap());
    let body = fx.tool(&run, "w1", &write("/workspace/a.txt"));
    meantime.join();
    let report = rx.recv().unwrap().unwrap();
    assert!(
        meantime.held(),
        "the revocation's first phase began while a write stood decided"
    );
    // Decided while the grant stood, performed and recorded before the
    // revocation committed: an authorised effect, answered as one.
    write_done(&body);
    let writes = fx.fake.asked_for("fs.write");
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].active_runs, 1,
        "the write reached the broker after its run was reaped"
    );
    let events = fx.events();
    assert!(position(&events, "tool.completed") < position(&events, "ownership.revoked"));
    // The report is true when it is read: nothing of the run is pending.
    assert_eq!((report.leases_invalidated, report.runs_reaped), (1, 1));
    assert_eq!(report.status, RevocationStatus::Complete);
    // From the revocation's commit nothing the delegate sends reaches the
    // broker.
    let next = fx.tool(&run, "w2", &write("/workspace/b.txt"));
    assert_eq!(refused_as(&next), "StaleEpoch");
    assert_eq!(fx.fake.asked_for("fs.write").len(), 1);
}

#[test]
fn f02_a_takeover_after_expiry_waits_for_the_old_holders_decided_write() {
    let meantime = Meantime::default();
    let mut fx = writer_at(&meantime, CrashPoint::ToolAfterIntent);
    let run = fx.run("r1", WRITES);
    let mut other = fx.authority().handle().unwrap();
    let session = fx.session.clone();
    let clock = Arc::clone(&fx.clock);
    let (tx, rx) = mpsc::channel();
    meantime.then(move || {
        // The old holder's lease expires while its write stands decided; a
        // new connection of the same subject takes the session over.
        clock.advance(DEFAULT_LEASE_TTL_MS + 1);
        let caller = other.connect(AuthenticatedSubject::unix_uid(1000));
        let taken = other.acquire_lease(&caller, &session).unwrap();
        tx.send((caller, taken)).unwrap();
    });
    let body = fx.tool(&run, "w1", &write("/workspace/a.txt"));
    meantime.join();
    let (caller, taken) = rx.recv().unwrap();
    assert!(
        meantime.held(),
        "the new tenure began while the old holder's write stood decided"
    );
    let Reply::Done(epoch) = taken else {
        panic!("the takeover: {taken:?}")
    };
    assert!(epoch.get() > fx.epoch.get(), "a new, higher epoch");
    write_done(&body);
    let writes = fx.fake.asked_for("fs.write");
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].active_runs, 1,
        "the old holder's write reached the broker after the new tenure reaped its run"
    );
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM run WHERE run_id = '{}'",
            run.as_str()
        )),
        "REAPED"
    );
    let events = fx.events();
    assert!(position(&events, "tool.completed") < position(&events, "run.reaped"));
    // The old holder is fenced; the new tenure's own write is the one writer.
    let stale = fx.tool(&run, "w2", &write("/workspace/b.txt"));
    assert_eq!(refused_as(&stale), "StaleEpoch");
    fx.caller = Some(caller);
    fx.epoch = epoch;
    let next = fx.run("r2", WRITES);
    write_done(&fx.tool(&next, "w3", &write("/workspace/c.txt")));
    let writes = fx.fake.asked_for("fs.write");
    assert_eq!(writes.len(), 2);
    assert!(writes.iter().all(|w| w.active_runs == 1));
}

#[test]
fn f02_a_run_release_waits_for_a_decided_write() {
    let meantime = Meantime::default();
    let mut fx = writer_at(&meantime, CrashPoint::ToolAfterIntent);
    let run = fx.run("r1", WRITES);
    let mut other = fx.authority().handle().unwrap();
    let (caller, session, epoch, released) = (
        fx.caller.unwrap(),
        fx.session.clone(),
        fx.epoch,
        run.clone(),
    );
    let (tx, rx) = mpsc::channel();
    meantime.then(move || {
        tx.send(
            other
                .release_run(&caller, &session, &released, epoch)
                .unwrap(),
        )
        .unwrap();
    });
    let body = fx.tool(&run, "w1", &write("/workspace/a.txt"));
    meantime.join();
    assert!(matches!(rx.recv().unwrap(), Reply::Done(())));
    assert!(
        meantime.held(),
        "the release began while a write stood decided"
    );
    write_done(&body);
    let writes = fx.fake.asked_for("fs.write");
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].active_runs, 1,
        "the write followed its run's release"
    );
    let next = fx.tool(&run, "w2", &write("/workspace/b.txt"));
    assert_eq!(refused_as(&next), "UnknownRun");
    assert_eq!(fx.fake.asked_for("fs.write").len(), 1);
}

#[test]
fn f02_a_lease_release_waits_for_a_decided_workload_start() {
    let meantime = Meantime::default();
    let mut fx = launcher_at(&meantime, CrashPoint::WorkloadAfterIntent);
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake.running(1);
    let mut other = fx.authority().handle().unwrap();
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    let (tx, rx) = mpsc::channel();
    meantime.then(move || {
        tx.send(other.release_lease(&caller, &session, epoch).unwrap())
            .unwrap();
    });
    let dispatched = fx.exec(&run, "w1", &call(FIXTURE, &["workload-daemon"]));
    meantime.join();
    assert!(matches!(rx.recv().unwrap(), Reply::Done(())));
    assert!(
        meantime.held(),
        "the lease's end began while a start stood decided"
    );
    let starts = fx.fake.asked_for("workload.start");
    assert_eq!(starts.len(), 1);
    assert_eq!(
        starts[0].active_runs, 1,
        "the start reached the broker after its run was reaped"
    );
    // Started first, then ended with its run: its environment's destruction
    // was ordered after the start, and the parked launch settles.
    let operations = fx.fake.operations();
    let started = operations.iter().position(|o| *o == "workload.start");
    let destroyed = operations.iter().position(|o| *o == "environment.destroy");
    assert!(started < destroyed, "{operations:?}");
    assert_eq!(fx.fake.states_of(&environment).1, "REAPED");
    let Dispatched::Parked(parked) = dispatched else {
        panic!("a started launch is parked")
    };
    let _ = fx.settle(parked);
}

#[test]
fn f02_a_revocation_waits_for_a_decided_start_and_withholds_what_it_produced() {
    let meantime = Meantime::default();
    let mut fx = launcher_at(&meantime, CrashPoint::WorkloadAfterIntent);
    delegated(&mut fx);
    let run = fx.run("r1", &[GRANT]);
    let _environment = fx.ready(&run);
    fx.fake.running(1);
    let other = fx.authority().handle().unwrap();
    let session = fx.session.clone();
    let (tx, rx) = mpsc::channel();
    meantime.then(move || tx.send(revoke_delegate(other, &session)).unwrap());
    let dispatched = fx.exec(&run, "w1", &call(FIXTURE, &["workload-daemon"]));
    meantime.join();
    let report = rx.recv().unwrap().unwrap();
    assert!(
        meantime.held(),
        "the revocation's first phase began while a start stood decided"
    );
    let starts = fx.fake.asked_for("workload.start");
    assert_eq!(starts.len(), 1);
    assert_eq!(
        starts[0].active_runs, 1,
        "the start reached the broker after the revocation reaped its run"
    );
    // ADR-0063's two phases, as for any running workload: the environment's
    // destruction ordered after the start, the report REVOKED while the
    // workload is unsettled, and the revoked run told nothing it produced.
    assert_eq!((report.leases_invalidated, report.runs_reaped), (1, 1));
    assert_eq!(report.status, RevocationStatus::Revoked);
    let Dispatched::Parked(parked) = dispatched else {
        panic!("a started launch is parked")
    };
    let body = fx.settle(parked);
    assert_eq!(failed(&body).0, F::OutcomeUnknown);
    let report = fx
        .authority()
        .revocation_status(report.revocation)
        .unwrap()
        .unwrap();
    assert_eq!(report.status, RevocationStatus::Complete);
}

/// Racing invocations under one key, on two handles: the decision's
/// transaction binds the key, so exactly one is performed -- whatever the
/// other asks, the same payload or another -- and the other is refused.
#[test]
fn f02_racing_invocations_under_one_key_are_one_effect() {
    let mut fx = writer_at(&Meantime::default(), CrashPoint::ToolAfterIntent);
    let run = fx.run("r1", WRITES);
    let caller = fx.caller.unwrap();
    for round in 0..8 {
        let key = format!("k{round}");
        let messages = [
            fx.message(
                &run,
                2,
                "direwolf.tool.invoke",
                Some(&key),
                &write("/workspace/a.txt"),
            ),
            fx.message(
                &run,
                2,
                "direwolf.tool.invoke",
                Some(&key),
                &write(&format!("/workspace/other-{round}.txt")),
            ),
        ];
        let before = fx.fake.asked_for("fs.write").len();
        let barrier = Arc::new(Barrier::new(2));
        let answers = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = messages
            .into_iter()
            .map(|message| {
                let mut handle = fx.authority().handle().unwrap();
                let (barrier, answers) = (Arc::clone(&barrier), Arc::clone(&answers));
                std::thread::spawn(move || {
                    barrier.wait();
                    let body = handle.dispatch(&caller, &message).unwrap();
                    answers.lock().unwrap().push(body);
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let answers = answers.lock().unwrap();
        let done = answers
            .iter()
            .filter(|b| matches!(b, DwkpBody::ToolResultV2(_)))
            .count();
        let reused = answers
            .iter()
            .filter(|b| matches!(b, DwkpBody::ToolRefusedV2(r) if format!("{:?}", r.reason) == "IdempotencyKeyReused"))
            .count();
        assert_eq!((done, reused), (1, 1), "round {round}: {answers:?}");
        assert_eq!(fx.fake.asked_for("fs.write").len(), before + 1);
    }
}

// ---------------------------------------------------------------------------
// The other direction: an end of authority stopped inside its section,
// before its transaction, while the holder asks for a write on another
// handle. The write must wait at the gate -- it is not even decided -- and,
// decided after the end, is refused with nothing sent. An end that left its
// section before its transaction, or never entered one, lets the write be
// decided first and handed over after the end commits.
// ---------------------------------------------------------------------------

/// The two threads' holds: the end's, before its transaction; the write's,
/// after its intent.
struct Holds {
    ending: Arc<Hold>,
    effect: Arc<Hold>,
}

fn writer_with_holds() -> (Fixture, Holds) {
    let holds = Holds {
        ending: Arc::default(),
        effect: Arc::default(),
    };
    let hook = Hold::hook(vec![Arc::clone(&holds.ending), Arc::clone(&holds.effect)]);
    let mut fx = Fixture::with_declared(writing(), Some(hook), WRITES);
    fx.attach(IMAGE);
    (fx, holds)
}

fn a_write_waits_while_an_end_stands_before_its_transaction(
    fx: &mut Fixture,
    holds: &Holds,
    run: &RunId,
    end: impl FnOnce() + Send + 'static,
    before_release: impl FnOnce(),
) {
    let gate = fx.authority().gate();
    let ending_hold = Arc::clone(&holds.ending);
    let ending = std::thread::spawn(move || {
        ending_hold.arm_here(CrashPoint::BeforeTransaction);
        end();
    });
    until("the end stands before its transaction", || {
        holds.ending.reached()
    });
    let mut handle = fx.authority().handle().unwrap();
    let caller = fx.caller.unwrap();
    let message = fx.message(
        run,
        2,
        "direwolf.tool.invoke",
        Some("held"),
        &write("/workspace/held.txt"),
    );
    let effect_hold = Arc::clone(&holds.effect);
    let effect = std::thread::spawn(move || {
        effect_hold.arm_here(CrashPoint::ToolAfterIntent);
        handle.dispatch(&caller, &message).unwrap()
    });
    until("the write waits at the gate, or stands decided", || {
        gate.effects_waiting() == 1 || holds.effect.reached()
    });
    let waited = gate.effects_waiting() == 1 && !holds.effect.reached();
    before_release();
    holds.ending.release();
    ending.join().unwrap();
    // A write decided before the end -- only an end outside its section
    // allows one -- goes on now, after the end has committed.
    holds.effect.release();
    let body = effect.join().unwrap();
    assert!(
        fx.fake.asked_for("fs.write").is_empty(),
        "a write decided beside an end of authority reached the broker after it: {:?}",
        fx.fake.asked_for("fs.write")
    );
    assert!(
        waited,
        "a write began while an end of authority stood in its section"
    );
    assert!(matches!(body, DwkpBody::ToolRefusedV2(_)), "{body:?}");
}

#[test]
fn f02_a_run_release_holds_its_section_through_its_transaction() {
    let (mut fx, holds) = writer_with_holds();
    let run = fx.run("r1", WRITES);
    let mut other = fx.authority().handle().unwrap();
    let (caller, session, epoch, released) = (
        fx.caller.unwrap(),
        fx.session.clone(),
        fx.epoch,
        run.clone(),
    );
    let end = move || {
        let reply = other
            .release_run(&caller, &session, &released, epoch)
            .unwrap();
        assert!(matches!(reply, Reply::Done(())), "{reply:?}");
    };
    a_write_waits_while_an_end_stands_before_its_transaction(&mut fx, &holds, &run, end, || {});
    assert_eq!(
        refused_as(&fx.tool(&run, "after", &write("/workspace/b.txt"))),
        "UnknownRun"
    );
}

#[test]
fn f02_a_lease_release_holds_its_section_through_its_transaction() {
    let (mut fx, holds) = writer_with_holds();
    let run = fx.run("r1", WRITES);
    let mut other = fx.authority().handle().unwrap();
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    let end = move || {
        let reply = other.release_lease(&caller, &session, epoch).unwrap();
        assert!(matches!(reply, Reply::Done(())), "{reply:?}");
    };
    a_write_waits_while_an_end_stands_before_its_transaction(&mut fx, &holds, &run, end, || {});
}

#[test]
fn f02_a_takeover_holds_its_section_through_its_transaction() {
    let (mut fx, holds) = writer_with_holds();
    let run = fx.run("r1", WRITES);
    let mut other = fx.authority().handle().unwrap();
    let session = fx.session.clone();
    let clock = Arc::clone(&fx.clock);
    let end = move || {
        let caller = other.connect(AuthenticatedSubject::unix_uid(1000));
        let reply = other.acquire_lease(&caller, &session).unwrap();
        assert!(matches!(reply, Reply::Done(_)), "{reply:?}");
    };
    // The old holder's lease expires only once the takeover stands in its
    // section: a write decided before then would be the old tenure's.
    let expire = move || clock.advance(DEFAULT_LEASE_TTL_MS + 1);
    a_write_waits_while_an_end_stands_before_its_transaction(&mut fx, &holds, &run, end, expire);
}

#[test]
fn f02_a_revocation_holds_its_section_through_its_first_phase() {
    let (mut fx, holds) = writer_with_holds();
    delegated(&mut fx);
    let run = fx.run("r1", WRITES);
    let other = fx.authority().handle().unwrap();
    let session = fx.session.clone();
    let end = move || {
        let report = revoke_delegate(other, &session).unwrap();
        assert_eq!(report.runs_reaped, 1);
    };
    a_write_waits_while_an_end_stands_before_its_transaction(&mut fx, &holds, &run, end, || {});
}
