//! M6.2 (ADR-0080, Proposed): the approval registry through the real
//! authority and store -- runs admitted over the in-process dispatcher, the
//! sandboxed `process.exec` route, the real policy engine, the real binding,
//! the real transactions and audit -- with the route tests' fake broker,
//! which runs nothing.
//!
//! Decisions are made through the registry's own state machine
//! (`Authority::decide_approval`), the seam M6.3's approver operations will
//! call; the approver set is attached by `Authority::attach_approvers`, which
//! exists in test builds only. Nothing here is an approval operation a
//! runtime, a DWKP peer or the approver endpoint can reach.
//!
//! Each `APPROVAL-EVIDENCE` line is printed only after the assertions before
//! it held; `make approval-registry-evidence` requires every case.

use std::sync::Barrier;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use super::*;
use crate::state::DEFAULT_LEASE_TTL_MS;
use crate::state::approvals::{ApproverDecision, Assurance, DecisionRefused};
use crate::state::interleave::{Hold, Meantime, until};

/// An operator's approver: never a runtime's uid (ADR-0067).
const APPROVER: u32 = 2001;

/// The runtime's uid in every fixture.
const RUNTIME: u32 = 1000;

/// One line of the registry's evidence, after its assertions.
fn approval_evidence(case: &str, outcome: &str) {
    println!(
        "APPROVAL-EVIDENCE {{\"suite\":\"authority-approval-registry\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// A sandboxed launch of the fixture needs an approval: exact action, this
/// TTL and use limit. **Not** a shipped pack.
fn approval_policy(max_uses: u32, ttl: &str) -> PolicySet {
    scoped_policy("exact_action", max_uses, ttl)
}

/// [`approval_policy`] under another scope.
fn scoped_policy(scope: &str, max_uses: u32, ttl: &str) -> PolicySet {
    PolicySet {
        profile: "m62".to_owned(),
        sources: vec![PolicySource {
            name: "m62.toml".to_owned(),
            text: format!(
                r#"schema_version = 1

[meta]
name = "m62"

[[rule]]
id = "approve-fixture"
effect = "REQUIRE_APPROVAL"
reason = "SENSITIVE_PATH"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["fixture"]
approval.scope = "{scope}"
approval.ttl = "{ttl}"
approval.max_uses = {max_uses}

[[rule]]
id = "allow-sandbox-exec"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#
            ),
        }],
    }
}

fn approval_fixture_with(
    max_uses: u32,
    ttl: &str,
    hook: Option<CrashHook>,
    approvers: &[u32],
) -> Fixture {
    let mut fx = Fixture::with(approval_policy(max_uses, ttl), hook);
    fx.attach(IMAGE);
    assert!(fx.authority().attach_approvers(approvers));
    fx
}

fn approval_fixture(max_uses: u32) -> Fixture {
    approval_fixture_with(max_uses, "10m", None, &[APPROVER])
}

/// A run with a `READY` environment.
fn ready_run(fx: &mut Fixture, key: &str) -> RunId {
    let run = fx.run(key, &[GRANT]);
    fx.ready(&run);
    run
}

/// A `READY` run whose taint is already at its plateau: one allowed launch's
/// output has reached it (`LOCAL_UNVERIFIED`, ADR-0062). The run's taint is
/// a bound member (ADR-0079), so an approval asked for before a launch's
/// output raised it binds a world that no longer is; asked for after, the
/// same launch binds the same bytes every time.
fn warm_run(fx: &mut Fixture, key: &str) -> RunId {
    let run = ready_run(fx, key);
    let warm = format!("warm-up-{key}");
    assert!(ran_or_denied(&fx.ran(&run, &warm, &call(HYGIENIC, &[]))));
    let rank = fx.count(&format!(
        "SELECT taint FROM run_policy_input WHERE run_id = '{}'",
        run.as_str()
    ));
    assert!(rank > 0, "the warm-up's output tainted the run: {rank}");
    run
}

fn launch() -> String {
    call(FIXTURE, &["--approved"])
}

fn grant(approver: u32) -> ApproverDecision {
    ApproverDecision::Grant {
        approver: AuthenticatedSubject::unix_uid(approver),
        assurance: Assurance::A1,
    }
}

impl Fixture {
    /// Move the clock on by `ms`, the lease kept alive by heartbeats: a
    /// lease lives one TTL without one, and an expired lease fences every
    /// launch before the registry is asked.
    fn tick(&mut self, mut ms: u64) {
        while ms > 0 {
            let (caller, session, epoch) = (self.caller.unwrap(), self.session.clone(), self.epoch);
            let beat = self
                .authority()
                .heartbeat(&caller, &session, epoch)
                .unwrap();
            assert!(matches!(beat, Reply::Done(())), "{beat:?}");
            let step = ms.min(DEFAULT_LEASE_TTL_MS >> 1);
            self.clock.advance(step);
            ms -= step;
        }
    }

    fn strings(&self, sql: &str) -> Vec<String> {
        let db = self.db();
        let mut statement = db.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    }

    /// The pending requests, oldest first.
    fn pending(&self) -> Vec<String> {
        self.strings(
            "SELECT request_id FROM approval_request WHERE state = 'PENDING' \
             ORDER BY requested_ms, request_id",
        )
    }

    /// The approval's `(uses, state)`.
    fn approval(&self, approval: &str) -> (i64, String) {
        self.db()
            .query_row(
                "SELECT uses, state FROM approval WHERE approval_id = ?1",
                [approval],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    /// The audit log's approval events, in order.
    fn approval_events(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|e| e.starts_with("approval."))
            .collect()
    }

    /// Deny a launch that needs an approval, then grant its one request.
    fn requested_and_granted(&mut self, run: &RunId, key: &str) -> String {
        let body = self.answered(run, key, &launch());
        let (_, reason, rule) = denied(&body);
        assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
        assert_eq!(rule, "approve-fixture");
        let pending = self.pending();
        assert_eq!(pending.len(), 1, "one request");
        self.authority()
            .decide_approval(&pending[0], grant(APPROVER))
            .unwrap()
            .unwrap()
            .unwrap()
    }
}

/// A launch's answer: `true` if it ran, `false` if denied.
fn ran_or_denied(body: &DwkpBody) -> bool {
    match body {
        DwkpBody::ToolResultV5(_) => true,
        DwkpBody::ToolDeniedV5(_) => false,
        other => panic!("neither ran nor denied: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The lifecycle.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_launch_needing_approval_is_requested_once_denied_and_nothing_runs() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    for key in ["k1", "k2", "k3"] {
        let (_, reason, _) = denied(&fx.answered(&run, key, &launch()));
        assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    }
    assert_eq!(fx.pending().len(), 1, "one pending request per binding");
    assert_eq!(fx.approval_events(), ["approval.requested"], "audited once");
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0, "nothing ran");
    assert_eq!(
        fx.count("SELECT count(*) FROM approval"),
        0,
        "nothing granted"
    );
    assert!(fx.fake.asked_for("workload.start").is_empty());
    // Another call is another binding, and another request.
    denied(&fx.answered(&run, "k4", &call(FIXTURE, &["--other"])));
    assert_eq!(fx.pending().len(), 2);
    approval_evidence("request-recorded-once-nothing-runs", "1-request+denied");
}

#[test]
fn m6_2_a_granted_approval_is_spent_once_with_its_intent_and_never_again() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k1");
    assert_eq!(fx.approval(&approval), (0, "OPEN".to_owned()));
    let body = fx.ran(&run, "k2", &launch());
    let (plan, _) = result(&body);
    assert_eq!(plan.effect, DecisionEffect::Allow, "approved, so allowed");
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    assert_eq!(fx.approval(&approval), (1, "EXHAUSTED".to_owned()));
    // The use names the launch's own intent.
    let linked = fx.strings(
        "SELECT u.invocation_id FROM approval_use u JOIN workload w \
         ON w.invocation_id = u.invocation_id AND w.run_id = u.run_id",
    );
    assert_eq!(linked.len(), 1, "the use names its intent");
    // Spent: the same launch again is denied and asks again.
    assert!(!ran_or_denied(&fx.answered(&run, "k3", &launch())));
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1, "never twice");
    assert_eq!(fx.pending().len(), 1, "a new request");
    assert_eq!(
        fx.approval_events(),
        [
            "approval.requested",
            "approval.granted",
            "approval.used",
            "approval.requested"
        ]
    );
    approval_evidence("granted-spent-once-with-its-intent", "1-use+exhausted");
}

#[test]
fn m6_2_a_k_use_approval_is_spent_k_times_and_no_more() {
    let mut fx = approval_fixture(3);
    let run = warm_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    let ran: Vec<bool> = (1..=5)
        .map(|n| ran_or_denied(&fx.ran(&run, &format!("k{n}"), &launch())))
        .collect();
    assert_eq!(ran, [true, true, true, false, false]);
    assert_eq!(fx.approval(&approval), (3, "EXHAUSTED".to_owned()));
    assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 3);
    // The warm-up, and three uses.
    assert_eq!(fx.fake.asked_for("workload.start").len(), 4);
    approval_evidence("k-uses-and-no-more", "3-of-5");
}

#[test]
fn m6_2_a_run_whose_taint_rose_spends_nothing_granted_below_it() {
    // Granted while the run was clean; the first use's output taints it.
    let mut fx = approval_fixture(3);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    let bound = fx.one("SELECT binding_sha256 FROM approval_request");
    assert!(ran_or_denied(&fx.ran(&run, "k1", &launch())));
    // The same call is another binding now: denied, a new request, nothing
    // spent -- the approval stays open for the world it was granted in.
    assert!(!ran_or_denied(&fx.answered(&run, "k2", &launch())));
    assert_eq!(fx.approval(&approval), (1, "OPEN".to_owned()));
    let pending = fx.strings("SELECT binding_sha256 FROM approval_request WHERE state = 'PENDING'");
    assert_eq!(pending.len(), 1);
    assert_ne!(pending[0], bound, "the run's taint is bound");
    approval_evidence("taint-rise-is-another-binding", "denied+new-request");
}

// ---------------------------------------------------------------------------
// Concurrency: separate handles, real transactions.
// ---------------------------------------------------------------------------

/// `contenders` handles launch the approved action at once; each answer.
///
/// Each handle waits up to two minutes for the store's write lock, not the
/// five seconds a production handle waits before answering `Busy`
/// (fail-closed, spending nothing): the property here is which of the
/// contenders, all of them decided, spends -- and the production server's
/// one worker never contends with itself.
fn contend(fx: &mut Fixture, run: &RunId, contenders: usize, round: usize) -> Vec<DwkpBody> {
    let caller = fx.caller.unwrap();
    let barrier = Arc::new(Barrier::new(contenders));
    let threads: Vec<_> = (0..contenders)
        .map(|n| {
            let message = fx.message(
                run,
                5,
                "direwolf.tool.invoke",
                Some(&format!("c{round}-{n}")),
                &format!(r#"{{"process_exec":{}}}"#, launch()),
            );
            let mut handle = fx.authority().handle().unwrap();
            handle
                .conn
                .busy_timeout(std::time::Duration::from_secs(120))
                .unwrap();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                match handle.dispatch_parkable(&caller, &message).unwrap() {
                    Dispatched::Answer(body) => body,
                    Dispatched::Parked(mut parked) => (0..1000)
                        .find_map(|_| handle.resume(&mut parked).unwrap())
                        .expect("a parked launch ends"),
                }
            })
        })
        .collect();
    threads.into_iter().map(|t| t.join().unwrap()).collect()
}

#[test]
fn m6_2_of_a_hundred_concurrent_contenders_exactly_one_spends_a_single_use() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    let answers = contend(&mut fx, &run, 100, 0);
    let ran = answers
        .iter()
        .filter(|b| matches!(b, DwkpBody::ToolResultV5(_)))
        .count();
    let denied = answers
        .iter()
        .filter(|b| matches!(b, DwkpBody::ToolDeniedV5(_)))
        .count();
    assert_eq!(ran, 1, "one winner");
    assert_eq!(
        ran + denied
            + answers
                .iter()
                .filter(|b| matches!(b, DwkpBody::ToolRefusedV5(_)))
                .count(),
        100
    );
    assert_eq!(fx.approval(&approval), (1, "EXHAUSTED".to_owned()));
    assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 1, "one use");
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 1, "one intent");
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1, "one start");
    assert_eq!(
        fx.approval_events()
            .iter()
            .filter(|e| *e == "approval.used")
            .count(),
        1,
        "one successful use audited"
    );
    approval_evidence("single-use-100-contenders", "1-winner");
}

#[test]
fn m6_2_concurrent_contenders_never_spend_more_than_k_uses() {
    let mut fx = approval_fixture(5);
    let run = warm_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    let mut ran = 0;
    for round in 0..40 {
        let answers = contend(&mut fx, &run, 8, round);
        ran += answers
            .iter()
            .filter(|b| matches!(b, DwkpBody::ToolResultV5(_)))
            .count();
        let (uses, _) = fx.approval(&approval);
        assert!(uses <= 5, "never past its limit: {uses}");
        if uses == 5 {
            break;
        }
    }
    assert_eq!(ran, 5);
    assert_eq!(fx.approval(&approval), (5, "EXHAUSTED".to_owned()));
    assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 5);
    // The warm-up, and five uses.
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 6);
    approval_evidence("multi-use-contended", "5-of-5");
}

// ---------------------------------------------------------------------------
// Life: the exact boundary, and the clock moving back.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_an_approval_is_spent_before_its_instant_never_at_it_and_never_again() {
    let mut fx = approval_fixture_with(5, "1m", None, &[APPROVER]);
    let run = warm_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    fx.tick(59_999);
    assert!(
        ran_or_denied(&fx.ran(&run, "k1", &launch())),
        "a millisecond before"
    );
    fx.tick(1);
    assert!(
        !ran_or_denied(&fx.answered(&run, "k2", &launch())),
        "at the instant"
    );
    assert_eq!(fx.approval(&approval).1, "EXPIRED");
    // The clock moved back: still expired, durably.
    fx.clock.set(START_MS);
    assert!(!ran_or_denied(&fx.answered(&run, "k3", &launch())));
    assert_eq!(fx.approval(&approval), (1, "EXPIRED".to_owned()));
    let events = fx.approval_events();
    assert!(events.contains(&"approval.expired".to_owned()));
    assert!(
        !events.contains(&"approval.denied".to_owned()),
        "expiry is not a denial"
    );
    approval_evidence("expiry-exact-and-durable", "expired-at-the-instant");
}

#[test]
fn m6_2_a_clock_moved_back_never_revives_a_passed_instant() {
    let mut fx = approval_fixture_with(5, "1m", None, &[APPROVER]);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    // Another registry transaction, past the approval's life, raises the
    // registry's clock -- the approval itself not yet looked at.
    fx.tick(120_000);
    denied(&fx.answered(&run, "k1", &call(FIXTURE, &["--another"])));
    // The host clock goes back inside the life: the registry's does not.
    fx.clock.set(START_MS + 1_000);
    assert!(!ran_or_denied(&fx.answered(&run, "k2", &launch())));
    assert_eq!(fx.approval(&approval).1, "EXPIRED");
    approval_evidence("clock-rollback-refused", "high-water");
}

// ---------------------------------------------------------------------------
// Decisions: who may decide, and once.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2() {
    let mut fx = approval_fixture_with(1, "10m", None, &[APPROVER, RUNTIME]);
    let run = ready_run(&mut fx, "r1");
    denied(&fx.answered(&run, "k1", &launch()));
    let request = fx.pending()[0].clone();
    let decide = |fx: &mut Fixture, decision: ApproverDecision| {
        fx.authority().decide_approval(&request, decision).unwrap()
    };
    assert_eq!(
        decide(&mut fx, grant(RUNTIME)),
        Err(DecisionRefused::SelfApproval)
    );
    assert_eq!(
        decide(&mut fx, grant(3000)),
        Err(DecisionRefused::UnknownApprover)
    );
    assert_eq!(
        decide(
            &mut fx,
            ApproverDecision::Grant {
                approver: AuthenticatedSubject::unix_uid(APPROVER),
                assurance: Assurance::A2,
            }
        ),
        Err(DecisionRefused::AssuranceUnavailable),
        "no presence factor exists: A2 is never recorded"
    );
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 0);
    let denial = ApproverDecision::Deny {
        approver: AuthenticatedSubject::unix_uid(APPROVER),
    };
    assert_eq!(decide(&mut fx, denial), Ok(None));
    assert_eq!(
        decide(&mut fx, grant(APPROVER)),
        Err(DecisionRefused::NotPending),
        "once"
    );
    assert!(
        !ran_or_denied(&fx.answered(&run, "k2", &launch())),
        "a denial spends nothing"
    );
    assert_eq!(
        fx.authority()
            .decide_approval(&"0".repeat(64), grant(APPROVER))
            .unwrap(),
        Err(DecisionRefused::UnknownRequest)
    );
    assert!(fx.approval_events().contains(&"approval.denied".to_owned()));
    approval_evidence("decision-refusals", "self+unknown+a2+once");
}

#[test]
fn m6_2_without_an_attached_approver_set_nothing_is_decided_or_spent() {
    // The shipped build attaches no set: no approval can be decided.
    let mut fx = Fixture::new(approval_policy(1, "10m"));
    fx.attach(IMAGE);
    let run = ready_run(&mut fx, "r1");
    denied(&fx.answered(&run, "k1", &launch()));
    let request = fx.pending()[0].clone();
    assert_eq!(
        fx.authority()
            .decide_approval(&request, grant(APPROVER))
            .unwrap(),
        Err(DecisionRefused::UnknownApprover)
    );
    approval_evidence("no-approver-set-no-decision", "unknown-approver");
}

// ---------------------------------------------------------------------------
// Drift, revocation, restart.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_call_asked_again_under_another_binding_is_drift_and_spends_nothing() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k1");
    // The same key, another argument: another binding.
    assert!(!ran_or_denied(&fx.answered(
        &run,
        "k1",
        &call(FIXTURE, &["--changed"])
    )));
    assert!(
        fx.approval_events()
            .contains(&"approval.drift_detected".to_owned())
    );
    assert_eq!(
        fx.approval(&approval),
        (0, "OPEN".to_owned()),
        "nothing spent"
    );
    // The approved binding itself still runs.
    assert!(ran_or_denied(&fx.ran(&run, "k1", &launch())));
    approval_evidence("drift-detected", "denied+untouched");
}

#[test]
fn m6_2_a_revoked_approval_is_never_spent() {
    let mut fx = approval_fixture(3);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    assert!(fx.authority().revoke_approval(&approval).unwrap());
    assert!(!fx.authority().revoke_approval(&approval).unwrap(), "once");
    assert!(!ran_or_denied(&fx.answered(&run, "k1", &launch())));
    assert_eq!(fx.approval(&approval), (0, "REVOKED".to_owned()));
    assert!(
        fx.approval_events()
            .contains(&"approval.revoked".to_owned())
    );
    approval_evidence("revoked-never-spent", "denied");
}

#[test]
fn m6_2_a_restart_leaves_no_approval_spendable() {
    let mut fx = approval_fixture(3);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    fx.restart(Some(IMAGE));
    assert!(fx.authority().attach_approvers(&[APPROVER]));
    // A new incarnation and a new tenure: the run was reaped with the old
    // one, and fenced before the registry is asked.
    assert_eq!(refused(&fx.answered(&run, "k1", &launch())), R::UnknownRun);
    // A run of the new tenure binds another run: the old approval is not its.
    let again = ready_run(&mut fx, "r2");
    assert!(!ran_or_denied(&fx.answered(&again, "k2", &launch())));
    assert_eq!(
        fx.approval(&approval),
        (0, "OPEN".to_owned()),
        "nothing spent"
    );
    assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 0);
    approval_evidence("restart-refused", "nothing-spent");
}

// ---------------------------------------------------------------------------
// Crashes inside and after the intent transaction.
// ---------------------------------------------------------------------------

/// A hook that, once armed, stops at `point` -- the first one at or after
/// `marker`, or, with no marker, the first one at all. Every generic point --
/// a commit, the audit outbox's steps -- is crossed by every transaction;
/// counting from a registry point makes each window that transaction's.
fn stop_after(marker: Option<CrashPoint>, point: CrashPoint) -> (CrashHook, Arc<AtomicBool>) {
    let armed = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicBool::new(marker.is_none()));
    let (on, past) = (Arc::clone(&armed), Arc::clone(&seen));
    let hook: CrashHook = Arc::new(move |at| {
        if !on.load(Ordering::SeqCst) {
            return HookAction::Continue;
        }
        if Some(at) == marker {
            past.store(true, Ordering::SeqCst);
        }
        if past.load(Ordering::SeqCst) && at == point {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    (hook, armed)
}

/// [`stop_after`] the use's own crash point: each window the intent's.
fn after_the_use(point: CrashPoint) -> (CrashHook, Arc<AtomicBool>) {
    stop_after(Some(CrashPoint::ApprovalBeforeUse), point)
}

/// Each window of an approved launch, and what a restart finds: `None` --
/// neither the use nor its intent; or both, the workload in that state.
const CRASH_WINDOWS: [(CrashPoint, Option<&str>); 11] = [
    (CrashPoint::ApprovalBeforeUse, None),
    (CrashPoint::BeforeCommit, None),
    (CrashPoint::AfterCommitBeforeAudit, Some("UNKNOWN")),
    (CrashPoint::MidAuditRecord, Some("UNKNOWN")),
    (CrashPoint::AfterAuditWriteBeforeSync, Some("UNKNOWN")),
    (CrashPoint::AfterAuditSyncBeforeMark, Some("UNKNOWN")),
    (CrashPoint::AfterAuditMark, Some("UNKNOWN")),
    (CrashPoint::WorkloadAfterIntent, Some("UNKNOWN")),
    (CrashPoint::WorkloadAfterStart, Some("UNKNOWN")),
    (CrashPoint::WorkloadAfterBroker, Some("UNKNOWN")),
    (CrashPoint::WorkloadAfterOutcome, Some("COMPLETED")),
];

#[test]
fn m6_2_a_crash_in_every_window_of_a_spend_leaves_both_or_neither_and_spends_once() {
    for (point, after) in CRASH_WINDOWS {
        let (hook, armed) = after_the_use(point);
        let mut fx = approval_fixture_with(1, "10m", Some(hook), &[APPROVER]);
        let run = ready_run(&mut fx, "r1");
        let approval = fx.requested_and_granted(&run, "k0");
        armed.store(true, Ordering::SeqCst);
        let message = fx.message(
            &run,
            5,
            "direwolf.tool.invoke",
            Some("k1"),
            &format!(r#"{{"process_exec":{}}}"#, launch()),
        );
        let caller = fx.caller.unwrap();
        let stopped = match fx.authority().dispatch_parkable(&caller, &message) {
            Err(_) => true,
            Ok(Dispatched::Parked(mut parked)) => {
                (0..10).any(|_| fx.authority().resume(&mut parked).is_err())
            }
            Ok(Dispatched::Answer(body)) => panic!("{point}: answered {body:?}"),
        };
        assert!(stopped, "{point}: the hook stopped it");
        armed.store(false, Ordering::SeqCst);
        let starts = fx.fake.asked_for("workload.start").len();
        fx.restart(Some(IMAGE));
        assert!(fx.authority().attach_approvers(&[APPROVER]));
        let spent = i64::from(after.is_some());
        assert_eq!(
            fx.count("SELECT count(*) FROM approval_use"),
            spent,
            "{point}: the use"
        );
        assert_eq!(
            fx.count("SELECT count(*) FROM workload"),
            spent,
            "{point}: its intent"
        );
        if let Some(state) = after {
            assert_eq!(
                fx.strings(
                    "SELECT w.state FROM workload w JOIN approval_use u                      ON u.invocation_id = w.invocation_id AND u.run_id = w.run_id"
                ),
                [state],
                "{point}: the use names its intent"
            );
            assert_eq!(
                fx.approval(&approval),
                (1, "EXHAUSTED".to_owned()),
                "{point}"
            );
        } else {
            assert_eq!(fx.approval(&approval), (0, "OPEN".to_owned()), "{point}");
            assert_eq!(starts, 0, "{point}: nothing reached the broker");
        }
        // The audit log agrees with the store: the use recorded once, never
        // lost and never replayed twice.
        crate::state::verify_audit_log(&fx.state().join("audit.log")).unwrap();
        let used = fx
            .approval_events()
            .iter()
            .filter(|e| *e == "approval.used")
            .count();
        assert_eq!(i64::try_from(used).unwrap(), spent, "{point}: audited once");
        // Never run again: the same key on a run of the new tenure starts
        // nothing, and nothing is spent.
        let again = ready_run(&mut fx, "r2");
        assert!(
            !matches!(
                fx.answered(&again, "k1", &launch()),
                DwkpBody::ToolResultV5(_)
            ),
            "{point}"
        );
        assert_eq!(fx.fake.asked_for("workload.start").len(), starts, "{point}");
        assert_eq!(
            fx.count("SELECT count(*) FROM approval_use"),
            spent,
            "{point}"
        );
    }
    approval_evidence("crash-windows", "11-both-or-neither");
}

// ---------------------------------------------------------------------------
// Revocation against a spend: ADR-0064's gate.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_revocation_waits_for_a_decided_spend_and_wins_against_a_later_one() {
    let hold = Arc::new(Hold::default());
    let mut fx = approval_fixture_with(
        2,
        "10m",
        Some(Hold::hook(vec![Arc::clone(&hold)])),
        &[APPROVER],
    );
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    let caller = fx.caller.unwrap();
    let message = fx.message(
        &run,
        5,
        "direwolf.tool.invoke",
        Some("k1"),
        &format!(r#"{{"process_exec":{}}}"#, launch()),
    );
    let mut spender = fx.authority().handle().unwrap();
    let spender_hold = Arc::clone(&hold);
    let spend = std::thread::spawn(move || {
        spender_hold.arm_here(CrashPoint::ApprovalBeforeUse);
        match spender.dispatch_parkable(&caller, &message).unwrap() {
            Dispatched::Answer(body) => body,
            Dispatched::Parked(mut parked) => (0..1000)
                .find_map(|_| spender.resume(&mut parked).unwrap())
                .expect("a parked launch ends"),
        }
    });
    until("the spend stands inside its transaction", || hold.reached());
    let gate = fx.authority().gate();
    let mut revoker = fx.authority().handle().unwrap();
    let target = approval.clone();
    let revoke = std::thread::spawn(move || revoker.revoke_approval(&target).unwrap());
    until("the revocation waits at the gate", || {
        gate.endings_waiting() == 1
    });
    hold.release();
    assert!(
        ran_or_denied(&spend.join().unwrap()),
        "the decided spend goes on"
    );
    assert!(revoke.join().unwrap(), "then the revocation ends it");
    assert_eq!(fx.approval(&approval), (1, "REVOKED".to_owned()));
    // After the revocation, nothing more is spent.
    assert!(!ran_or_denied(&fx.answered(&run, "k2", &launch())));
    assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 1);
    approval_evidence("revocation-spend-race", "spend-then-revoke");
}

// ---------------------------------------------------------------------------
// The database's own refusals, on a real store.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_the_registry_tables_refuse_what_no_guard_would_write() {
    let mut fx = approval_fixture(2);
    let run = ready_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    assert!(ran_or_denied(&fx.ran(&run, "k1", &launch())));
    // A settled intent of the run that spent nothing: an allowed launch.
    assert!(ran_or_denied(&fx.ran(&run, "w2", &call(HYGIENIC, &[]))));
    let db = fx.db();
    let request: String = db
        .query_row(
            "SELECT request_id FROM approval WHERE approval_id = ?1",
            [&approval],
            |row| row.get(0),
        )
        .unwrap();
    let refused = |sql: &str| {
        assert!(db.execute_batch(sql).is_err(), "{sql}");
    };
    refused(&format!(
        "UPDATE approval SET uses = 2 WHERE approval_id = '{approval}'"
    ));
    refused(&format!(
        "UPDATE approval SET max_uses = 9 WHERE approval_id = '{approval}'"
    ));
    refused(&format!(
        "UPDATE approval_request SET state = 'PENDING', decided_ms = NULL WHERE request_id = '{request}'"
    ));
    refused(&format!(
        "UPDATE approval_request SET requester = 'uid:7' WHERE request_id = '{request}'"
    ));
    refused(&format!(
        "DELETE FROM approval WHERE approval_id = '{approval}'"
    ));
    refused("DELETE FROM approval_use");
    refused("UPDATE approval_use SET seq = 9");
    refused("DELETE FROM approval_request");
    refused("UPDATE approval_clock SET high_water_ms = 0");
    // A second approval for the decided request.
    refused(&format!(
        "INSERT INTO approval (approval_id, request_id, approver, channel, assurance, granted_ms, \
         not_after_ms, max_uses, uses, state) VALUES ('{}', '{request}', 'uid:2001', \
         'APPROVER_ENDPOINT', 'A1', 1, 2, 2, 0, 'OPEN')",
        "e".repeat(64)
    ));
    // A use with no intent at all, and one on an intent of its run that is
    // no longer `LAUNCHING` -- each otherwise in order: its seq next, its
    // action the approval's binding, inside its life. The first is refused
    // by the foreign key and the trigger; the second by the trigger alone.
    let bound: String = db
        .query_row(
            "SELECT binding_sha256 FROM approval_request WHERE request_id = ?1",
            [&request],
            |row| row.get(0),
        )
        .unwrap();
    let settled: String = db
        .query_row(
            "SELECT invocation_id FROM workload WHERE idempotency_key = 'w2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for invocation in [format!("inv_{}", "0".repeat(26)), settled] {
        refused(&format!(
            "INSERT INTO approval_use (approval_id, seq, invocation_id, run_id, action_sha256, \
             used_ms) VALUES ('{approval}', 2, '{invocation}', '{}', '{bound}', {})",
            run.as_str(),
            START_MS + 1
        ));
    }
    // A requester approving its own pending request, otherwise in bounds.
    drop(db);
    denied(&fx.answered(&run, "k2", &call(FIXTURE, &["--pending"])));
    let db = fx.db();
    let pending: String = db
        .query_row(
            "SELECT request_id FROM approval_request WHERE state = 'PENDING'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        db.execute_batch(&format!(
            "INSERT INTO approval (approval_id, request_id, approver, channel, assurance, \
             granted_ms, not_after_ms, max_uses, uses, state) VALUES ('{}', '{pending}', \
             'uid:1000', 'APPROVER_ENDPOINT', 'A1', {}, {}, 2, 0, 'OPEN')",
            "d".repeat(64),
            START_MS + 1,
            START_MS + 2
        ))
        .is_err(),
        "self-approval"
    );
    assert_eq!(fx.approval(&approval), (1, "OPEN".to_owned()), "untouched");
    approval_evidence("database-refuses", "13-writes");
}

#[test]
fn m6_2_the_registrys_audit_links_each_use_and_holds_no_binding_text() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    fx.requested_and_granted(&run, "k0");
    assert!(ran_or_denied(&fx.ran(&run, "k1", &launch())));
    let records = crate::state::read_audit_log(&fx.state().join("audit.log")).unwrap();
    let used: Vec<_> = records
        .iter()
        .filter(|r| r.event() == "approval.used")
        .collect();
    assert_eq!(used.len(), 1);
    let invocation = used[0].text("invocation_id").unwrap().to_owned();
    let intent: Vec<_> = records
        .iter()
        .filter(|r| {
            r.event() == "workload.intent_recorded"
                && r.text("invocation_id") == Some(invocation.as_str())
        })
        .collect();
    assert_eq!(intent.len(), 1, "the use names its intent's record");
    // The registry's records carry ids and digests: neither the binding's
    // members nor the command (the intent's record holds argv, SANDBOX.md
    // §4 -- the approval's never repeats it).
    let log = std::fs::read_to_string(fx.state().join("audit.log")).unwrap();
    let registry: Vec<&str> = log.lines().filter(|l| l.contains("\"approval.")).collect();
    assert_eq!(registry.len(), 3, "requested, granted, used");
    for line in registry {
        for absent in [
            "resource_identity",
            "canonical_args",
            "environment_profile",
            "--approved",
            FIXTURE,
        ] {
            assert!(!line.contains(absent), "{absent} on record: {line}");
        }
    }
    approval_evidence("audit-linked-no-binding-text", "linked");
}

// ---------------------------------------------------------------------------
// What is never asked for, and the bounds on what is.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_launch_without_its_capability_or_under_another_scope_asks_for_nothing() {
    // The run's grant covers another executable: no capability, no request.
    let mut fx = approval_fixture(1);
    let run = fx.run("r1", &["process.exec:/opt/tools/hygienic"]);
    fx.ready(&run);
    let (_, reason, _) = denied(&fx.answered(&run, "k1", &launch()));
    assert_eq!(reason, ProcessDecisionReason::NoCapability);
    assert_eq!(fx.count("SELECT count(*) FROM approval_request"), 0);
    // A rule whose scope is not `exact_action` has no binding the registry
    // can spend in M6.2: it denies as it did before, and asks for nothing.
    let mut fx = Fixture::new(scoped_policy("executable_and_argv", 3, "10m"));
    fx.attach(IMAGE);
    assert!(fx.authority().attach_approvers(&[APPROVER]));
    let run = ready_run(&mut fx, "r1");
    let (_, reason, _) = denied(&fx.answered(&run, "k1", &launch()));
    assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    assert_eq!(fx.count("SELECT count(*) FROM approval_request"), 0);
    assert!(fx.approval_events().is_empty());
    approval_evidence("no-capability-or-other-scope-no-request", "denied");
}

#[test]
fn m6_2_an_approval_by_an_approver_outside_the_set_is_never_spent() {
    // A row the decision seam would never write -- its approver is not one
    // of the operator's -- made raw, as a set changed since, or a forgery
    // the triggers admit, would be.
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    denied(&fx.answered(&run, "k1", &launch()));
    let request = fx.pending()[0].clone();
    let approval = "f".repeat(64);
    let db = fx.db();
    db.execute(
        "INSERT INTO approval (approval_id, request_id, approver, channel, assurance, \
         granted_ms, not_after_ms, max_uses, uses, state) VALUES \
         (?1, ?2, 'uid:3000', 'APPROVER_ENDPOINT', 'A1', ?3, ?4, 1, 0, 'OPEN')",
        rusqlite::params![
            approval,
            request,
            i64::try_from(START_MS).unwrap(),
            i64::try_from(START_MS + 600_000).unwrap()
        ],
    )
    .unwrap();
    db.execute(
        "UPDATE approval_request SET state = 'GRANTED', decided_ms = ?2 WHERE request_id = ?1",
        rusqlite::params![request, i64::try_from(START_MS).unwrap()],
    )
    .unwrap();
    drop(db);
    assert!(!ran_or_denied(&fx.answered(&run, "k2", &launch())));
    assert_eq!(fx.approval(&approval), (0, "OPEN".to_owned()));
    assert!(fx.fake.asked_for("workload.start").is_empty());
    approval_evidence("approver-outside-the-set-never-spent", "denied");
}

#[test]
fn m6_2_a_run_holds_at_most_sixteen_pending_requests() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    for n in 0..20 {
        let arg = format!("--n{n}");
        let (_, reason, _) = denied(&fx.answered(&run, &format!("k{n}"), &call(FIXTURE, &[&arg])));
        assert_eq!(reason, ProcessDecisionReason::ApprovalRequired, "{n}");
    }
    assert_eq!(fx.pending().len(), 16, "the run's bound");
    assert_eq!(
        fx.approval_events()
            .iter()
            .filter(|e| *e == "approval.requested")
            .count(),
        16
    );
    // Another run has a bound of its own.
    let other = ready_run(&mut fx, "r2");
    denied(&fx.answered(&other, "o1", &launch()));
    assert_eq!(fx.pending().len(), 17);
    approval_evidence("pending-bound-per-run", "16");
}

#[test]
fn m6_2_a_request_waits_ten_minutes_at_most_and_then_ends_expired() {
    // A one-hour TTL: the request still waits ten minutes, no more.
    let mut fx = approval_fixture_with(1, "1h", None, &[APPROVER]);
    let run = ready_run(&mut fx, "r1");
    denied(&fx.answered(&run, "k1", &call(FIXTURE, &["--a"])));
    denied(&fx.answered(&run, "k2", &call(FIXTURE, &["--b"])));
    denied(&fx.answered(&run, "k3", &call(FIXTURE, &["--c"])));
    assert_eq!(fx.pending().len(), 3);
    // By the call each was asked for: three made in one millisecond have no
    // order of their own.
    let asked = |fx: &Fixture, key: &str| {
        fx.strings(&format!(
            "SELECT request_id FROM approval_request WHERE idempotency_key = '{key}'"
        ))
        .remove(0)
    };
    let pending = [asked(&fx, "k1"), asked(&fx, "k2")];
    fx.tick(599_999);
    let decided = fx
        .authority()
        .decide_approval(&pending[0], grant(APPROVER))
        .unwrap();
    assert!(decided.is_ok(), "within the window: {decided:?}");
    fx.tick(1);
    assert_eq!(
        fx.authority()
            .decide_approval(&pending[1], grant(APPROVER))
            .unwrap(),
        Err(DecisionRefused::Expired),
        "at the window's end"
    );
    // The same call again, past its window: the old request ends EXPIRED
    // and a new one waits.
    denied(&fx.answered(&run, "k4", &call(FIXTURE, &["--c"])));
    let states = fx.strings("SELECT state FROM approval_request ORDER BY requested_ms, request_id");
    assert_eq!(
        states.iter().filter(|s| *s == "EXPIRED").count(),
        2,
        "{states:?}"
    );
    assert_eq!(fx.pending().len(), 1);
    // The approval granted in the window lives its own TTL: an hour.
    let life = fx.count("SELECT not_after_ms - granted_ms FROM approval");
    assert_eq!(life, 3_600_000);
    approval_evidence("request-window-bounded", "expired-at-ten-minutes");
}

// ---------------------------------------------------------------------------
// The remaining windows: a request recorded, a revocation, and the ends of a
// run's authority beside a spend.
// ---------------------------------------------------------------------------

#[test]
fn m6_2_a_crash_while_a_request_is_recorded_leaves_it_whole_or_absent() {
    for (point, durable) in [
        (CrashPoint::ApprovalBeforeRequest, false),
        (CrashPoint::BeforeCommit, false),
        (CrashPoint::AfterCommitBeforeAudit, true),
        (CrashPoint::MidAuditRecord, true),
        (CrashPoint::AfterAuditSyncBeforeMark, true),
    ] {
        let (hook, armed) = stop_after(Some(CrashPoint::ApprovalBeforeRequest), point);
        let mut fx = approval_fixture_with(1, "10m", Some(hook), &[APPROVER]);
        let run = ready_run(&mut fx, "r1");
        armed.store(true, Ordering::SeqCst);
        let message = fx.message(
            &run,
            5,
            "direwolf.tool.invoke",
            Some("k1"),
            &format!(r#"{{"process_exec":{}}}"#, launch()),
        );
        let caller = fx.caller.unwrap();
        assert!(
            fx.authority().dispatch_parkable(&caller, &message).is_err(),
            "{point}"
        );
        armed.store(false, Ordering::SeqCst);
        fx.restart(Some(IMAGE));
        let n = i64::from(durable);
        assert_eq!(
            fx.count("SELECT count(*) FROM approval_request"),
            n,
            "{point}"
        );
        crate::state::verify_audit_log(&fx.state().join("audit.log")).unwrap();
        let requested = fx
            .approval_events()
            .iter()
            .filter(|e| *e == "approval.requested")
            .count();
        assert_eq!(
            i64::try_from(requested).unwrap(),
            n,
            "{point}: audited once"
        );
        // No implicit grant, nothing run.
        assert_eq!(fx.count("SELECT count(*) FROM approval"), 0, "{point}");
        assert_eq!(fx.count("SELECT count(*) FROM workload"), 0, "{point}");
        assert!(fx.fake.asked_for("workload.start").is_empty(), "{point}");
    }
    approval_evidence("crash-while-requesting", "whole-or-absent");
}

#[test]
fn m6_2_a_crash_while_revoking_leaves_the_approval_revoked_or_open() {
    for (point, durable) in [
        (CrashPoint::BeforeCommit, false),
        (CrashPoint::AfterCommitBeforeAudit, true),
        (CrashPoint::MidAuditRecord, true),
    ] {
        // The revocation's one transaction is the first after arming.
        let (hook, armed) = stop_after(None, point);
        let mut fx = approval_fixture_with(1, "10m", Some(hook), &[APPROVER]);
        let run = ready_run(&mut fx, "r1");
        let approval = fx.requested_and_granted(&run, "k0");
        armed.store(true, Ordering::SeqCst);
        assert!(
            fx.authority().revoke_approval(&approval).is_err(),
            "{point}"
        );
        armed.store(false, Ordering::SeqCst);
        fx.restart(Some(IMAGE));
        let state = if durable { "REVOKED" } else { "OPEN" };
        assert_eq!(fx.approval(&approval), (0, state.to_owned()), "{point}");
        crate::state::verify_audit_log(&fx.state().join("audit.log")).unwrap();
        let revoked = fx
            .approval_events()
            .iter()
            .filter(|e| *e == "approval.revoked")
            .count();
        assert_eq!(
            revoked,
            usize::from(durable),
            "{point}: audited as the store says"
        );
        // Either way nothing is spent: the run was fenced by the restart.
        assert_eq!(
            refused(&fx.answered(&run, "k1", &launch())),
            R::UnknownRun,
            "{point}"
        );
        assert_eq!(fx.count("SELECT count(*) FROM approval_use"), 0, "{point}");
    }
    approval_evidence("crash-while-revoking", "revoked-or-open");
}

#[test]
fn m6_2_a_run_or_lease_ended_beside_a_decided_spend_waits_for_it_and_nothing_is_spent_after() {
    for end in ["run", "lease"] {
        let meantime = Meantime::default();
        let mut fx = approval_fixture_with(
            3,
            "10m",
            Some(meantime.hook(CrashPoint::ApprovalBeforeUse)),
            &[APPROVER],
        );
        meantime.watch(fx.authority().gate());
        let run = warm_run(&mut fx, "r1");
        let approval = fx.requested_and_granted(&run, "k0");
        fx.fake.running(1);
        let mut other = fx.authority().handle().unwrap();
        let (caller, session, epoch, released) = (
            fx.caller.unwrap(),
            fx.session.clone(),
            fx.epoch,
            run.clone(),
        );
        let (tx, rx) = mpsc::channel();
        meantime.then(move || {
            let reply = if end == "run" {
                other.release_run(&caller, &session, &released, epoch)
            } else {
                other.release_lease(&caller, &session, epoch)
            };
            tx.send(reply.unwrap()).unwrap();
        });
        let dispatched = fx.exec(&run, "k1", &launch());
        meantime.join();
        // Bounded: a launch that never stood at its use -- one not approved --
        // never ran the end, and must fail here rather than wait for ever.
        let reply = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{end}: the launch never stood decided at its use"));
        assert!(matches!(reply, Reply::Done(())), "{end}");
        assert!(
            meantime.held(),
            "{end}: the end waited at the gate while the spend stood decided"
        );
        // The decided spend went on first: its use with its intent, its start
        // at the broker while its run still held authority.
        let starts = fx.fake.asked_for("workload.start");
        assert_eq!(
            starts.len(),
            2,
            "{end}: the warm-up and the approved launch"
        );
        assert_eq!(starts[1].active_runs, 1, "{end}");
        assert_eq!(fx.approval(&approval).0, 1, "{end}: one use");
        if let Dispatched::Parked(parked) = dispatched {
            let _ = fx.settle(parked);
        }
        // After the end, the run is fenced before the registry is asked.
        let after = fx.answered(&run, "k2", &launch());
        assert!(
            matches!(after, DwkpBody::ToolRefusedV5(_)),
            "{end}: {after:?}"
        );
        assert_eq!(fx.approval(&approval).0, 1, "{end}: nothing spent after");
        assert_eq!(fx.fake.asked_for("workload.start").len(), 2, "{end}");
    }
    approval_evidence("run-or-lease-end-beside-a-spend", "spend-then-end");
}

#[test]
fn m6_2_a_replayed_key_spends_nothing_and_another_runs_binding_is_not_this_runs_approval() {
    let mut fx = approval_fixture(3);
    let run = warm_run(&mut fx, "r1");
    let approval = fx.requested_and_granted(&run, "k0");
    assert!(ran_or_denied(&fx.ran(&run, "k1", &launch())));
    assert_eq!(fx.approval(&approval).0, 1);
    // The same key again is answered from its record: no intent, no use.
    let replayed = fx.ran(&run, "k1", &launch());
    assert!(
        !matches!(replayed, DwkpBody::ToolDeniedV5(_)),
        "{replayed:?}"
    );
    assert_eq!(fx.approval(&approval).0, 1, "a replay spends nothing");
    assert_eq!(
        fx.count("SELECT count(*) FROM workload"),
        2,
        "the warm-up and k1"
    );
    // Another run of the session at the same taint binds the same bytes --
    // and its launch is not this run's to approve: a hash is an identity,
    // never an authority.
    let other = warm_run(&mut fx, "r2");
    assert!(!ran_or_denied(&fx.answered(&other, "o1", &launch())));
    let hashes = fx.strings("SELECT binding_sha256 FROM approval_request");
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes[0], hashes[1], "one binding, two runs");
    assert_eq!(fx.approval(&approval).0, 1);
    approval_evidence("replay-and-another-run", "nothing-spent");
}

#[test]
fn m6_2_a_request_whose_run_has_ended_is_never_decided() {
    let mut fx = approval_fixture(1);
    let run = ready_run(&mut fx, "r1");
    denied(&fx.answered(&run, "k1", &call(FIXTURE, &["--a"])));
    denied(&fx.answered(&run, "k2", &call(FIXTURE, &["--b"])));
    let asked = |fx: &Fixture, key: &str| {
        fx.strings(&format!(
            "SELECT request_id FROM approval_request WHERE idempotency_key = '{key}'"
        ))
        .remove(0)
    };
    let (first, second) = (asked(&fx, "k1"), asked(&fx, "k2"));
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    let released = fx
        .authority()
        .release_run(&caller, &session, &run, epoch)
        .unwrap();
    assert!(matches!(released, Reply::Done(())), "{released:?}");
    // The seam refuses, and ends the request: no approval for authority
    // that has ended.
    assert_eq!(
        fx.authority()
            .decide_approval(&first, grant(APPROVER))
            .unwrap(),
        Err(DecisionRefused::RunEnded)
    );
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM approval_request WHERE request_id = '{first}'"
        )),
        "EXPIRED"
    );
    // And the database refuses an approval of the run's other pending
    // request, otherwise in bounds.
    let db = fx.db();
    assert!(
        db.execute(
            "INSERT INTO approval (approval_id, request_id, approver, channel, assurance, \
             granted_ms, not_after_ms, max_uses, uses, state) VALUES \
             (?1, ?2, 'uid:2001', 'APPROVER_ENDPOINT', 'A1', ?3, ?4, 1, 0, 'OPEN')",
            rusqlite::params![
                "c".repeat(64),
                second,
                i64::try_from(START_MS).unwrap(),
                i64::try_from(START_MS + 1_000).unwrap()
            ],
        )
        .is_err(),
        "an approval of an ended run's request"
    );
    drop(db);
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 0);
    approval_evidence("ended-run-never-decided", "refused+expired");
}
