//! M6.3 (ADR-0081, Proposed): the approver endpoint's operations on the real
//! authority and store -- `approver.list`, `approver.show`,
//! `approver.decide` answered by `Authority::serve_approver`, the decision's
//! binding echo checked in its own transaction -- and, through the real
//! approver endpoint and worker on a real socket, the whole round: a launch
//! denied `REQUIRE_APPROVAL`, the request listed, shown and approved, the
//! launch spent once. The route tests' fake broker runs nothing, so no
//! containment is claimed here; the approver set is attached by the test
//! (`attach_approvers`, test builds only). The production start-up's
//! attachment and genuine identities are the hosted evidence's
//! (`tests/transport_approver.rs`, `tests/sandbox_workload.rs`).
//!
//! Each `APPROVER-EVIDENCE` line is printed only after the assertions before
//! it held; `make approver-operations-evidence` requires every case once.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::sync::Barrier;

use dwk_proto::approverp::{
    self, Digest, Outcome, RefusalCode, Request, RequestDetail, RequestId, RequestState, Response,
    Verdict,
};

use super::*;
use crate::state::approvals::MAX_DENIALS_PER_BINDING;
use crate::state::{ApproverPrincipal, DEFAULT_LEASE_TTL_MS};

/// An operator's approver in the registry-level tests: never a runtime's uid.
const APPROVER: u32 = 2001;

/// One line of the M6.3 evidence, after its assertions.
fn approver_evidence(case: &str, outcome: &str, level: &str) {
    println!(
        "APPROVER-EVIDENCE {{\"suite\":\"authority-approver-operations\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"level\":\"{level}\",\"count\":1}}"
    );
}

/// A sandboxed launch of the fixture needs an approval: exact action, ten
/// minutes, once. **Not** a shipped pack.
fn policy() -> PolicySet {
    PolicySet {
        profile: "m63".to_owned(),
        sources: vec![PolicySource {
            name: "m63.toml".to_owned(),
            text: r#"schema_version = 1

[meta]
name = "m63"

[[rule]]
id = "approve-fixture"
effect = "REQUIRE_APPROVAL"
reason = "SENSITIVE_PATH"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["fixture"]
approval.scope = "exact_action"
approval.ttl = "10m"
approval.max_uses = 1

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
            .to_owned(),
        }],
    }
}

/// A fixture whose approvers are `approvers`, its runtime `runtime`.
fn fixture_as(runtime: u32, approvers: &[u32]) -> Fixture {
    let mut fx = Fixture::with_declared_in_as(
        Scratch::new("approver-route"),
        policy(),
        None,
        DECLARED,
        runtime,
    );
    fx.attach(IMAGE);
    assert!(fx.authority().attach_approvers(approvers));
    fx
}

fn fixture() -> Fixture {
    fixture_as(1000, &[APPROVER])
}

fn ready(fx: &mut Fixture, key: &str) -> RunId {
    let run = fx.run(key, &[GRANT]);
    fx.ready(&run);
    run
}

fn launch() -> String {
    call(FIXTURE, &["--approved"])
}

fn serve(fx: &mut Fixture, as_uid: u32, request: &Request) -> Response {
    fx.authority()
        .serve_approver(ApproverPrincipal::kernel_reported(as_uid), request)
        .unwrap()
}

/// Deny a launch for want of an approval: its request's id.
fn requested(fx: &mut Fixture, run: &RunId, key: &str, launch: &str) -> String {
    let (_, reason, rule) = denied(&fx.answered(run, key, launch));
    assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    assert_eq!(rule, "approve-fixture");
    newest_request(fx)
}

fn newest_request(fx: &Fixture) -> String {
    fx.db()
        .query_row(
            "SELECT request_id FROM approval_request ORDER BY requested_ms DESC, rowid DESC \
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn stored(fx: &Fixture, request: &str) -> (String, String, Vec<u8>) {
    fx.db()
        .query_row(
            "SELECT state, binding_sha256, binding FROM approval_request WHERE request_id = ?1",
            [request],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn show(fx: &mut Fixture, request: &str) -> RequestDetail {
    match serve(
        fx,
        APPROVER,
        &Request::Show(RequestId::new(request).unwrap()),
    ) {
        Response::Shown(detail) => *detail,
        other => panic!("not shown: {other:?}"),
    }
}

fn decide(fx: &mut Fixture, as_uid: u32, request: &str, hash: &str, verdict: Verdict) -> Response {
    serve(
        fx,
        as_uid,
        &Request::Decide {
            request_id: RequestId::new(request).unwrap(),
            binding_sha256: Digest::new(hash).unwrap(),
            decision: verdict,
        },
    )
}

fn approve(fx: &mut Fixture, request: &str) -> Response {
    let (_, hash, _) = stored(fx, request);
    decide(fx, APPROVER, request, &hash, Verdict::Approve)
}

fn kinds(fx: &Fixture, prefix: &str) -> Vec<String> {
    fx.events()
        .into_iter()
        .filter(|e| e.starts_with(prefix))
        .collect()
}

fn listed(fx: &mut Fixture) -> (u16, Vec<String>) {
    match serve(fx, APPROVER, &Request::List) {
        Response::Listed(listed) => (
            listed.waiting.get(),
            listed
                .requests
                .iter()
                .map(|s| s.request_id.as_str().to_owned())
                .collect(),
        ),
        other => panic!("not listed: {other:?}"),
    }
}

/// Move the clock on by `ms`, the lease kept alive by heartbeats.
fn tick(fx: &mut Fixture, mut ms: u64) {
    while ms > 0 {
        let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
        let beat = fx.authority().heartbeat(&caller, &session, epoch).unwrap();
        assert!(matches!(beat, Reply::Done(())), "{beat:?}");
        let step = ms.min(DEFAULT_LEASE_TTL_MS >> 1);
        fx.clock.advance(step);
        ms -= step;
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ---------------------------------------------------------------------------
// List and show.
// ---------------------------------------------------------------------------

#[test]
fn m6_3_a_listing_is_what_waits_and_writes_nothing() {
    let mut fx = fixture();
    assert_eq!(listed(&mut fx), (0, Vec::new()), "nothing waits");
    let run = ready(&mut fx, "r1");
    let first = requested(&mut fx, &run, "k1", &launch());
    fx.clock.advance(1);
    let second = requested(&mut fx, &run, "k2", &call(FIXTURE, &["--other"]));
    let before = fx.events().len();
    let (waiting, ids) = listed(&mut fx);
    assert_eq!(
        (waiting, ids.clone()),
        (2, vec![first.clone(), second.clone()])
    );
    assert_eq!(fx.events().len(), before, "a listing writes no record");
    // Past the window, neither waits -- and the listing ends neither: they
    // stay PENDING until a decision or the run's next request finds them.
    tick(&mut fx, 10 * 60 * 1000);
    assert_eq!(listed(&mut fx), (0, Vec::new()));
    assert_eq!(stored(&fx, &first).0, "PENDING");
    assert_eq!(fx.events().len(), before);
    approver_evidence("list-waiting-only-read-only", "2-then-0", "component");
}

#[test]
fn m6_3_a_listing_leaves_out_an_ended_runs_requests() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    requested(&mut fx, &run, "k1", &launch());
    assert_eq!(listed(&mut fx).0, 1);
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    let released = fx
        .authority()
        .release_run(&caller, &session, &run, epoch)
        .unwrap();
    assert!(matches!(released, Reply::Done(())), "{released:?}");
    assert_eq!(listed(&mut fx), (0, Vec::new()), "its authority ended");
    approver_evidence("list-excludes-ended-run", "0", "component");
}

#[test]
fn m6_3_a_request_is_shown_as_stored_and_its_binding_hashes_to_its_digest() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let (_, hash, bytes) = stored(&fx, &request);
    let detail = show(&mut fx, &request);
    assert_eq!(detail.request_id.as_str(), request);
    assert_eq!(detail.state, RequestState::Pending);
    assert!(detail.decidable);
    assert_eq!(detail.run_id, run);
    assert_eq!(detail.requester.as_str(), "uid:1000");
    assert_eq!(detail.rule_id.as_str(), "approve-fixture");
    assert_eq!(detail.scope.as_str(), "exact_action");
    assert_eq!((detail.ttl_s.get(), detail.max_uses.get()), (600, 1));
    assert_eq!(detail.assurance_required, approverp::Assurance::A1);
    assert_eq!(detail.binding_sha256.as_str(), hash);
    assert_eq!(detail.binding.as_str().as_bytes(), bytes.as_slice());
    assert_eq!(hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)), hash);
    assert_eq!(
        detail.binding_schema.as_str(),
        crate::state::binding::SCHEMA
    );
    assert!(detail.approval.is_none() && detail.decided_ms.is_none());
    // The binding is the authority's canonical JSON, the argv the launch's own.
    let value = dwk_proto::json::parse(&bytes, dwk_proto::json::ParseOptions::dwkp()).unwrap();
    assert_eq!(dwk_proto::json::to_canonical_bytes(&value), bytes);
    assert!(detail.binding.as_str().contains("--approved"));
    // An id no request has is answered as such, and writes nothing.
    let unknown = "f".repeat(64);
    assert_eq!(
        serve(
            &mut fx,
            APPROVER,
            &Request::Show(RequestId::new(&unknown).unwrap())
        ),
        Response::Refused(RefusalCode::UnknownRequest)
    );
    approver_evidence("show-canonical-binding", "hash-verified", "component");
}

// ---------------------------------------------------------------------------
// Decisions.
// ---------------------------------------------------------------------------

#[test]
fn m6_3_a_decision_must_echo_its_requests_binding() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let first = requested(&mut fx, &run, "k1", &launch());
    let second = requested(&mut fx, &run, "k2", &call(FIXTURE, &["--other"]));
    let (_, first_hash, _) = stored(&fx, &first);
    let (_, second_hash, _) = stored(&fx, &second);
    // Another request's binding, a hash of nothing, an unknown request with
    // a real binding: each refused, nothing decided, nothing granted.
    for (request, hash, code) in [
        (&first, second_hash.as_str(), RefusalCode::BindingMismatch),
        (&first, &"0".repeat(64)[..], RefusalCode::BindingMismatch),
        (
            &"e".repeat(64),
            first_hash.as_str(),
            RefusalCode::UnknownRequest,
        ),
    ] {
        for verdict in [Verdict::Approve, Verdict::Deny] {
            assert_eq!(
                decide(&mut fx, APPROVER, request, hash, verdict),
                Response::Refused(code),
                "{request} {hash} {verdict:?}"
            );
        }
    }
    assert_eq!(stored(&fx, &first).0, "PENDING");
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 0);
    assert!(kinds(&fx, "approval.granted").is_empty());
    assert!(kinds(&fx, "approval.denied").is_empty());
    approver_evidence(
        "decision-binding-mismatch-refused",
        "BINDING_MISMATCH",
        "component",
    );
    // The request's own binding: granted, at A1, by the approver the
    // endpoint reported, for the rule's life and uses.
    let Response::Decided(decided) = approve(&mut fx, &first) else {
        panic!("not granted")
    };
    assert_eq!(decided.outcome, Outcome::Granted);
    let approval = decided.approval_id.unwrap();
    let (approver, assurance, channel, max_uses): (String, String, String, i64) = fx
        .db()
        .query_row(
            "SELECT approver, assurance, channel, max_uses FROM approval WHERE approval_id = ?1",
            [approval.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (
            approver.as_str(),
            assurance.as_str(),
            channel.as_str(),
            max_uses
        ),
        ("uid:2001", "A1", "APPROVER_ENDPOINT", 1)
    );
    let granted = records(&fx, "approval.granted");
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].text("requester"), Some("uid:1000"));
    assert_eq!(granted[0].text("approver"), Some("uid:2001"));
    assert_eq!(granted[0].text("binding_sha256"), Some(first_hash.as_str()));
    assert!(granted[0].text("policy_revision").is_some());
    approver_evidence("decision-a1-recorded", "GRANTED-A1", "component");
}

#[test]
fn m6_3_a_request_is_decided_once_whatever_is_replayed() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let (_, hash, _) = stored(&fx, &request);
    let Response::Decided(first) = decide(&mut fx, APPROVER, &request, &hash, Verdict::Approve)
    else {
        panic!("not granted")
    };
    // The same approval again, a denial after it, from another approver
    // too: each refused, and still one approval, one record.
    for (uid, verdict) in [
        (APPROVER, Verdict::Approve),
        (APPROVER, Verdict::Deny),
        (2002, Verdict::Approve),
    ] {
        assert_eq!(
            decide(&mut fx, uid, &request, &hash, verdict),
            Response::Refused(if uid == APPROVER {
                RefusalCode::NotPending
            } else {
                RefusalCode::UnknownApprover
            })
        );
    }
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 1);
    assert_eq!(kinds(&fx, "approval.granted").len(), 1);
    assert_eq!(show(&mut fx, &request).state, RequestState::Granted);
    assert_eq!(
        show(&mut fx, &request).approval.unwrap().approval_id,
        first.approval_id.unwrap()
    );
    approver_evidence("replayed-approval-refused", "NOT_PENDING", "component");
    // A denial is decided once too, and is never an approval afterwards.
    let other = requested(&mut fx, &run, "k2", &call(FIXTURE, &["--other"]));
    let (_, other_hash, _) = stored(&fx, &other);
    assert!(matches!(
        decide(&mut fx, APPROVER, &other, &other_hash, Verdict::Deny),
        Response::Decided(d) if d.outcome == Outcome::Denied && d.approval_id.is_none()
    ));
    for verdict in [Verdict::Deny, Verdict::Approve] {
        assert_eq!(
            decide(&mut fx, APPROVER, &other, &other_hash, verdict),
            Response::Refused(RefusalCode::NotPending)
        );
    }
    assert_eq!(
        fx.count("SELECT count(*) FROM approval"),
        1,
        "no approval of a denial"
    );
    assert_eq!(show(&mut fx, &other).state, RequestState::Denied);
    assert_eq!(kinds(&fx, "approval.denied").len(), 1);
    approver_evidence("replayed-denial-refused", "NOT_PENDING", "component");
}

#[test]
fn m6_3_an_expired_or_ended_request_decides_nothing() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    tick(&mut fx, 10 * 60 * 1000);
    let (_, hash, _) = stored(&fx, &request);
    assert_eq!(
        decide(&mut fx, APPROVER, &request, &hash, Verdict::Approve),
        Response::Refused(RefusalCode::Expired)
    );
    assert_eq!(stored(&fx, &request).0, "EXPIRED", "ended by the decision");
    assert!(!show(&mut fx, &request).decidable);
    approver_evidence("decision-after-expiry-refused", "EXPIRED", "component");

    let other = ready(&mut fx, "r2");
    let request = requested(&mut fx, &other, "k2", &launch());
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    assert!(matches!(
        fx.authority()
            .release_run(&caller, &session, &other, epoch)
            .unwrap(),
        Reply::Done(())
    ));
    let (_, hash, _) = stored(&fx, &request);
    assert_eq!(
        decide(&mut fx, APPROVER, &request, &hash, Verdict::Approve),
        Response::Refused(RefusalCode::RunEnded)
    );
    assert_eq!(stored(&fx, &request).0, "EXPIRED");
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 0);
    approver_evidence("decision-after-run-end-refused", "RUN_ENDED", "component");
}

#[test]
fn m6_3_the_approver_is_checked_again_and_never_the_requester() {
    // The registry's set holds the runtime's uid too -- which no production
    // start-up allows -- to show the second statement of disjointness: the
    // requester cannot approve its own request, and nobody outside the set
    // can list, show or decide.
    let mut fx = fixture_as(1000, &[APPROVER, 1000]);
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let (_, hash, _) = stored(&fx, &request);
    assert_eq!(
        decide(&mut fx, 1000, &request, &hash, Verdict::Approve),
        Response::Refused(RefusalCode::SelfApproval)
    );
    approver_evidence("self-approval-refused", "SELF_APPROVAL", "component");
    for operation in [
        Request::List,
        Request::Show(RequestId::new(&request).unwrap()),
        Request::Decide {
            request_id: RequestId::new(&request).unwrap(),
            binding_sha256: Digest::new(&hash).unwrap(),
            decision: Verdict::Approve,
        },
    ] {
        assert_eq!(
            serve(&mut fx, 2999, &operation),
            Response::Refused(RefusalCode::UnknownApprover),
            "{operation:?}"
        );
    }
    assert_eq!(stored(&fx, &request).0, "PENDING");
    assert_eq!(fx.count("SELECT count(*) FROM approval"), 0);
    approver_evidence("unknown-approver-refused", "UNKNOWN_APPROVER", "component");
}

#[test]
fn m6_3_an_approver_removed_by_a_restart_decides_and_spends_nothing() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    // A restart whose operator names another approver: the old one is no
    // approver now, at the decision and -- for an approval it granted
    // before -- at the spend.
    fx.restart(Some(IMAGE));
    assert!(fx.authority().attach_approvers(&[2002]));
    let (_, hash, _) = stored(&fx, &request);
    assert_eq!(
        decide(&mut fx, APPROVER, &request, &hash, Verdict::Approve),
        Response::Refused(RefusalCode::UnknownApprover)
    );
    approver_evidence("removed-approver-refused", "UNKNOWN_APPROVER", "component");
}

// ---------------------------------------------------------------------------
// The approval, spent.
// ---------------------------------------------------------------------------

#[test]
fn m6_3_an_endpoint_approval_is_spent_once_by_its_exact_action() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    assert_eq!(fx.fake.asked_for("workload.start").len(), 0, "nothing ran");
    let Response::Decided(decided) = approve(&mut fx, &request) else {
        panic!("not granted")
    };
    let approval = decided.approval_id.unwrap();
    assert_eq!(
        fx.fake.asked_for("workload.start").len(),
        0,
        "a decision runs nothing"
    );
    // The exact action, re-asked: spent once, on its intent.
    let body = fx.ran(&run, "k2", &launch());
    assert!(matches!(body, DwkpBody::ToolResultV5(_)), "{body:?}");
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    let (uses, state): (i64, String) = fx
        .db()
        .query_row(
            "SELECT uses, state FROM approval WHERE approval_id = ?1",
            [approval.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((uses, state.as_str()), (1, "EXHAUSTED"));
    let spent = records(&fx, "approval.used");
    assert_eq!(spent.len(), 1);
    assert_eq!(spent[0].text("approver"), Some("uid:2001"));
    approver_evidence(
        "endpoint-approval-spent-once",
        "1-of-1",
        "end-to-end-fake-broker",
    );
    // Again: nothing left to spend, so denied and asked anew; no second run.
    let (_, reason, _) = denied(&fx.answered(&run, "k3", &launch()));
    assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    approver_evidence(
        "exhausted-approval-not-reused",
        "APPROVAL_REQUIRED",
        "end-to-end-fake-broker",
    );
    // Another action never borrows it.
    let (_, reason, _) = denied(&fx.answered(&run, "k4", &call(FIXTURE, &["--changed"])));
    assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    approver_evidence(
        "changed-action-not-approved",
        "APPROVAL_REQUIRED",
        "end-to-end-fake-broker",
    );
}

#[test]
fn m6_3_three_denials_of_one_binding_are_not_asked_a_fourth_time() {
    let mut fx = fixture();
    let run = ready(&mut fx, "r1");
    let mut key = 0;
    let mut next = |fx: &mut Fixture| {
        key += 1;
        let (_, reason, _) = denied(&fx.answered(&run, &format!("k{key}"), &launch()));
        assert_eq!(reason, ProcessDecisionReason::ApprovalRequired);
    };
    // An expiry first: not a denial, and not counted.
    next(&mut fx);
    tick(&mut fx, 10 * 60 * 1000);
    next(&mut fx);
    let mut denials = 0;
    while denials < MAX_DENIALS_PER_BINDING {
        let request = newest_request(&fx);
        assert_eq!(stored(&fx, &request).0, "PENDING");
        let (_, hash, _) = stored(&fx, &request);
        assert!(matches!(
            decide(&mut fx, APPROVER, &request, &hash, Verdict::Deny),
            Response::Decided(_)
        ));
        denials += 1;
        next(&mut fx);
    }
    // After the third denial the launch is denied as before, and no fourth
    // request is recorded: no approver is asked again in this run.
    let requests = fx.count("SELECT count(*) FROM approval_request");
    assert_eq!(requests, 1 + 3, "one expired, three denied, none more");
    assert_eq!(listed(&mut fx).0, 0);
    next(&mut fx);
    assert_eq!(fx.count("SELECT count(*) FROM approval_request"), requests);
    approver_evidence(
        "fatigue-denials-not-asked-again",
        "3-denied-then-quiet",
        "component",
    );
    // Another binding in the same run is still asked: the bound is per
    // action, not a punishment of the run.
    denied(&fx.answered(&run, "other", &call(FIXTURE, &["--other"])));
    assert_eq!(listed(&mut fx).0, 1);
    approver_evidence("fatigue-expiry-not-counted", "expiry-ignored", "component");
}

// ---------------------------------------------------------------------------
// Concurrency.
// ---------------------------------------------------------------------------

#[test]
fn m6_3_concurrent_decisions_on_separate_handles_record_one() {
    // Eight decisions -- approvals and denials, from two approvers -- race
    // on separate handles onto one store: exactly one is recorded, the rest
    // are refused, and one record and at most one approval exist.
    let mut fx = fixture_as(1000, &[APPROVER, 2002]);
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let (_, hash, _) = stored(&fx, &request);
    let start = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for n in 0..8_u32 {
        let mut handle = fx.authority().handle().unwrap();
        let start = Arc::clone(&start);
        let (request, hash) = (request.clone(), hash.clone());
        threads.push(std::thread::spawn(move || {
            let uid = if n % 2 == 0 { APPROVER } else { 2002 };
            let verdict = if n % 3 == 0 {
                Verdict::Deny
            } else {
                Verdict::Approve
            };
            start.wait();
            handle
                .serve_approver(
                    ApproverPrincipal::kernel_reported(uid),
                    &Request::Decide {
                        request_id: RequestId::new(&request).unwrap(),
                        binding_sha256: Digest::new(&hash).unwrap(),
                        decision: verdict,
                    },
                )
                .unwrap()
        }));
    }
    let answers: Vec<Response> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let decided = answers
        .iter()
        .filter(|a| matches!(a, Response::Decided(_)))
        .count();
    let refused = answers
        .iter()
        .filter(|a| **a == Response::Refused(RefusalCode::NotPending))
        .count();
    assert_eq!((decided, refused), (1, 7), "{answers:?}");
    let terminal = kinds(&fx, "approval.granted").len() + kinds(&fx, "approval.denied").len();
    assert_eq!(terminal, 1, "one record");
    assert!(fx.count("SELECT count(*) FROM approval") <= 1);
    approver_evidence("concurrent-decisions-one-recorded", "1-of-8", "component");
}

// ---------------------------------------------------------------------------
// Through the endpoint: a real socket, the real worker.
// ---------------------------------------------------------------------------

/// This process's uid: the kernel's report for every connection it makes.
fn own_uid(fx: &Fixture) -> u32 {
    std::fs::metadata(fx.scratch.path()).unwrap().uid()
}

/// One request over the endpoint at `path`; its answer, or `None` if the
/// connection closed unanswered.
fn over_socket(path: &std::path::Path, request: &Request) -> Option<Response> {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    stream.write_all(&request.encode_frame().unwrap()).unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    (!bytes.is_empty())
        .then(|| Response::decode_frame_body(&bytes[dwk_proto::frame::HEADER_LEN..]).unwrap())
}

#[test]
fn m6_3_the_endpoint_lists_shows_and_decides_and_the_launch_is_spent() {
    // The runtime is not this process's uid; this process -- the kernel's
    // report for every connection it makes -- is the approver.
    let probe = Scratch::new("approver-uid");
    let me = std::fs::metadata(probe.path()).unwrap().uid();
    let runtime = if me == 4242 { 4243 } else { 4242 };
    let mut fx = fixture_as(runtime, &[me]);
    assert_eq!(own_uid(&fx), me);
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let path = fx.scratch.path().join("approver.sock");
    let endpoint =
        crate::server::testing::approver_endpoint(fx.authority().handle().unwrap(), &path, &[me]);
    // List and show, as the client does.
    let Some(Response::Listed(listing)) = over_socket(&path, &Request::List) else {
        panic!("not listed")
    };
    assert_eq!(listing.waiting.get(), 1);
    assert_eq!(listing.requests.as_slice()[0].request_id.as_str(), request);
    let Some(Response::Shown(detail)) =
        over_socket(&path, &Request::Show(RequestId::new(&request).unwrap()))
    else {
        panic!("not shown")
    };
    assert_eq!(detail.requester.as_str(), format!("uid:{runtime}"));
    let hash = detail.binding_sha256.clone();
    // A wrong echo first: refused, and recorded as the endpoint's refusal.
    let wrong = Request::Decide {
        request_id: RequestId::new(&request).unwrap(),
        binding_sha256: Digest::new("1".repeat(64)).unwrap(),
        decision: Verdict::Approve,
    };
    assert_eq!(
        over_socket(&path, &wrong),
        Some(Response::Refused(RefusalCode::BindingMismatch))
    );
    let decide = Request::Decide {
        request_id: RequestId::new(&request).unwrap(),
        binding_sha256: hash,
        decision: Verdict::Approve,
    };
    let Some(Response::Decided(decided)) = over_socket(&path, &decide) else {
        panic!("not decided")
    };
    assert_eq!(decided.outcome, Outcome::Granted);
    // The answer replayed on a new connection: decided once.
    assert_eq!(
        over_socket(&path, &decide),
        Some(Response::Refused(RefusalCode::NotPending))
    );
    drop(endpoint);
    let refused = records(&fx, "approver.request_refused");
    assert_eq!(refused.len(), 2, "the mismatch and the replay");
    assert_eq!(refused[0].text("code"), Some("BINDING_MISMATCH"));
    assert_eq!(refused[1].text("code"), Some("NOT_PENDING"));
    assert_eq!(
        refused[0].text("approver"),
        Some(format!("uid:{me}").as_str())
    );
    assert_eq!(records(&fx, "approver.peer_authenticated").len(), 5);
    approver_evidence(
        "endpoint-list-show-decide",
        "GRANTED",
        "end-to-end-fake-broker",
    );
    // The launch the approval was granted for: spent, once.
    let body = fx.ran(&run, "k2", &launch());
    assert!(matches!(body, DwkpBody::ToolResultV5(_)), "{body:?}");
    assert_eq!(records(&fx, "approval.used").len(), 1);
    approver_evidence(
        "endpoint-approval-consumed",
        "1-of-1",
        "end-to-end-fake-broker",
    );
}

#[test]
fn m6_3_concurrent_endpoint_decisions_record_one_and_a_lost_answer_is_read_back() {
    let probe = Scratch::new("approver-uid");
    let me = std::fs::metadata(probe.path()).unwrap().uid();
    let runtime = if me == 4242 { 4243 } else { 4242 };
    let mut fx = fixture_as(runtime, &[me]);
    let run = ready(&mut fx, "r1");
    let request = requested(&mut fx, &run, "k1", &launch());
    let (_, hash, _) = stored(&fx, &request);
    let path = fx.scratch.path().join("approver.sock");
    let endpoint =
        crate::server::testing::approver_endpoint(fx.authority().handle().unwrap(), &path, &[me]);
    // A decision whose client hangs up before its answer: recorded anyway.
    {
        let mut stream = UnixStream::connect(&path).unwrap();
        let lost = Request::Decide {
            request_id: RequestId::new(&request).unwrap(),
            binding_sha256: Digest::new(&hash).unwrap(),
            decision: Verdict::Approve,
        };
        stream.write_all(&lost.encode_frame().unwrap()).unwrap();
        drop(stream);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let Some(Response::Shown(detail)) =
            over_socket(&path, &Request::Show(RequestId::new(&request).unwrap()))
        else {
            panic!("not shown")
        };
        if detail.state == RequestState::Granted {
            assert!(detail.approval.is_some());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the decision never landed"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    approver_evidence("lost-answer-read-back", "GRANTED", "end-to-end-fake-broker");
    // Four concurrent decisions over the endpoint on another request: one.
    let other = requested(&mut fx, &run, "k2", &call(FIXTURE, &["--other"]));
    let (_, other_hash, _) = stored(&fx, &other);
    let start = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|n| {
            let (path, other, other_hash) = (path.clone(), other.clone(), other_hash.clone());
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                over_socket(
                    &path,
                    &Request::Decide {
                        request_id: RequestId::new(&other).unwrap(),
                        binding_sha256: Digest::new(&other_hash).unwrap(),
                        decision: if n % 2 == 0 {
                            Verdict::Approve
                        } else {
                            Verdict::Deny
                        },
                    },
                )
            })
        })
        .collect();
    let answers: Vec<Option<Response>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    drop(endpoint);
    let decided = answers
        .iter()
        .filter(|a| matches!(a, Some(Response::Decided(_))))
        .count();
    assert_eq!(decided, 1, "{answers:?}");
    assert!(
        answers.iter().all(|a| matches!(
            a,
            Some(Response::Decided(_) | Response::Refused(RefusalCode::NotPending))
        )),
        "{answers:?}"
    );
    approver_evidence(
        "concurrent-endpoint-decisions-one",
        "1-of-4",
        "end-to-end-fake-broker",
    );
}

/// The audit log's records of `kind`, in order.
fn records(fx: &Fixture, kind: &str) -> Vec<crate::state::AuditRecord> {
    crate::state::read_audit_log(&fx.state().join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.event() == kind)
        .collect()
}
