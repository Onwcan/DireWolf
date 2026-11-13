//! F-01 (ADR-0062, Proposed) in this crate's unit tests: taint that follows
//! the content a run receives. The real authority and store, and the route
//! tests' fake broker, whose reports stand in for the broker's own. What
//! these prove is the authority's: which deliveries raise a run's taint and
//! to what, before the run is answered; what the evidence of each rise
//! says, and that a possibility is never taken for content received; that a
//! run holding external content marks the root it changes before the broker
//! hears of it; that one run's taint never reaches into another's running
//! workload; and that a restart, an uncertain ending or a contradictory
//! report fails closed. The real broker's reports and the real runtime are
//! `make sandbox-egress-evidence`'s.

use dwk_proto::wire::scalar::FsFailureReason;

use super::workspace::{write, write_done, write_failed};
use super::*;

/// One line of this half's evidence, like the F-17 cases beside it.
fn taint_evidence(case: &str, outcome: &str) {
    evidence(case, outcome);
}

/// The F-17 policy with brokered writes allowed: an operator test policy,
/// **not** a shipped pack. It keeps `approve-egress-when-tainted`.
fn taint_policy() -> PolicySet {
    let marker = "[[rule]]\nid = \"default\"";
    assert!(EGRESS_POLICY.contains(marker));
    PolicySet {
        profile: "f01".to_owned(),
        sources: vec![PolicySource {
            name: "f01.toml".to_owned(),
            text: EGRESS_POLICY
                .replace("name = \"f17\"", "name = \"f01\"")
                .replace(
                    marker,
                    &format!(
                        "[[rule]]\nid = \"allow-writes\"\neffect = \"ALLOW\"\n\
                     when.verb = [\"fs.write\", \"fs.create\"]\n\n{marker}"
                    ),
                ),
        }],
    }
}

/// What a run of these tests asks for.
const ASKED: &[&str] = &[
    GRANT,
    ALLOWED,
    "fs.read:*",
    "fs.stat:*",
    "fs.write:*",
    "fs.create:*",
];

fn taint_fixture_with(hook: Option<CrashHook>) -> Fixture {
    let mut declared = DECLARED.to_vec();
    declared.extend(["network.https:*", "fs.write:*", "fs.create:*"]);
    let mut fx = Fixture::with_declared(taint_policy(), hook, &declared);
    fx.authority().attach_sandbox(proxy_sandbox(IMAGE)).unwrap();
    fx
}

fn taint_fixture() -> Fixture {
    taint_fixture_with(None)
}

impl Fixture {
    /// `run`'s stored taint: 0, 1 or 2.
    fn taint(&self, run: &RunId) -> i64 {
        self.count(&format!(
            "SELECT taint FROM run_policy_input WHERE run_id = '{}'",
            run.as_str()
        ))
    }

    /// `run`'s evidence rows, `cause:basis:from>to`, in order.
    fn evidence_of(&self, run: &RunId) -> Vec<String> {
        let db = self.db();
        let mut statement = db
            .prepare(
                "SELECT cause || ':' || basis || ':' || from_taint || '>' || to_taint \
                 FROM run_taint_evidence WHERE run_id = ?1 ORDER BY seq",
            )
            .unwrap();
        statement
            .query_map([run.as_str()], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    }

    /// A read-family result from the workspace root.
    fn stat(&mut self, run: &RunId, key: &str) -> DwkpBody {
        self.tool(run, key, r#"{"fs_stat":{"path":"/workspace"}}"#)
    }

    /// A workload started and parked, its egress authorisation returned.
    fn parked_workload(&mut self, run: &RunId, key: &str) -> (Box<Parked>, WorkloadEgress) {
        self.fake.running(1);
        let Dispatched::Parked(parked) = self.exec(run, key, &call(FIXTURE, &[])) else {
            panic!("parked")
        };
        let egress = self.fake.egresses().last().cloned().unwrap().unwrap();
        (parked, egress)
    }

    /// A workload run to its end, its broker reporting `reached` and its
    /// stdout `stdout`.
    fn reporting(
        &mut self,
        run: &RunId,
        key: &str,
        stdout: &[u8],
        reached: &[(&str, u64)],
    ) -> DwkpBody {
        let (parked, egress) = self.parked_workload(run, key);
        self.fake
            .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
                ran(WorkloadEnding::Exited, stdout, Verdict::Pass),
                Some(Box::new(egress_report(&egress, reached))),
            ))));
        self.settle(parked)
    }

    /// The replay check: every run's taint is what its evidence says.
    fn history_holds(&self) {
        crate::state::taint::history_holds(&self.db()).unwrap();
    }

    /// Every audit record of `event`.
    fn audited(&self, event: &str) -> Vec<crate::state::AuditRecord> {
        crate::state::read_audit_log(&self.state().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.event() == event)
            .collect()
    }
}

#[test]
fn f01_a_workload_whose_tunnel_received_origin_bytes_taints_its_run_even_printing_nothing() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    assert_eq!(fx.taint(&run), 0);
    let body = fx.reporting(&run, "k1", b"", &[("allowed.example.com", 10)]);
    let (_, out) = result(&body);
    assert_eq!(out.ending, SandboxEnding::Exited);
    assert_eq!(fx.taint(&run), 2, "an origin byte reached the workload");
    assert_eq!(fx.evidence_of(&run), ["workload_reached:ORIGIN_BYTES:0>2"]);
    let raised = fx.audited("run.taint_raised");
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].text("basis"), Some("ORIGIN_BYTES"));
    assert_eq!(raised[0].text("cause"), Some("workload_reached"));
    let outcome = fx.audited("workload.outcome");
    assert_eq!(outcome[0].text("taint"), Some("EXTERNAL_UNTRUSTED"));
    assert_eq!(outcome[0].text("taint_basis"), Some("ORIGIN_BYTES"));
    // Raised before the run was answered: the outcome and the rise are one
    // transaction, and the rise's record precedes the outcome's.
    let events = fx.events();
    let rise = events.iter().position(|e| e == "run.taint_raised").unwrap();
    let ended = events.iter().position(|e| e == "workload.outcome").unwrap();
    assert!(rise < ended, "{events:?}");
    fx.history_holds();
    taint_evidence("taint-origin-bytes-no-output", "external");
}

#[test]
fn f01_permission_alone_never_taints_and_local_output_stays_local() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    // Allowed to reach `allowed.example.com`; reached nothing; printed
    // nothing: nothing was received.
    fx.reporting(&run, "k1", b"", &[]);
    assert_eq!(fx.taint(&run), 0, "permission is not content");
    assert!(fx.evidence_of(&run).is_empty());
    // Output, with nothing reached on a pristine root: what the environment
    // produced, LOCAL_UNVERIFIED as ever.
    fx.reporting(&run, "k2", b"hello", &[]);
    assert_eq!(fx.taint(&run), 1);
    assert_eq!(fx.evidence_of(&run), ["tool_result:LOCAL_CONTENT:0>1"]);
    assert_eq!(fx.count("SELECT count(*) FROM workspace_exposure"), 0);
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), 0);
    fx.history_holds();
    taint_evidence("taint-permission-only-none", "none");
}

#[test]
fn f01_an_uncertain_ending_that_allowed_something_taints_and_says_it_is_uncertain() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    fx.fake.then_collect(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    )));
    fx.ran(&run, "k1", &call(FIXTURE, &[]));
    assert_eq!(fx.one("SELECT settled FROM workload_egress"), "UNCERTAIN");
    assert_eq!(fx.taint(&run), 2);
    assert_eq!(
        fx.evidence_of(&run),
        ["workload_uncertain:UNCERTAIN:0>2"],
        "uncertain, never said to be content received"
    );
    // One whose authorisation allowed nothing: its uncertain ending cannot
    // have brought anything through a tunnel, and its root is pristine.
    let mut fx = taint_fixture();
    let run = fx.run("r1", &[GRANT, BLOCKED]);
    fx.ready(&run);
    fx.fake.then_collect(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    )));
    fx.ran(&run, "k1", &call(FIXTURE, &[]));
    assert_eq!(fx.count("SELECT allows_anything FROM workload_egress"), 0);
    assert_eq!(fx.taint(&run), 0);
    fx.history_holds();
    taint_evidence("taint-uncertain-ending", "external-uncertain");
}

#[test]
fn f01_a_report_that_contradicts_itself_is_never_taken_for_no_content() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    let (parked, egress) = fx.parked_workload(&run, "k1");
    // Bytes back from a destination, yet "nothing reached": a broker that
    // does not keep the protocol.
    let mut report = egress_report(&egress, &[("allowed.example.com", 7)]);
    report.exposed = false;
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"", Verdict::Pass),
            Some(Box::new(report)),
        ))));
    fx.settle(parked);
    assert_eq!(fx.one("SELECT settled FROM workload_egress"), "UNCERTAIN");
    assert_eq!(fx.taint(&run), 2);
    assert_eq!(fx.evidence_of(&run), ["workload_uncertain:UNCERTAIN:0>2"]);
    taint_evidence("taint-contradictory-report", "external-uncertain");
}

#[test]
fn f01_downloaded_content_is_external_when_read_in_the_same_run_and_another() {
    let mut fx = taint_fixture();
    let first = fx.run("r1", ASKED);
    let second = fx.run("r2", ASKED);
    fx.ready(&first);
    fx.reporting(&first, "k1", b"", &[("allowed.example.com", 10)]);
    assert_eq!(fx.taint(&first), 2);
    // The same run reads what its workload left: already external, and the
    // read says so.
    assert!(matches!(fx.stat(&first, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&first), 2);
    // Another run on the same root, which received nothing yet: its first
    // read is external, because the root holds what an origin sent.
    assert_eq!(fx.taint(&second), 0);
    assert!(matches!(fx.stat(&second, "s2"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&second), 2);
    assert_eq!(fx.evidence_of(&second), ["root_exposed:ORIGIN_BYTES:0>2"]);
    let completed = fx.audited("tool.completed");
    let read = completed.last().unwrap();
    assert_eq!(read.text("taint"), Some("EXTERNAL_UNTRUSTED"));
    assert_eq!(read.text("taint_basis"), Some("ORIGIN_BYTES"));
    // A workload of the second run that reaches nothing and prints nothing
    // still returns from the exposed root: its outcome is external too.
    let third = fx.run("r3", ASKED);
    fx.ready(&third);
    fx.reporting(&third, "k3", b"", &[]);
    assert_eq!(fx.taint(&third), 2);
    assert_eq!(fx.evidence_of(&third), ["root_exposed:ORIGIN_BYTES:0>2"]);
    fx.history_holds();
    taint_evidence("taint-downloaded-file-read-cross-run", "external");
}

#[test]
fn f01_two_workspaces_bound_to_one_directory_are_one_root() {
    let mut fx = taint_fixture();
    let first = fx.run("r1", ASKED);
    fx.ready(&first);
    fx.reporting(&first, "k1", b"", &[("allowed.example.com", 1)]);
    // A second workspace, bound to the same directory, in another session.
    let other = WorkspaceId::new("ws-alias").unwrap();
    let session = SessionId::from_uuid(uuid(2)).unwrap();
    let directory = fx.scratch.path().join("ws");
    {
        let mut operator = fx.authority().operator();
        operator
            .install_workspace(&other, WorkspaceSensitivity::Private)
            .unwrap();
        operator
            .install_workspace_root(&other, directory.to_str().unwrap())
            .unwrap();
        operator.bind_session_workspace(&session, &other).unwrap();
    }
    fx.session = session;
    fx.lease();
    let aliased = fx.run("r2", ASKED);
    assert!(matches!(fx.stat(&aliased, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&aliased), 2, "the same root, by its identity");
    taint_evidence("taint-root-by-identity", "external");
}

#[test]
fn f01_a_reader_beside_a_workload_in_flight_is_tainted_by_a_possibility_that_never_marks() {
    let mut fx = taint_fixture();
    let runner = fx.run("r1", ASKED);
    let reader = fx.run("r2", ASKED);
    fx.ready(&runner);
    let (parked, egress) = fx.parked_workload(&runner, "k1");
    // A read while another run's workload on the root may reach an origin:
    // a possibility, recorded as one, with the workload it rests on.
    assert!(matches!(fx.stat(&reader, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&reader), 2);
    assert_eq!(fx.evidence_of(&reader), ["root_exposed:IN_FLIGHT:0>2"]);
    assert_eq!(
        fx.count("SELECT count(*) FROM run_taint_in_flight"),
        1,
        "the workload it rests on"
    );
    // The workload settles having reached nothing: the possibility never
    // became content.
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"", Verdict::Pass),
            Some(Box::new(egress_report(&egress, &[]))),
        ))));
    fx.settle(parked);
    assert_eq!(fx.count("SELECT count(*) FROM workspace_exposure"), 0);
    // The reader's taint does not fall -- but what it writes is not
    // external content: no mark, and the root stays pristine.
    assert_eq!(fx.taint(&reader), 2);
    write_done(&fx.tool(&reader, "w1", &write("/workspace/a.txt")));
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), 0);
    let fresh = fx.run("r3", ASKED);
    assert!(matches!(fx.stat(&fresh, "s2"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&fresh), 1, "a pristine root reads as local");
    fx.history_holds();
    taint_evidence("taint-in-flight-possibility-never-marks", "possibility");
}

#[test]
fn f01_a_possibility_that_settled_exposed_is_content_and_marks() {
    let mut fx = taint_fixture();
    let runner = fx.run("r1", ASKED);
    let reader = fx.run("r2", ASKED);
    fx.ready(&runner);
    let (parked, egress) = fx.parked_workload(&runner, "k1");
    assert!(matches!(fx.stat(&reader, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.evidence_of(&reader), ["root_exposed:IN_FLIGHT:0>2"]);
    // This time the workload did reach its origin.
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"", Verdict::Pass),
            Some(Box::new(egress_report(
                &egress,
                &[("allowed.example.com", 3)],
            ))),
        ))));
    fx.settle(parked);
    write_done(&fx.tool(&reader, "w1", &write("/workspace/a.txt")));
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), 1);
    taint_evidence("taint-possibility-settled-exposed-marks", "marked");
}

#[test]
fn f01_a_run_holding_external_content_marks_the_root_before_the_effect() {
    let mut fx = taint_fixture();
    let writer = fx.run("r1", ASKED);
    let reader = fx.run("r2", ASKED);
    // External content from elsewhere (net.http's, say): the trusted path.
    fx.authority()
        .raise_taint(
            &writer,
            crate::policy::TaintLevel::ExternalUntrusted,
            crate::state::TaintCause::ToolResult,
        )
        .unwrap();
    assert_eq!(fx.evidence_of(&writer), ["tool_result:TRUSTED_CALLER:0>2"]);
    write_done(&fx.tool(&writer, "w1", &write("/workspace/notes.txt")));
    // The mark was durable when the broker heard of the write.
    let asked = fx.fake.asked_for("fs.write");
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].marks, 1, "marked before the effect");
    assert_eq!(fx.one("SELECT tool FROM workspace_taint"), "fs.write");
    assert_eq!(fx.audited("workspace.tainted").len(), 1);
    // Another run reads it: external, because a tainted run changed the root.
    assert!(matches!(fx.stat(&reader, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(
        fx.evidence_of(&reader),
        ["root_exposed:EXTERNAL_RUN_EFFECT:0>2"]
    );
    // And its workloads start exposed.
    fx.ready(&reader);
    fx.reporting(&reader, "k1", b"", &[]);
    assert!(fx.fake.egresses().last().cloned().unwrap().unwrap().exposed);
    // A write excluded by a workload in flight marks nothing: nothing is
    // handed over.
    let other = fx.run("r3", ASKED);
    fx.ready(&other);
    let (parked, _) = fx.parked_workload(&other, "k2");
    let marks = fx.count("SELECT count(*) FROM workspace_taint");
    assert_eq!(
        write_failed(&fx.tool(&writer, "w2", &write("/workspace/b.txt"))),
        FsFailureReason::SharedDirectory
    );
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), marks);
    fx.settle(parked);
    fx.history_holds();
    taint_evidence("taint-tainted-writer-marks-before-effect", "marked");
}

#[test]
fn f01_a_tainted_launch_waits_while_a_pristine_networked_workload_runs_on_the_root() {
    let mut fx = taint_fixture();
    let pristine = fx.run("r1", ASKED);
    let tainted = fx.run("r2", ASKED);
    fx.ready(&pristine);
    fx.ready(&tainted);
    fx.authority()
        .raise_taint(
            &tainted,
            crate::policy::TaintLevel::ExternalUntrusted,
            crate::state::TaintCause::ToolResult,
        )
        .unwrap();
    let (parked, _) = fx.parked_workload(&pristine, "k1");
    assert!(!fx.fake.egresses().last().cloned().unwrap().unwrap().exposed);
    // The tainted run's workload would mark the root that workload's
    // pristine cells are deciding: it waits, refused before anything is
    // recorded.
    let body = fx.answered(&tainted, "k2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentBusy);
    let refusals = fx.audited("workload.refused");
    assert_eq!(
        refusals.last().unwrap().text("reason"),
        Some("WORKSPACE_EXPOSURE_PENDING")
    );
    assert_eq!(
        fx.count(&format!(
            "SELECT count(*) FROM workload WHERE run_id = '{}'",
            tainted.as_str()
        )),
        0
    );
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), 0);
    fx.settle(parked);
    // Settled: it launches, its intent marks the root before the start, and
    // it starts exposed.
    fx.reporting(&tainted, "k3", b"", &[]);
    let started = fx.fake.asked_for("workload.start");
    assert_eq!(started.last().unwrap().marks, 1, "marked before the start");
    assert_eq!(fx.one("SELECT tool FROM workspace_taint"), "workload");
    assert!(fx.fake.egresses().last().cloned().unwrap().unwrap().exposed);
    fx.history_holds();
    taint_evidence("taint-tainted-launch-pending", "EnvironmentBusy");
}

#[test]
fn f01_one_runs_taint_never_reaches_into_another_runs_running_workload() {
    let mut fx = taint_fixture();
    let runner = fx.run("r1", ASKED);
    let reader = fx.run("r2", ASKED);
    let environment = fx.ready(&runner);
    let (parked, egress) = fx.parked_workload(&runner, "k1");
    let before = fx.taint(&runner);
    // The other run's taint rises while the workload runs.
    assert!(matches!(fx.stat(&reader, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&reader), 2);
    assert_eq!(fx.taint(&runner), before, "never pushed into another run");
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"ok", Verdict::Pass),
            Some(Box::new(egress_report(&egress, &[]))),
        ))));
    fx.settle(parked);
    // Its decided context held: no drift, the environment kept.
    assert_ne!(
        fx.db()
            .query_row(
                "SELECT COALESCE(failure, '') FROM environment WHERE environment_id = ?1",
                [environment.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "EGRESS_CONTEXT_DRIFT"
    );
    assert!(!fx.events().iter().any(|e| e == "environment.drifted"));
    taint_evidence("taint-never-pushed-no-drift", "held");
}

#[test]
fn f01_a_restart_records_what_an_interrupted_workload_may_have_brought() {
    let mut fx = taint_fixture_with(Some(stop_at(CrashPoint::WorkloadAfterStart)));
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    let caller = fx.caller.unwrap();
    let message = fx.message(
        &run,
        5,
        "direwolf.tool.invoke",
        Some("k1"),
        &format!(r#"{{"process_exec":{}}}"#, call(FIXTURE, &[])),
    );
    assert!(fx.authority().dispatch_parkable(&caller, &message).is_err());
    assert_eq!(fx.taint(&run), 0);
    fx.start(None);
    fx.authority().attach_sandbox(proxy_sandbox(IMAGE)).unwrap();
    // The run was reaped; its history says what its workload may have
    // brought, uncertainly.
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM run WHERE run_id = '{}'",
            run.as_str()
        )),
        "REAPED"
    );
    assert_eq!(fx.taint(&run), 2);
    assert_eq!(fx.evidence_of(&run), ["workload_interrupted:UNCERTAIN:0>2"]);
    // A run after the restart reads the root as it may be: uncertain.
    fx.clock.advance(1);
    fx.lease();
    let next = fx.run("r2", ASKED);
    assert!(matches!(fx.stat(&next, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.evidence_of(&next), ["root_exposed:UNCERTAIN:0>2"]);
    fx.history_holds();
    taint_evidence("taint-restart-interrupted", "external-uncertain");
}

#[test]
fn f01_taint_never_falls_and_every_decision_says_the_taint_it_used() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    assert!(matches!(fx.stat(&run, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.taint(&run), 1);
    fx.reporting(&run, "k1", b"", &[("allowed.example.com", 2)]);
    assert_eq!(fx.taint(&run), 2);
    assert_eq!(
        fx.evidence_of(&run),
        [
            "tool_result:LOCAL_CONTENT:0>1",
            "workload_reached:ORIGIN_BYTES:1>2"
        ]
    );
    // Each decision records the taint it was decided in.
    let read = fx
        .audited("tool.intent_recorded")
        .into_iter()
        .find(|r| r.text("tool") == Some("fs.stat"))
        .unwrap();
    assert_eq!(read.text("taint_at_decision"), Some("NONE"));
    let launch = fx.audited("workload.intent_recorded");
    assert_eq!(
        launch.last().unwrap().text("taint_at_decision"),
        Some("LOCAL_UNVERIFIED")
    );
    fx.ran(&run, "k2", &call(FIXTURE, &[]));
    let launch = fx.audited("workload.intent_recorded");
    assert_eq!(
        launch.last().unwrap().text("taint_at_decision"),
        Some("EXTERNAL_UNTRUSTED")
    );
    // Nothing lowers it, nothing rewrites its history.
    let db = fx.db();
    for sql in [
        "UPDATE run_policy_input SET taint = 1",
        "UPDATE run_policy_input SET taint = 0",
        "UPDATE run_taint_evidence SET basis = 'LOCAL_CONTENT'",
        "DELETE FROM run_taint_evidence",
        "DELETE FROM workspace_exposure",
    ] {
        assert!(db.execute(sql, []).is_err(), "{sql}");
    }
    fx.history_holds();
    taint_evidence("taint-monotone-and-attributed", "history");
}

#[test]
fn f01_a_pristine_root_stays_local() {
    let mut fx = taint_fixture();
    let run = fx.run("r1", ASKED);
    fx.ready(&run);
    assert!(matches!(fx.stat(&run, "s1"), DwkpBody::ToolResultV2(_)));
    fx.reporting(&run, "k1", b"out", &[]);
    write_done(&fx.tool(&run, "w1", &write("/workspace/c.txt")));
    assert_eq!(fx.taint(&run), 1);
    assert_eq!(fx.evidence_of(&run), ["tool_result:LOCAL_CONTENT:0>1"]);
    for sql in [
        "SELECT count(*) FROM workspace_exposure",
        "SELECT count(*) FROM workspace_taint",
        "SELECT count(*) FROM run_taint_in_flight",
    ] {
        assert_eq!(fx.count(sql), 0, "{sql}");
    }
    taint_evidence("taint-pristine-root-local", "local");
}

#[test]
fn f01_a_later_receipt_makes_a_run_whose_taint_was_a_possibility_hold_content() {
    let mut fx = taint_fixture();
    let runner = fx.run("r1", ASKED);
    let reader = fx.run("r2", ASKED);
    let fetcher = fx.run("r3", ASKED);
    fx.ready(&runner);
    let (parked, egress) = fx.parked_workload(&runner, "k1");
    assert!(matches!(fx.stat(&reader, "s1"), DwkpBody::ToolResultV2(_)));
    assert_eq!(fx.evidence_of(&reader), ["root_exposed:IN_FLIGHT:0>2"]);
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"", Verdict::Pass),
            Some(Box::new(egress_report(&egress, &[]))),
        ))));
    fx.settle(parked);
    // Another run's workload then does reach an origin.
    fx.ready(&fetcher);
    fx.reporting(&fetcher, "k2", b"", &[("allowed.example.com", 4)]);
    // The reader's next read receives what it sent: its taint does not rise
    // -- it is already external -- but what it rests on does, and is said.
    assert!(matches!(fx.stat(&reader, "s2"), DwkpBody::ToolResultV2(_)));
    assert_eq!(
        fx.evidence_of(&reader),
        [
            "root_exposed:IN_FLIGHT:0>2",
            "root_exposed:ORIGIN_BYTES:2>2"
        ]
    );
    // So what it writes now is external content: the root is marked.
    write_done(&fx.tool(&reader, "w1", &write("/workspace/a.txt")));
    assert_eq!(fx.count("SELECT count(*) FROM workspace_taint"), 1);
    fx.history_holds();
    taint_evidence("taint-later-receipt-is-content", "marked");
}
