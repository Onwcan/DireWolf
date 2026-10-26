//! The workspace contract on the authority's side (M5d.4, ADR-0052 §§6, 10;
//! OD-3(a), OD-6) in this crate's unit tests: the real authority and store,
//! and the route tests' **fake broker**, which contains nothing and runs
//! nothing. What these prove is the authority's: a workspace that is not the
//! contract's is refused before the broker hears of it; the contract each
//! environment was judged under is said; no name changes while a workload
//! may be running in the workspace, reclamation included; and a workspace
//! changed under a `READY` environment takes it down before the next
//! workload. The real filesystem, its group and its bound are `make
//! sandbox-workspace-evidence`'s.

use dwk_proto::brokerp::sandbox::WorkspaceQuota;
use dwk_proto::wire::scalar::FsFailureReason;

use super::*;

/// One line of `make sandbox-workspace-evidence`'s in-process half, printed
/// only after the assertions before it held. A fake broker: not containment.
fn evidence(case: &str, outcome: &str) {
    println!(
        "WORKSPACE-EVIDENCE {{\"suite\":\"authority-route\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

/// A production configuration: every run's workspace the operator's own
/// 64 MiB filesystem.
fn bounded(image: &str) -> SandboxConfig {
    SandboxConfig::new(
        TRUE,
        "/run/dw-fake-runtime.sock",
        image,
        PROBE,
        NetworkTopology::NoNetwork,
        WorkspaceSetting::Bounded(WorkspaceQuota::new(64 << 20).unwrap()),
    )
    .unwrap()
    .with_workloads(&manifest(), WorkloadBudget::default())
    .unwrap()
}

/// What a fixture that writes declares.
pub(super) const WRITES: &[&str] = &[
    "process.exec:*",
    "fs.read:*",
    "fs.stat:*",
    "fs.write:*",
    "fs.create:*",
];

/// The route tests' policy, with brokered writes allowed: an operator test
/// policy, **not** a shipped pack.
fn writing() -> PolicySet {
    let marker = "[[rule]]\nid = \"default\"";
    assert!(POLICY.contains(marker));
    PolicySet {
        profile: "m5d4".to_owned(),
        sources: vec![PolicySource {
            name: "m5d4.toml".to_owned(),
            text: POLICY
                .replace("name = \"m5d2\"", "name = \"m5d4\"")
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

/// A fixture whose policy allows brokered writes (the release tests use it
/// too, for what a lease's end leaves pending, ADR-0052 §8).
pub(super) fn writer() -> Fixture {
    let mut fx = Fixture::with_declared(writing(), None, WRITES);
    fx.attach(IMAGE);
    fx
}

impl Fixture {
    /// A version-2 tool invocation of `payload`, answered.
    pub(super) fn tool(&mut self, run: &RunId, key: &str, payload: &str) -> DwkpBody {
        let message = self.message(run, 2, "direwolf.tool.invoke", Some(key), payload);
        self.ask(&message)
    }

    /// The text of every audit record of `event`.
    fn records(&self, event: &str) -> Vec<String> {
        crate::state::read_audit_log(&self.state().join("audit.log"))
            .unwrap()
            .iter()
            .filter(|r| r.event() == event)
            .map(|r| format!("{r:?}"))
            .collect()
    }
}

pub(super) fn write(path: &str) -> String {
    format!(r#"{{"fs_write":{{"path":"{path}","content":"6869"}}}}"#)
}

pub(super) fn write_failed(body: &DwkpBody) -> FsFailureReason {
    match body {
        DwkpBody::ToolFailedV2(f) => f.reason,
        other => panic!("not a failed write: {other:?}"),
    }
}

pub(super) fn write_done(body: &DwkpBody) {
    assert!(
        matches!(body, DwkpBody::ToolResultV2(r) if r.output.fs_write.is_some()),
        "not a write's result: {body:?}"
    );
}

#[test]
fn a_workspace_not_the_contracts_is_refused_before_the_broker_hears_of_it() {
    let mut fx = Fixture::new(custom());
    fx.authority().attach_sandbox(bounded(IMAGE)).unwrap();
    let run = fx.run("ws-1", &["process.exec:*"]);
    // The fixture's root is a plain directory of the test's own group: not
    // the workspace group's, so not a workspace -- whatever else it is.
    let reply = fx.authority().environment_prepare(&run).unwrap();
    let crate::state::EnvironmentReply::Failed { reason, .. } = reply else {
        panic!("refused: {reply:?}")
    };
    assert_eq!(reason, "WORKSPACE_GROUP");
    assert!(
        !fx.fake.operations().contains(&"environment.prepare"),
        "the broker was told nothing"
    );
    assert_eq!(fx.one("SELECT state FROM environment"), "REFUSED");
    assert_eq!(fx.one("SELECT failure FROM environment"), "WORKSPACE_GROUP");
    // Through the public route, the launch is refused and nothing runs --
    // nowhere, the host included.
    let body = fx.answered(&run, "ws-2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentUnavailable);
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
    // The contract it was judged under is the audit's to say.
    let intents = fx.records("environment.intent_recorded");
    assert!(
        intents
            .iter()
            .all(|r| r.contains("BOUNDED") && r.contains("67108864")),
        "{intents:?}"
    );
    evidence("authority-unbounded-workspace-refused", "WORKSPACE_GROUP");
    evidence("authority-refused-before-the-broker", "not-asked");
}

#[test]
fn the_evidence_harnesses_workspace_is_said_wherever_it_is_used() {
    let mut fx = fixture();
    let run = fx.run("ev-1", &["process.exec:*"]);
    fx.ready(&run);
    let intents = fx.records("environment.intent_recorded");
    assert!(!intents.is_empty());
    assert!(
        intents.iter().all(|r| r.contains("UNVERIFIED_EVIDENCE")),
        "{intents:?}"
    );
    evidence("authority-unverified-workspace-said", "UNVERIFIED_EVIDENCE");
}

#[test]
fn no_name_changes_while_a_workload_may_run_in_the_workspace() {
    let mut fx = writer();
    let run = fx.run("ex-1", WRITES);
    let other = fx.run("ex-2", WRITES);
    fx.fake.running(4);
    let Dispatched::Parked(parked) = fx.exec(&run, "ex-3", &call(FIXTURE, &["workload-sleep"]))
    else {
        panic!("a long workload is parked")
    };
    assert_eq!(
        fx.count("SELECT count(*) FROM workload WHERE state = 'LAUNCHING'"),
        1
    );
    // The run's own write, and another run's in the same workspace: each
    // ends as a shared directory's change does, and the broker is never
    // asked (the fake panics at a write it was not meant to see).
    for (who, key) in [(&run, "ex-4"), (&other, "ex-5")] {
        let body = fx.tool(who, key, &write("/workspace/new.txt"));
        assert_eq!(write_failed(&body), FsFailureReason::SharedDirectory);
    }
    assert!(fx.fake.asked_for("fs.write").is_empty());
    let failed = fx.records("tool.failed");
    assert_eq!(
        failed
            .iter()
            .filter(|r| r.contains("WORKLOAD_IN_WORKSPACE"))
            .count(),
        2,
        "{failed:?}"
    );
    // Nothing was handed over, and no staging directory can exist.
    assert_eq!(
        fx.count("SELECT count(*) FROM tool_staging WHERE state = 'EXPECTED'"),
        0
    );
    // A read changes no name: it is served as ever.
    let body = fx.tool(&run, "ex-6", r#"{"fs_stat":{"path":"/workspace"}}"#);
    assert!(matches!(body, DwkpBody::ToolResultV2(_)), "{body:?}");
    // The workload ends, `reap` having proved it alone: the next write
    // reaches the broker.
    fx.settle(parked);
    let body = fx.tool(&run, "ex-7", &write("/workspace/new.txt"));
    write_done(&body);
    assert_eq!(fx.fake.asked_for("fs.write").len(), 1);
    evidence(
        "authority-write-excluded-during-a-workload",
        "SHARED_DIRECTORY",
    );
    evidence("authority-other-runs-write-excluded", "SHARED_DIRECTORY");
    evidence("authority-read-served-during-a-workload", "served");
    evidence("authority-write-after-the-workload", "done");
}

#[test]
fn an_environment_whose_end_nothing_proved_excludes_until_it_is_gone() {
    let mut fx = writer();
    let run = fx.run("un-1", WRITES);
    // A preparation whose deadline passed after the order left: `UNKNOWN`,
    // a container possibly there with its probe.
    fx.fake
        .prepare_errors
        .lock()
        .unwrap()
        .push_back(BrokerError::after_sending(BrokerFailure::Unreachable(
            Unreachable::Timeout,
        )));
    let reply = fx.authority().environment_prepare(&run).unwrap();
    assert!(
        matches!(reply, crate::state::EnvironmentReply::Unknown { .. }),
        "{reply:?}"
    );
    let body = fx.tool(&run, "un-2", &write("/workspace/a.txt"));
    assert_eq!(write_failed(&body), FsFailureReason::SharedDirectory);
    // A READY one being destroyed: still possibly running something.
    let mut fx = writer();
    let run = fx.run("ds-1", WRITES);
    let environment = fx.ready(&run);
    fx.db()
        .execute(
            "UPDATE environment SET state = 'DESTROYING' WHERE environment_id = ?1",
            [environment.as_str()],
        )
        .unwrap();
    let body = fx.tool(&run, "ds-2", &write("/workspace/a.txt"));
    assert_eq!(write_failed(&body), FsFailureReason::SharedDirectory);
    // Gone: the write proceeds.
    fx.db()
        .execute(
            "UPDATE environment SET state = 'DESTROYED', ended_ms = intent_ms \
             WHERE environment_id = ?1",
            [environment.as_str()],
        )
        .unwrap();
    let body = fx.tool(&run, "ds-3", &write("/workspace/a.txt"));
    write_done(&body);
    assert_eq!(fx.fake.asked_for("fs.write").len(), 1);
    evidence("authority-unknown-environment-excludes", "SHARED_DIRECTORY");
    evidence(
        "authority-destroying-environment-excludes",
        "SHARED_DIRECTORY",
    );
}

#[test]
fn a_reclamation_waits_while_a_workload_may_run_in_the_workspace() {
    let mut fx = writer();
    let run = fx.run("rc-1", WRITES);
    // A write whose staging directory the broker could not prove gone, and
    // whose reclamation right after went unanswered: `EXPECTED`.
    fx.fake
        .writes
        .lock()
        .unwrap()
        .push_back(Ok(BrokerDelivery::Write {
            created: true,
            debris: true,
        }));
    fx.fake
        .reclaims
        .lock()
        .unwrap()
        .push_back(Err(BrokerError::before_sending(
            BrokerFailure::Unreachable(Unreachable::Connect),
        )));
    let body = fx.tool(&run, "rc-2", &write("/workspace/b.txt"));
    write_done(&body);
    let expected = "SELECT count(*) FROM tool_staging WHERE state = 'EXPECTED'";
    assert_eq!(fx.count(expected), 1);
    assert_eq!(fx.fake.asked_for("fs.reclaim").len(), 1);
    // A workload runs in the workspace: the sweep leaves it, unasked.
    fx.fake.running(4);
    let Dispatched::Parked(parked) = fx.exec(&run, "rc-3", &call(FIXTURE, &["workload-sleep"]))
    else {
        panic!("parked")
    };
    let sweep = fx.authority().reclaim_staging(None, 64).unwrap();
    assert_eq!((sweep.pending, sweep.absent), (1, 0));
    assert_eq!(fx.fake.asked_for("fs.reclaim").len(), 1);
    assert_eq!(fx.count(expected), 1);
    // The workload over, it is reclaimed.
    fx.settle(parked);
    let sweep = fx.authority().reclaim_staging(None, 64).unwrap();
    assert_eq!((sweep.pending, sweep.absent), (0, 1));
    assert_eq!(fx.fake.asked_for("fs.reclaim").len(), 2);
    assert_eq!(fx.count(expected), 0);
    evidence("authority-reclamation-waits-for-the-workload", "EXPECTED");
}

#[test]
fn a_workspace_replaced_under_a_ready_environment_takes_it_down_before_the_next_workload() {
    let mut fx = fixture();
    let run = fx.run("rp-1", &["process.exec:*"]);
    fx.ready(&run);
    // The bound root's path now names another directory.
    let root = fx.scratch.path().join("ws");
    std::fs::rename(&root, fx.scratch.path().join("ws-away")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let body = fx.ran(&run, "rp-2", &call(FIXTURE, &[]));
    let (_, destroyed) = failed(&body);
    assert_eq!(destroyed, Some(true), "{body:?}");
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.fake.asked_for("environment.destroy").len(), 1);
    assert_eq!(
        fx.one("SELECT failure FROM workload ORDER BY intent_ms DESC LIMIT 1"),
        "WORKSPACE_CHANGED"
    );
    evidence("authority-replaced-workspace-destroys", "WORKSPACE_CHANGED");
}

#[test]
fn a_workspace_no_longer_the_contracts_is_answered_as_an_environment_not_clean() {
    // Found before a workload, any of these destroys the environment; the
    // public answer says the environment did not hold, not that the broker
    // failed.
    for reason in [
        "WORKSPACE_OWNER",
        "WORKSPACE_GROUP",
        "WORKSPACE_MODE",
        "WORKSPACE_GROUP_MEMBERSHIP",
        "WORKSPACE_UNBOUNDED",
        "WORKSPACE_QUOTA_MISMATCH",
        "WORKSPACE_FILESYSTEM_SHARED",
        "WORKSPACE_UNOBSERVABLE",
        "WORKSPACE_UNVERIFIED",
    ] {
        assert_eq!(
            super::super::failure(reason),
            F::EnvironmentNotClean,
            "{reason}"
        );
    }
    evidence(
        "authority-workspace-drift-answered-not-clean",
        "ENVIRONMENT_NOT_CLEAN",
    );
}
