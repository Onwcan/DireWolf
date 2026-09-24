//! Which paths consult the filesystem, measured (M4c, ADR-0044 §6).
//!
//! Three paths are kept apart, and each is measured here by the filesystem
//! lookups it begins on this thread — every re-pinning of a bound workspace
//! root and every resolution beneath one:
//!
//! | path | what it consults | lookups |
//! |---|---|---|
//! | a **new** declaration, at admission | the production resolver | some |
//! | a **stored** grant, re-read for a query or a replay | its canonical text, by grammar alone | **none** |
//! | an admission **replay** | its idempotency record | **none** |
//! | a **tool target**, at invocation | the production resolver, again | some |
//!
//! The counter, [`lookups_on_this_thread`], exists only in this crate's unit
//! tests: it is how the proof observes the resolver, not an interface of the
//! product, and no build a user runs contains it. So the proof lives here,
//! beside the code, and drives the real authority — a real store, a real
//! workspace root — through the entry points the server calls.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use dwk_proto::dwkp::messages::FsReadCall;
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{AgentProfileName, Epoch, FsRefusalReason, ReadLimit, WorkspacePath};

use super::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, ManualClock, Mode, PolicySet,
    Reply, StartOptions, StartupConfig, ToolReply, ToolRequest, WorkspaceId, WorkspaceSensitivity,
};
use crate::capability::PrivacyClass;
use crate::resource::fs::lookups_on_this_thread;
use crate::scratch::Scratch;

const START_MS: u64 = 1_758_000_000_000;
const DECLARED: &str = "fs.read:/workspace/a.txt?max_bytes=64";

fn uuid(n: u64) -> u128 {
    let ts = u128::from(START_MS);
    let n = u128::from(n);
    (ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | (n & ((1 << 62) - 1))
}

fn id(prefix: &str, n: u64) -> String {
    format!("{prefix}_{}", encode_uuid(uuid(n)))
}

fn decode(json: &str) -> DwkpMessage {
    dwkp::decode_body(json.as_bytes()).unwrap_or_else(|e| panic!("decodes: {e}\n{json}"))
}

fn admit(session: &SessionId, epoch: Epoch, key: &str, msg: u64) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-21T10:00:01.000Z","correlation_id":"{corr}","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"agent_profile":"reader","skills":[],"requested_capabilities":["{DECLARED}"]}}}}"#,
        id = id("msg", 10_000 + msg),
        corr = id("cor", 20_000 + msg),
        session = session.as_str(),
        epoch = epoch.get(),
    ))
}

fn query(session: &SessionId, run: &RunId, epoch: Epoch) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.authority.query","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"payload":{{}}}}"#,
        id = id("msg", 30_000),
        session = session.as_str(),
        run = run.as_str(),
        epoch = epoch.get(),
    ))
}

fn granted(reply: &Reply<super::Admission>) -> Vec<String> {
    let Reply::Done(admission) = reply else {
        panic!("admitted: {reply:?}")
    };
    admission
        .granted()
        .iter()
        .map(|g| g.capability().to_canonical_string())
        .collect()
}

/// Lookups `work` began on this thread.
fn lookups<T>(work: impl FnOnce() -> T) -> (T, u64) {
    let before = lookups_on_this_thread();
    let done = work();
    (done, lookups_on_this_thread() - before)
}

struct Fixture {
    _scratch: Scratch,
    root: std::path::PathBuf,
    authority: Authority,
    caller: CallerContext,
    session: SessionId,
    epoch: Epoch,
}

/// A real authority: a store, the shipped balanced policy, a `reader`
/// profile that may declare `fs.read`, and a workspace bound to a real
/// directory holding `a.txt`.
fn fixture() -> Fixture {
    let scratch = Scratch::new("lookups");
    let root = scratch.path().join("ws");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"first").unwrap();
    let config = StartupConfig::new(
        PolicySet::shipped("balanced").unwrap(),
        Mode::Balanced,
        vec!["fs.read:*".to_owned()],
    );
    let options = StartOptions {
        clock: Arc::new(ManualClock::new(START_MS)),
        crash_hook: None,
        broker: None,
    };
    let (mut authority, _) =
        Authority::start(&scratch.path().join("state"), &config, options).unwrap();
    let workspace = WorkspaceId::new("ws").unwrap();
    let session = SessionId::from_uuid(uuid(1)).unwrap();
    {
        let mut operator = authority.operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("reader").unwrap(),
                declared: vec!["fs.read:*".to_owned()],
                baseline_skills: Vec::new(),
                privacy_default: PrivacyClass::Any,
            })
            .unwrap();
        operator
            .install_workspace(&workspace, WorkspaceSensitivity::Private)
            .unwrap();
        operator
            .install_workspace_root(&workspace, root.to_str().unwrap())
            .unwrap();
        operator
            .bind_session_workspace(&session, &workspace)
            .unwrap();
    }
    let caller = authority.connect(AuthenticatedSubject::unix_uid(1000));
    let Reply::Done(epoch) = authority.acquire_lease(&caller, &session).unwrap() else {
        panic!("a lease")
    };
    Fixture {
        _scratch: scratch,
        root,
        authority,
        caller,
        session,
        epoch,
    }
}

fn evidence(case: &str, outcome: &str) {
    println!(
        "FSOP-EVIDENCE {{\"suite\":\"grant-rehydration\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

#[test]
fn a_stored_grant_and_an_admission_replay_begin_no_lookup_and_a_tool_target_does() {
    let Fixture {
        _scratch,
        root,
        mut authority,
        caller,
        session,
        epoch,
    } = fixture();

    // A new declaration: resolved, beneath the pinned root.
    let first = admit(&session, epoch, "k1", 1);
    let (reply, looked) = lookups(|| authority.admit_run(&caller, &first).unwrap());
    assert!(looked > 0, "a new declaration is resolved");
    assert_eq!(granted(&reply), [DECLARED]);
    let Reply::Done(admission) = reply else {
        unreachable!("granted above")
    };
    let run = admission.run_id().clone();

    // The replay under the same key: answered from the record — before any
    // lookup, not after one whose answer happened not to change.
    let (replayed, looked) = lookups(|| authority.admit_run(&caller, &first).unwrap());
    assert_eq!(looked, 0, "an admission replay begins no lookup");
    assert_eq!(granted(&replayed), [DECLARED]);

    // The object deleted. The stored grant is re-read for a query — its
    // canonical text, by grammar — and for a replay: no lookup, the grant
    // unchanged.
    std::fs::remove_file(root.join("a.txt")).unwrap();
    let asked = query(&session, &run, epoch);
    let (answer, looked) = lookups(|| authority.dispatch(&caller, &asked).unwrap());
    assert_eq!(looked, 0, "a stored grant is re-read, never resolved");
    let DwkpBody::EffectiveAuthority(answer) = answer else {
        panic!("an answer: {answer:?}")
    };
    let texts: Vec<&str> = answer
        .granted
        .iter()
        .map(|g| g.capability.as_str())
        .collect();
    assert_eq!(texts, [DECLARED]);
    let (replayed, looked) = lookups(|| authority.admit_run(&caller, &first).unwrap());
    assert_eq!(looked, 0, "nor after the object is gone");
    assert_eq!(granted(&replayed), [DECLARED]);

    // A tool target: resolved afresh at invocation — and there is nothing
    // there now.
    let call = FsReadCall {
        path: WorkspacePath::new("/workspace/a.txt").unwrap(),
        max_bytes: ReadLimit::new(8).unwrap(),
    };
    let (reply, looked) = lookups(|| {
        authority
            .tool_invoke(&caller, &session, &run, epoch, &ToolRequest::v1(&call))
            .unwrap()
    });
    assert!(looked > 0, "a tool target is resolved at invocation");
    assert!(
        matches!(reply, ToolReply::Refused(_, FsRefusalReason::NotFound)),
        "{reply:?}"
    );

    evidence("lookups-new-declaration", "resolved");
    evidence("lookups-admission-replay", "0-lookups");
    evidence("lookups-stored-grant-after-delete", "0-lookups");
    evidence("lookups-tool-target", "resolved-at-invocation");
}
