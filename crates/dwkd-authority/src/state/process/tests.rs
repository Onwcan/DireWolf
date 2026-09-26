//! The process pipeline's state machine, in this crate's unit tests
//! (ADR-0045 §2, evidence D and B).
//!
//! A real authority — a store, a policy, a workspace bound to a real
//! directory, real executables resolved and hashed by the real resolver —
//! and an **in-process fake broker**. A fake cannot execute anything and
//! these tests do not claim that it does: they prove what the authority
//! records, decides, refuses and never repeats. Launches are exercised for
//! real by the broker's own suites (evidence C).
//!
//! Two kinds of test live here:
//!
//! * **production floor** — no approval: every host `process.exec` is denied
//!   before any broker contact, whatever policy says;
//! * **after the floor** — inside [`with_test_approval`], the `#[cfg(test)]`
//!   stand-in for M6's per-invocation approval, which no build a user runs
//!   contains.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dwk_proto::brokerp::{BrokerGeneration, BrokerRefusal, Indeterminate};
use dwk_proto::dwkp::procops::{
    ProcessArgs, ProcessExecCall, ProcessKillCall, ProcessStatusCall, ToolCallV3,
};
use dwk_proto::dwkp::{self, DwkpMessage};
use dwk_proto::wire::id::{ProcessId, RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{
    AgentProfileName, Epoch, HostPath, IdempotencyKey, KillOutcome, ProcessArg,
    ProcessDecisionReason, ProcessState, ToolFailureReasonV3, ToolRefusalReasonV3, WorkspacePath,
};

use super::with_test_approval;
use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation,
    ProcessStartDelivery, ProcessStatusDelivery, StreamDelivery,
};
use crate::capability::PrivacyClass;
use crate::resource::exec::lookups_on_this_thread;
use crate::scratch::Scratch;
use crate::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, ConfigFlags, CrashHook,
    CrashPoint, HookAction, ManualClock, Mode, PolicySet, PolicySource, ProcessOutput,
    ProcessReply, ProcessRequest, Reply, StartOptions, StartupConfig, WorkspaceId,
    WorkspaceSensitivity,
};

const START_MS: u64 = 1_758_000_000_000;

const POLICY: &str = r#"schema_version = 1

[meta]
name = "m4d"

[[rule]]
id = "deny-named"
effect = "DENY"
reason = "NO_MATCHING_RULE"
when.verb = "process.exec"
when.executable_in = ["denied-tool"]

[[rule]]
id = "network-denied-tool"
effect = "ALLOW"
when.verb = "process.exec"
when.executable_in = ["netdeny-tool"]
obligations = ["network_deny"]

[[rule]]
id = "hygiene-tool"
effect = "ALLOW"
when.verb = "process.exec"
when.executable_in = ["hygiene-tool"]
obligations = ["workspace_exec_hygiene"]

[[rule]]
id = "capped-tool"
effect = "ALLOW"
when.verb = "process.exec"
when.executable_in = ["capped-tool"]
obligations = ["max_output_bytes=1024", "audit_level=full"]

[[rule]]
id = "approve-reinterpreting"
effect = "REQUIRE_APPROVAL"
reason = "UNKNOWN_EXECUTABLE"
when.verb = "process.exec"
when.argv_safe = false
approval.scope = "executable_and_argv"
approval.ttl = "10m"
approval.max_uses = 1

[[rule]]
id = "allow-host-process"
effect = "ALLOW"
when.verb = ["process.exec", "process.inspect", "process.signal"]
when.environment = "host"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// The fake broker's answers, and what it was asked.
#[derive(Debug, Default)]
struct Fake {
    script: Mutex<VecDeque<Result<BrokerDelivery, BrokerError>>>,
    asked: Mutex<Vec<Asked>>,
    /// Where the store is, to prove what was durable when it was asked.
    store: Mutex<Option<PathBuf>>,
}

/// One order the fake received.
#[derive(Debug, Clone)]
struct Asked {
    operation: &'static str,
    args: Vec<String>,
    stream_limit: Option<u32>,
    /// `(process_invocation INTENT rows, tool_process LAUNCHING rows)` in the
    /// store when the order arrived.
    durable: (i64, i64),
}

fn generation() -> BrokerGeneration {
    BrokerGeneration::new("ab".repeat(16)).unwrap()
}

fn stream(bytes: &[u8]) -> StreamDelivery {
    StreamDelivery {
        content: bytes.to_vec(),
        observed: u64::try_from(bytes.len()).unwrap(),
        truncated: false,
    }
}

impl EffectBroker for Fake {
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        let (args, stream_limit) = match order.operation() {
            Operation::ProcessStart {
                args, stream_limit, ..
            } => (args.clone(), Some(*stream_limit)),
            _ => (Vec::new(), None),
        };
        let durable = self.store.lock().unwrap().as_ref().map_or((0, 0), |db| {
            let conn = rusqlite::Connection::open(db).unwrap();
            let count = |sql: &str| conn.query_row(sql, [], |row| row.get(0)).unwrap();
            (
                count("SELECT count(*) FROM process_invocation WHERE state = 'INTENT'"),
                count("SELECT count(*) FROM tool_process WHERE state = 'LAUNCHING'"),
            )
        });
        self.asked.lock().unwrap().push(Asked {
            operation: order.operation().name(),
            args,
            stream_limit,
            durable,
        });
        if let Some(reply) = self.script.lock().unwrap().pop_front() {
            return reply;
        }
        Ok(match order.operation() {
            Operation::ProcessStart { .. } => {
                BrokerDelivery::ProcessStarted(ProcessStartDelivery {
                    generation: generation(),
                    state: ProcessState::Running,
                    exit_code: None,
                    signal: None,
                })
            }
            Operation::ProcessStatus { .. } => {
                BrokerDelivery::ProcessStatus(ProcessStatusDelivery {
                    state: ProcessState::Exited,
                    exit_code: Some(0),
                    signal: None,
                    timed_out: false,
                    stdout: stream(b"out\x00\xff"),
                    stderr: stream(b""),
                })
            }
            Operation::ProcessKill { .. } => BrokerDelivery::ProcessKilled(KillOutcome::Signaled),
            _ => panic!("not a process operation"),
        })
    }
}

impl Fake {
    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }

    fn then(&self, reply: Result<BrokerDelivery, BrokerError>) {
        self.script.lock().unwrap().push_back(reply);
    }
}

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

fn admit(session: &SessionId, epoch: Epoch, key: &str, requested: &[String]) -> DwkpMessage {
    let caps: Vec<String> = requested.iter().map(|c| format!("\"{c}\"")).collect();
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-21T10:00:01.000Z","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"agent_profile":"operator","skills":[],"requested_capabilities":[{caps}]}}}}"#,
        id = id("msg", 10_000 + u64::try_from(key.len()).unwrap()),
        session = session.as_str(),
        epoch = epoch.get(),
        caps = caps.join(","),
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

/// A tiny file the resolver reads as native. Never executed: the broker is a
/// fake.
const ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00direwolf-m4d-authority-fixture";

struct Fixture {
    scratch: Scratch,
    bin: PathBuf,
    authority: Option<Authority>,
    fake: Arc<Fake>,
    caller: CallerContext,
    session: SessionId,
    epoch: Epoch,
    config: StartupConfig,
}

fn config(host: bool) -> StartupConfig {
    let mut config = StartupConfig::new(
        PolicySet {
            profile: "m4d".to_owned(),
            sources: vec![PolicySource {
                name: "m4d.toml".to_owned(),
                text: POLICY.to_owned(),
            }],
        },
        Mode::Balanced,
        vec![
            "process.exec:*".to_owned(),
            "process.inspect:*".to_owned(),
            "process.signal:*".to_owned(),
            "fs.read:*".to_owned(),
        ],
    );
    config.flags = ConfigFlags {
        security_allow_host_execution: host,
    };
    config
}

fn start(
    state: &Path,
    config: &StartupConfig,
    fake: &Arc<Fake>,
    hook: Option<CrashHook>,
) -> (Authority, crate::state::StartReport) {
    let broker: Arc<dyn EffectBroker> = fake.clone();
    Authority::start(
        state,
        config,
        StartOptions {
            clock: Arc::new(ManualClock::new(START_MS)),
            crash_hook: hook,
            broker: Some(broker),
        },
    )
    .unwrap()
}

/// A real authority with the `m4d` policy, an `operator` profile declaring
/// `declared`, a workspace bound to a real directory, and executables in a
/// trusted directory: `tool` and the policy's named tools.
fn fixture_with(host: bool, declared: &[String], hook: Option<CrashHook>) -> Fixture {
    let scratch = Scratch::new("process-state");
    let root = scratch.path().join("ws");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let bin = scratch.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in [
        "tool",
        "denied-tool",
        "netdeny-tool",
        "hygiene-tool",
        "capped-tool",
    ] {
        let path = bin.join(name);
        std::fs::write(&path, ELF).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let config = config(host);
    let fake = Arc::new(Fake::default());
    let state = scratch.path().join("state");
    let (mut authority, _) = start(&state, &config, &fake, hook);
    *fake.store.lock().unwrap() = Some(state.join("kernel.db"));
    let workspace = WorkspaceId::new("ws").unwrap();
    let session = SessionId::from_uuid(uuid(1)).unwrap();
    {
        let mut operator = authority.operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: declared.to_vec(),
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
        scratch,
        bin,
        authority: Some(authority),
        fake,
        caller,
        session,
        epoch,
        config,
    }
}

fn universal() -> Vec<String> {
    ["process.exec:*", "process.inspect:*", "process.signal:*"]
        .map(str::to_owned)
        .to_vec()
}

fn fixture(host: bool) -> Fixture {
    fixture_with(host, &universal(), None)
}

impl Fixture {
    fn authority(&mut self) -> &mut Authority {
        self.authority.as_mut().unwrap()
    }

    fn tool(&self, name: &str) -> String {
        self.bin.join(name).display().to_string()
    }

    fn run(&mut self, key: &str, requested: &[String]) -> RunId {
        let message = admit(&self.session, self.epoch, key, requested);
        let (caller, authority) = (self.caller, self.authority.as_mut().unwrap());
        match authority.admit_run(&caller, &message).unwrap() {
            Reply::Done(admission) => admission.run_id().clone(),
            Reply::Refused(why) => panic!("admitted: {why:?}"),
        }
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.scratch.path().join("state").join("kernel.db")).unwrap()
    }

    fn rows(&self, sql: &str) -> Vec<String> {
        let conn = self.db();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn invoke(&mut self, run: &RunId, call: ToolCallV3, key: &str) -> ProcessReply {
        let request =
            ProcessRequest::new(call, Some(IdempotencyKey::new(key.to_owned()).unwrap())).unwrap();
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .process_invoke(&caller, &session, run, epoch, &request)
            .unwrap()
    }

    fn preview(&mut self, run: &RunId, call: ToolCallV3) -> ProcessReply {
        let request = ProcessRequest::new(call, None).unwrap();
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .process_preview(&caller, &session, run, epoch, &request)
            .unwrap()
    }
}

fn empty() -> ToolCallV3 {
    ToolCallV3 {
        fs_read: None,
        fs_list: None,
        fs_search: None,
        fs_stat: None,
        fs_write: None,
        fs_patch: None,
        fs_move: None,
        fs_delete: None,
        process_exec: None,
        process_status: None,
        process_kill: None,
    }
}

fn exec(executable: &str, args: &[&str]) -> ToolCallV3 {
    let args: Vec<ProcessArg> = args
        .iter()
        .map(|a| ProcessArg::new((*a).to_owned()).unwrap())
        .collect();
    ToolCallV3 {
        process_exec: Some(ProcessExecCall {
            executable: HostPath::new(executable.to_owned()).unwrap(),
            args: ProcessArgs::new(args).unwrap(),
            cwd: Some(WorkspacePath::new("/workspace/sub".to_owned()).unwrap()),
        }),
        ..empty()
    }
}

fn status(process: &ProcessId) -> ToolCallV3 {
    ToolCallV3 {
        process_status: Some(ProcessStatusCall {
            process_id: process.clone(),
        }),
        ..empty()
    }
}

fn kill(process: &ProcessId) -> ToolCallV3 {
    ToolCallV3 {
        process_kill: Some(ProcessKillCall {
            process_id: process.clone(),
        }),
        ..empty()
    }
}

fn denied(reply: &ProcessReply) -> ProcessDecisionReason {
    match reply {
        ProcessReply::Denied(plan) => plan.action().reason(),
        other => panic!("denied: {other:?}"),
    }
}

fn launched(reply: &ProcessReply) -> ProcessId {
    match reply {
        ProcessReply::Done { output, .. } => match output.as_ref() {
            ProcessOutput::Launched { process_id, .. } => process_id.clone(),
            other => panic!("a launch: {other:?}"),
        },
        other => panic!("done: {other:?}"),
    }
}

fn evidence(case: &str, outcome: &str) {
    println!(
        "PROC-EVIDENCE {{\"suite\":\"authority-process\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

#[test]
fn the_host_floor_refuses_every_launch_without_an_approval_whatever_policy_allows() {
    // Opted out: HOST_EXECUTION_DISABLED, before any broker contact.
    let mut f = fixture(false);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let reply = f.invoke(&run, exec(&tool, &["status"]), "x1");
    assert_eq!(denied(&reply), ProcessDecisionReason::HostExecutionDisabled);
    // Opted in: policy allows, the capability covers — and no approval
    // exists before M6.
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let reply = f.invoke(&run, exec(&tool, &["status"]), "x1");
    let ProcessReply::Denied(plan) = &reply else {
        panic!("denied: {reply:?}")
    };
    assert!(plan.action().record().capability_satisfied());
    assert!(plan.action().policy_satisfied());
    assert_eq!(
        plan.action().reason(),
        ProcessDecisionReason::ApprovalRequired
    );
    assert!(f.fake.asked().is_empty(), "no broker contact");
    assert!(
        f.rows("SELECT invocation_id FROM process_invocation")
            .is_empty()
    );
    assert!(f.rows("SELECT process_id FROM tool_process").is_empty());
    evidence(
        "production-floor-opted-out",
        "HOST_EXECUTION_DISABLED-zero-broker",
    );
    evidence("production-floor-opted-in", "APPROVAL_REQUIRED-zero-broker");
}

#[test]
fn an_approved_launch_is_durable_before_the_broker_and_status_and_kill_follow_it() {
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &["status", "--short"]), "x1"));
    let process = launched(&reply);
    let asked = f.fake.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].operation, "process.start");
    assert_eq!(asked[0].args, ["status", "--short"]);
    assert_eq!(
        asked[0].durable,
        (1, 1),
        "intent and LAUNCHING row durable before the broker"
    );
    assert_eq!(asked[0].stream_limit, Some(131_072));
    assert_eq!(
        f.rows("SELECT state || ':' || broker_generation FROM tool_process"),
        [format!("RUNNING:{}", "ab".repeat(16))]
    );
    // Status: output bytes, exactly; the run is tainted.
    let reply = f.invoke(&run, status(&process), "x2");
    let ProcessReply::Done { output, .. } = &reply else {
        panic!("observed: {reply:?}")
    };
    let ProcessOutput::Observed { state, stdout, .. } = output.as_ref() else {
        panic!("a status")
    };
    assert_eq!(*state, ProcessState::Exited);
    assert_eq!(stdout.content, b"out\x00\xff");
    assert_eq!(f.rows("SELECT state FROM tool_process"), ["EXITED"]);
    // LOCAL_UNVERIFIED is rank 1 (TRUSTED 0, EXTERNAL_UNTRUSTED 2).
    assert_eq!(
        f.rows("SELECT CAST(taint AS TEXT) FROM run_policy_input WHERE run_id = (SELECT run_id FROM tool_process)"),
        ["1"]
    );
    // A status is retry-safe: again, under a new key.
    assert!(matches!(
        f.invoke(&run, status(&process), "x3"),
        ProcessReply::Done { .. }
    ));
    // Kill, after it ended: the broker says so.
    f.fake.then(Ok(BrokerDelivery::ProcessKilled(
        KillOutcome::AlreadyExited,
    )));
    let reply = f.invoke(&run, kill(&process), "x4");
    let ProcessReply::Done { output, .. } = &reply else {
        panic!("killed: {reply:?}")
    };
    assert!(matches!(
        output.as_ref(),
        ProcessOutput::Killed {
            outcome: KillOutcome::AlreadyExited,
            ..
        }
    ));
    let ops: Vec<&str> = f.fake.asked().iter().map(|a| a.operation).collect();
    assert_eq!(
        ops,
        [
            "process.start",
            "process.status",
            "process.status",
            "process.kill"
        ]
    );
    assert_eq!(
        f.rows(
            "SELECT tool || ':' || state || ':' || retry_class FROM process_invocation ORDER BY intent_ms, rowid"
        ),
        [
            "process.exec:COMPLETED:NON_RETRYABLE",
            "process.status:COMPLETED:RETRY_SAFE",
            "process.status:COMPLETED:RETRY_SAFE",
            "process.kill:COMPLETED:NON_RETRYABLE"
        ]
    );
    evidence(
        "durable-intent-before-exec",
        "INTENT+LAUNCHING-before-broker",
    );
    evidence("status-output-taints", "LOCAL_UNVERIFIED");
    evidence("status-retry-safe", "two-statuses");
}

#[test]
fn nothing_reaches_the_broker_without_the_capability_the_policy_or_a_satisfiable_approval() {
    // No process capability at all.
    let mut f = fixture_with(true, &["fs.read:*".to_owned()], None);
    let run = f.run("k1", &["fs.read:*".to_owned()]);
    let tool = f.tool("tool");
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x1"));
    assert_eq!(denied(&reply), ProcessDecisionReason::NoCapability);
    // Policy denies the executable.
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let named = f.tool("denied-tool");
    let reply = with_test_approval(|| f.invoke(&run, exec(&named, &[]), "x1"));
    assert_eq!(denied(&reply), ProcessDecisionReason::DeniedByRule);
    // Policy requires an approval (reinterpreting argv): none exists, and the
    // floor's stand-in is not one.
    let tool = f.tool("tool");
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &["-c", "x", "sh"]), "x2"));
    let ProcessReply::Denied(plan) = &reply else {
        panic!("denied: {reply:?}")
    };
    assert!(plan.action().launch().unwrap().reinterpreting());
    assert_eq!(
        plan.action().reason(),
        ProcessDecisionReason::ApprovalRequired
    );
    // Obligations this build cannot keep.
    for (name, expected) in [
        (
            "netdeny-tool",
            ProcessDecisionReason::ObligationUnenforceable,
        ),
        (
            "hygiene-tool",
            ProcessDecisionReason::ObligationUnenforceable,
        ),
    ] {
        let tool = f.tool(name);
        let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), name));
        assert_eq!(denied(&reply), expected, "{name}");
    }
    assert!(f.fake.asked().is_empty(), "no broker contact");
    // max_output_bytes and audit_level are kept: half each stream.
    let capped = f.tool("capped-tool");
    let reply = with_test_approval(|| f.invoke(&run, exec(&capped, &[]), "x9"));
    let _ = launched(&reply);
    assert_eq!(f.fake.asked()[0].stream_limit, Some(512));
    evidence("no-capability", "NO_CAPABILITY-zero-broker");
    evidence("policy-deny", "DENIED_BY_RULE-zero-broker");
    evidence("policy-approval", "APPROVAL_REQUIRED-zero-broker");
    evidence("network-deny-obligation", "OBLIGATION_UNENFORCEABLE");
    evidence(
        "workspace-exec-hygiene-obligation",
        "OBLIGATION_UNENFORCEABLE",
    );
    evidence("max-output-bytes-1024", "512-per-stream");
}

#[test]
fn status_and_kill_need_their_own_verbs_on_the_identity_the_process_was_launched_as() {
    // The run may launch, and nothing more: observing and signalling are
    // authority of their own.
    let exec_only = vec!["process.exec:*".to_owned()];
    let mut f = fixture_with(true, &exec_only, None);
    let run = f.run("k1", &exec_only);
    let tool = f.tool("tool");
    let process = launched(&with_test_approval(|| {
        f.invoke(&run, exec(&tool, &[]), "x1")
    }));
    let reply = f.invoke(&run, status(&process), "x2");
    assert_eq!(denied(&reply), ProcessDecisionReason::NoCapability);
    let reply = f.invoke(&run, kill(&process), "x3");
    assert_eq!(denied(&reply), ProcessDecisionReason::NoCapability);
    let ops: Vec<&str> = f.fake.asked().iter().map(|a| a.operation).collect();
    assert_eq!(ops, ["process.start"], "neither reached the broker");
    evidence("inspect-gate", "NO_CAPABILITY-zero-broker");
    evidence("signal-gate", "NO_CAPABILITY-zero-broker");
}

#[test]
fn a_key_names_one_invocation_and_an_ambiguous_effect_is_never_repeated() {
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let first = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "same"));
    let process = launched(&first);
    let again = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "same"));
    assert!(matches!(
        again,
        ProcessReply::Refused(_, ToolRefusalReasonV3::IdempotencyKeyReused)
    ));
    // A kill under a used key signals nothing.
    let reply = f.invoke(&run, kill(&process), "k-kill");
    assert!(matches!(reply, ProcessReply::Done { .. }));
    let again = f.invoke(&run, kill(&process), "k-kill");
    assert!(matches!(
        again,
        ProcessReply::Refused(_, ToolRefusalReasonV3::IdempotencyKeyReused)
    ));
    let ops: Vec<&str> = f.fake.asked().iter().map(|a| a.operation).collect();
    assert_eq!(ops, ["process.start", "process.kill"], "each effect once");

    // A launch whose answer never came: UNKNOWN, and its process is not one
    // a status or a kill may name.
    f.fake.then(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::LaunchUnconfirmed),
    )));
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x-unknown"));
    let ProcessReply::Failed { reason, .. } = reply else {
        panic!("failed: {reply:?}")
    };
    assert_eq!(reason, ToolFailureReasonV3::OutcomeUnknown);
    let unknown = f.rows("SELECT process_id FROM tool_process WHERE state = 'UNKNOWN'");
    assert_eq!(unknown.len(), 1);
    let handle = ProcessId::parse(&unknown[0]).unwrap();
    for call in [status(&handle), kill(&handle)] {
        assert!(matches!(
            f.invoke(&run, call, &format!("after-{}", f.fake.asked().len())),
            ProcessReply::Refused(_, ToolRefusalReasonV3::UnknownProcess)
        ));
    }
    // A kill whose answer never came: UNKNOWN too.
    f.fake.then(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::SignalUnconfirmed),
    )));
    let reply = f.invoke(&run, kill(&process), "x-kill-unknown");
    let ProcessReply::Failed { reason, .. } = reply else {
        panic!("failed: {reply:?}")
    };
    assert_eq!(reason, ToolFailureReasonV3::OutcomeUnknown);
    // A launch the broker provably refused: FAILED, and so is its process.
    f.fake
        .then(Err(BrokerError::after_sending(BrokerFailure::Refused(
            BrokerRefusal::DigestMismatch,
        ))));
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x-refused"));
    let ProcessReply::Failed { reason, .. } = reply else {
        panic!("failed: {reply:?}")
    };
    assert_eq!(reason, ToolFailureReasonV3::ExecutableChanged);
    assert_eq!(
        f.rows("SELECT state FROM tool_process ORDER BY created_ms, rowid"),
        ["RUNNING", "UNKNOWN", "FAILED"]
    );
    assert_eq!(
        f.rows(
            "SELECT tool || ':' || state FROM process_invocation WHERE state IN ('UNKNOWN', 'FAILED') ORDER BY rowid"
        ),
        ["process.exec:UNKNOWN", "process.kill:UNKNOWN", "process.exec:FAILED"]
    );
    evidence("exec-key-reuse", "IDEMPOTENCY_KEY_REUSED-one-launch");
    evidence("kill-key-reuse", "IDEMPOTENCY_KEY_REUSED-one-signal");
    evidence("launch-unconfirmed", "UNKNOWN-not-addressable");
    evidence("kill-unconfirmed", "UNKNOWN");
    evidence("launch-refused", "FAILED");
}

#[test]
fn a_process_is_its_runs_alone_and_a_stale_generation_is_unobservable() {
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let process = launched(&with_test_approval(|| {
        f.invoke(&run, exec(&tool, &[]), "x1")
    }));
    // Another run in the same session names it: refused before the broker.
    let other = f.run("k2", &universal());
    for (call, key) in [(status(&process), "o1"), (kill(&process), "o2")] {
        assert!(matches!(
            f.invoke(&other, call, key),
            ProcessReply::Refused(_, ToolRefusalReasonV3::UnknownProcess)
        ));
    }
    // A handle never issued.
    let invented = ProcessId::from_uuid(uuid(777)).unwrap();
    assert!(matches!(
        f.invoke(&run, status(&invented), "o3"),
        ProcessReply::Refused(_, ToolRefusalReasonV3::UnknownProcess)
    ));
    assert_eq!(f.fake.asked().len(), 1, "none of these reached the broker");
    // The broker restarted: its generation no longer holds the process.
    f.fake
        .then(Err(BrokerError::after_sending(BrokerFailure::Refused(
            BrokerRefusal::StaleGeneration,
        ))));
    let reply = f.invoke(&run, status(&process), "s1");
    let ProcessReply::Done { output, .. } = &reply else {
        panic!("observed: {reply:?}")
    };
    assert!(matches!(
        output.as_ref(),
        ProcessOutput::Observed {
            state: ProcessState::Unobservable,
            ..
        }
    ));
    assert_eq!(f.rows("SELECT state FROM tool_process"), ["UNOBSERVABLE"]);
    evidence("wrong-run-status", "UNKNOWN_PROCESS-zero-broker");
    evidence(
        "R10-process-handle-substituted",
        "UNKNOWN_PROCESS-zero-broker",
    );
    evidence("R11-process-of-another-run", "UNKNOWN_PROCESS-zero-broker");
    evidence("wrong-run-kill", "UNKNOWN_PROCESS-zero-broker");
    evidence("stale-generation", "UNOBSERVABLE");
}

#[test]
fn a_new_process_declaration_is_resolved_a_stored_one_is_not_and_new_bytes_are_a_new_authority() {
    let scratch_tool = |f: &Fixture| f.tool("tool");
    let mut f = fixture_with(true, &universal(), None);
    let tool = scratch_tool(&f);
    let declared = vec![format!("process.exec:{tool}")];
    // Re-install the profile declaring the concrete executable.
    {
        let mut operator = f.authority().operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: declared.clone(),
                baseline_skills: Vec::new(),
                privacy_default: PrivacyClass::Any,
            })
            .unwrap();
    }
    let before = lookups_on_this_thread();
    let run = f.run("k1", &declared);
    assert!(
        lookups_on_this_thread() > before,
        "a new declaration is resolved"
    );
    let message = admit(&f.session, f.epoch, "k1", &declared);
    let before = lookups_on_this_thread();
    let caller = f.caller;
    let _ = f.authority().admit_run(&caller, &message).unwrap();
    assert_eq!(
        lookups_on_this_thread(),
        before,
        "a replay resolves nothing"
    );
    // The stored grant: `process.exec:<path>@<digest>`, re-read by grammar.
    let (session, epoch) = (f.session.clone(), f.epoch);
    let before = lookups_on_this_thread();
    let answer = f
        .authority()
        .dispatch(&caller, &query(&session, &run, epoch))
        .unwrap();
    assert_eq!(
        lookups_on_this_thread(),
        before,
        "a stored grant is not resolved"
    );
    let dwk_proto::dwkp::DwkpBody::EffectiveAuthority(answer) = answer else {
        panic!("an answer")
    };
    let digest = {
        use sha2::Digest as _;
        sha2::Sha256::digest(ELF)
            .iter()
            .fold(String::new(), |mut text, b| {
                use core::fmt::Write as _;
                let _ = write!(text, "{b:02x}");
                text
            })
    };
    let granted: Vec<&str> = answer
        .granted
        .iter()
        .map(|g| g.capability.as_str())
        .collect();
    assert_eq!(granted, [format!("process.exec:{tool}@{digest}")]);
    // The grant covers the executable it names — resolved afresh.
    let before = lookups_on_this_thread();
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x1"));
    assert!(
        lookups_on_this_thread() > before,
        "a launch resolves its executable"
    );
    let _ = launched(&reply);
    // New bytes at the same path: the stored grant does not cover them.
    std::fs::write(&tool, b"\x7fELF\x02\x01\x01\x00an updated package").unwrap();
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x2"));
    assert_eq!(denied(&reply), ProcessDecisionReason::NoCapability);
    // Deleted: the grant still reads back, and covers nothing that exists.
    std::fs::remove_file(&tool).unwrap();
    let before = lookups_on_this_thread();
    let answer = f
        .authority()
        .dispatch(&caller, &query(&session, &run, epoch))
        .unwrap();
    assert_eq!(lookups_on_this_thread(), before);
    assert!(matches!(
        answer,
        dwk_proto::dwkp::DwkpBody::EffectiveAuthority(a) if a.granted.len() == 1
    ));
    assert!(matches!(
        with_test_approval(|| f.invoke(&run, exec(&tool, &[]), "x3")),
        ProcessReply::Refused(_, ToolRefusalReasonV3::ExecutableNotFound)
    ));
    evidence("new-process-declaration", "resolved");
    evidence("admission-replay", "0-executable-lookups");
    evidence("stored-process-grant", "0-executable-lookups");
    evidence("launch-lookup", "resolved-at-invocation");
    evidence("changed-hash", "NO_CAPABILITY");
    evidence("deleted-executable", "grant-reads-back-launch-refused");
}

#[test]
fn argv_allowlist_binds_the_first_argument_and_nothing_else() {
    let mut f = fixture(true);
    let tool = f.tool("tool");
    let declared = vec![format!(
        "process.exec:{tool}?argv_allowlist=diff,log,status"
    )];
    {
        let mut operator = f.authority().operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: declared.clone(),
                baseline_skills: Vec::new(),
                privacy_default: PrivacyClass::Any,
            })
            .unwrap();
    }
    let run = f.run("k1", &declared);
    let mut n = 0;
    let mut key = || {
        n += 1;
        format!("a{n}")
    };
    for args in [&["status"][..], &["diff", "--stat"], &["log", "-1"]] {
        let reply = with_test_approval(|| f.invoke(&run, exec(&tool, args), &key()));
        assert!(
            matches!(reply, ProcessReply::Done { .. }),
            "{args:?}: {reply:?}"
        );
    }
    for args in [
        &["push"][..],
        &["-C", "repo", "status"],
        &["--exec-path=/tmp", "status"],
        &["foo", "status"],
        &["statusx"],
        &["stat"],
        &[],
    ] {
        let reply = with_test_approval(|| f.invoke(&run, exec(&tool, args), &key()));
        assert_eq!(
            denied(&reply),
            ProcessDecisionReason::NoCapability,
            "{args:?}"
        );
    }
    evidence("argv-allowlist-positive", "status,diff,log");
    evidence(
        "argv-allowlist-negative",
        "push,-C,--exec-path,foo,statusx,stat,none",
    );
}

#[test]
fn a_preview_decides_the_same_plan_and_changes_nothing() {
    let mut f = fixture(true);
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let preview = f.preview(&run, exec(&tool, &["status"]));
    let ProcessReply::Previewed(plan) = &preview else {
        panic!("previewed: {preview:?}")
    };
    // Without the approval stand-in, as production would.
    assert_eq!(
        plan.action().reason(),
        ProcessDecisionReason::ApprovalRequired
    );
    let first_digest = plan.action().executable().digest().to_string();
    assert!(f.fake.asked().is_empty());
    assert!(
        f.rows("SELECT invocation_id FROM process_invocation")
            .is_empty()
    );
    assert!(f.rows("SELECT process_id FROM tool_process").is_empty());
    // The file changes between preview and invocation: the invocation
    // decides on what is there now, not on what the preview saw.
    std::fs::write(&tool, b"\x7fELF\x02\x01\x01\x00changed after the preview").unwrap();
    let reply = with_test_approval(|| f.invoke(&run, exec(&tool, &["status"]), "x1"));
    let ProcessReply::Done { plan, .. } = &reply else {
        panic!("done: {reply:?}")
    };
    assert_ne!(
        plan.action().executable().digest().to_string(),
        first_digest
    );
    evidence("preview-zero-effect", "no-broker-no-rows");
    evidence("preview-hash-drift", "invocation-rehashes");
}

#[test]
fn a_restart_ends_open_process_invocations_and_repeats_nothing() {
    static ARMED: AtomicBool = AtomicBool::new(false);
    let hook: CrashHook = Arc::new(|point| {
        if point == CrashPoint::ToolAfterIntent && ARMED.load(Ordering::SeqCst) {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    let mut f = fixture_with(true, &universal(), Some(hook));
    let run = f.run("k1", &universal());
    let tool = f.tool("tool");
    let process = launched(&with_test_approval(|| {
        f.invoke(&run, exec(&tool, &[]), "x1")
    }));
    ARMED.store(true, Ordering::SeqCst);
    // E2: a launch stopped after its intent was durable.
    let (caller, session, epoch) = (f.caller, f.session.clone(), f.epoch);
    let request = ProcessRequest::new(
        exec(&tool, &[]),
        Some(IdempotencyKey::new("x2".to_owned()).unwrap()),
    )
    .unwrap();
    assert!(with_test_approval(|| {
        f.authority()
            .process_invoke(&caller, &session, &run, epoch, &request)
            .is_err()
    }));
    // K2 and S1 on a restarted authority come next: first restart.
    ARMED.store(false, Ordering::SeqCst);
    f.authority = None;
    let state = f.scratch.path().join("state");
    let (authority, report) = start(&state, &f.config, &f.fake, None);
    f.authority = Some(authority);
    assert_eq!(report.invocations_unknown, 1);
    assert_eq!(
        f.rows("SELECT state FROM tool_process ORDER BY created_ms, rowid"),
        ["RUNNING", "UNKNOWN"]
    );
    let ops: Vec<&str> = f.fake.asked().iter().map(|a| a.operation).collect();
    assert_eq!(
        ops,
        ["process.start"],
        "the stopped launch was never sent, never retried"
    );
    // The running process survives an authority restart: its record, and the
    // broker generation that holds it, are unchanged.
    let caller = f.authority().connect(AuthenticatedSubject::unix_uid(1000));
    f.caller = caller;
    let (caller, session) = (f.caller, f.session.clone());
    let Reply::Done(epoch) = f.authority().acquire_lease(&caller, &session).unwrap() else {
        panic!("a lease")
    };
    f.epoch = epoch;
    let run = f.run("k-after", &universal());
    assert!(
        matches!(
            f.invoke(&run, status(&process), "after"),
            ProcessReply::Refused(_, ToolRefusalReasonV3::UnknownProcess)
        ),
        "a new run does not inherit the old run's process"
    );
    evidence("restart-open-launch", "UNKNOWN-never-sent");
    evidence("restart-running-process", "record-kept");
}

// ---- the crash campaign (ADR-0045 §17) --------------------------------------

/// Which tool a crash case interrupts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crashed {
    Exec,
    Kill,
    Status,
}

/// One crash case: where it stops (a crash point, or none and a broker
/// failure instead), and what must be recorded after a restart.
struct CrashCase {
    name: &'static str,
    tool: Crashed,
    stop: Option<CrashPoint>,
    broker: Option<Result<BrokerDelivery, BrokerError>>,
    /// The interrupted invocation's state after the restart; `None` when no
    /// invocation may exist.
    recorded: Option<&'static str>,
    /// The launched process's state after the restart.
    process: Option<&'static str>,
    /// How many times the broker was asked for the interrupted operation.
    asked: usize,
}

fn after_sending(failure: BrokerFailure) -> Result<BrokerDelivery, BrokerError> {
    Err(BrokerError::after_sending(failure))
}

fn case(
    name: &'static str,
    tool: Crashed,
    stop: Option<CrashPoint>,
    broker: Option<Result<BrokerDelivery, BrokerError>>,
    (recorded, process, asked): (Option<&'static str>, Option<&'static str>, usize),
) -> CrashCase {
    CrashCase {
        name,
        tool,
        stop,
        broker,
        recorded,
        process,
        asked,
    }
}

fn crash_cases() -> Vec<CrashCase> {
    use crate::broker::Unreachable;
    let io = || BrokerFailure::Unreachable(Unreachable::Io);
    let lost = || BrokerFailure::Protocol("the broker closed the channel early");
    let (exec_, kill_, status_) = (Crashed::Exec, Crashed::Kill, Crashed::Status);
    vec![
        case(
            "E1-before-intent",
            exec_,
            Some(CrashPoint::BeforeTransaction),
            None,
            (None, None, 0),
        ),
        case(
            "E2-after-intent",
            exec_,
            Some(CrashPoint::ToolAfterIntent),
            None,
            (Some("UNKNOWN"), Some("UNKNOWN"), 0),
        ),
        case(
            "E3-broker-accepted-then-lost",
            exec_,
            None,
            Some(after_sending(io())),
            (Some("UNKNOWN"), Some("UNKNOWN"), 1),
        ),
        case(
            "E4-helper-created-broker-lost",
            exec_,
            None,
            Some(after_sending(lost())),
            (Some("UNKNOWN"), Some("UNKNOWN"), 1),
        ),
        case(
            "E5-before-target-exec",
            exec_,
            None,
            Some(after_sending(BrokerFailure::Refused(
                BrokerRefusal::ExecSetupFailed,
            ))),
            (Some("FAILED"), Some("FAILED"), 1),
        ),
        case(
            "E6-exec-handshake-lost",
            exec_,
            None,
            Some(after_sending(BrokerFailure::Indeterminate(
                Indeterminate::LaunchUnconfirmed,
            ))),
            (Some("UNKNOWN"), Some("UNKNOWN"), 1),
        ),
        case(
            "E7-result-before-outcome",
            exec_,
            Some(CrashPoint::ToolAfterBroker),
            None,
            (Some("UNKNOWN"), Some("UNKNOWN"), 1),
        ),
        case(
            "E8-outcome-before-response",
            exec_,
            Some(CrashPoint::ToolAfterOutcome),
            None,
            (Some("COMPLETED"), Some("RUNNING"), 1),
        ),
        case(
            "K1-before-intent",
            kill_,
            Some(CrashPoint::BeforeTransaction),
            None,
            (None, Some("RUNNING"), 0),
        ),
        case(
            "K2-after-intent",
            kill_,
            Some(CrashPoint::ToolAfterIntent),
            None,
            (Some("UNKNOWN"), Some("RUNNING"), 0),
        ),
        case(
            "K3-broker-accepted-then-lost",
            kill_,
            None,
            Some(after_sending(io())),
            (Some("UNKNOWN"), Some("RUNNING"), 1),
        ),
        case(
            "K4-before-signal-broker-lost",
            kill_,
            None,
            Some(after_sending(lost())),
            (Some("UNKNOWN"), Some("RUNNING"), 1),
        ),
        case(
            "K5-signal-may-have-happened",
            kill_,
            None,
            Some(after_sending(BrokerFailure::Indeterminate(
                Indeterminate::SignalUnconfirmed,
            ))),
            (Some("UNKNOWN"), Some("RUNNING"), 1),
        ),
        case(
            "K6-result-before-outcome",
            kill_,
            Some(CrashPoint::ToolAfterBroker),
            None,
            (Some("UNKNOWN"), Some("RUNNING"), 1),
        ),
        case(
            "S1-after-validation",
            status_,
            Some(CrashPoint::ToolAfterIntent),
            None,
            (Some("INTERRUPTED"), Some("RUNNING"), 0),
        ),
        case(
            "S2-broker-inspection-lost",
            status_,
            None,
            Some(after_sending(io())),
            (Some("FAILED"), Some("RUNNING"), 1),
        ),
        case(
            "S3-result-before-outcome",
            status_,
            Some(CrashPoint::ToolAfterBroker),
            None,
            (Some("INTERRUPTED"), Some("RUNNING"), 1),
        ),
    ]
}

#[test]
fn every_crash_point_of_a_launch_a_kill_and_a_status_is_recorded_and_nothing_is_repeated() {
    for case in crash_cases() {
        let armed: Arc<Mutex<Option<CrashPoint>>> = Arc::new(Mutex::new(None));
        let hook: CrashHook = {
            let armed = Arc::clone(&armed);
            Arc::new(move |point| {
                let mut at = armed.lock().unwrap();
                if *at == Some(point) {
                    *at = None;
                    HookAction::Stop
                } else {
                    HookAction::Continue
                }
            })
        };
        let mut f = fixture_with(true, &universal(), Some(hook));
        let run = f.run("k1", &universal());
        let tool = f.tool("tool");
        let process = match case.tool {
            Crashed::Exec => None,
            Crashed::Kill | Crashed::Status => Some(launched(&with_test_approval(|| {
                f.invoke(&run, exec(&tool, &[]), "setup")
            }))),
        };
        let setup_rows = f.rows("SELECT invocation_id FROM process_invocation").len();
        let before = f.fake.asked().len();
        if let Some(reply) = case.broker.clone() {
            f.fake.then(reply);
        }
        *armed.lock().unwrap() = case.stop;
        let call = match (case.tool, &process) {
            (Crashed::Exec, _) => exec(&tool, &[]),
            (Crashed::Kill, Some(p)) => kill(p),
            (Crashed::Status, Some(p)) => status(p),
            _ => unreachable!("a process for kill and status"),
        };
        let (caller, session, epoch) = (f.caller, f.session.clone(), f.epoch);
        let request = ProcessRequest::new(
            call,
            Some(IdempotencyKey::new("crashing".to_owned()).unwrap()),
        )
        .unwrap();
        let answered = with_test_approval(|| {
            f.authority()
                .process_invoke(&caller, &session, &run, epoch, &request)
        });
        assert_eq!(answered.is_err(), case.stop.is_some(), "{}", case.name);
        // A restart, as after a crash: nothing is performed again.
        f.authority = None;
        let state = f.scratch.path().join("state");
        let (authority, _) = start(&state, &f.config, &f.fake, None);
        f.authority = Some(authority);
        assert_eq!(
            f.fake.asked().len() - before,
            case.asked,
            "{}: broker asked",
            case.name
        );
        // The interrupted invocation: every row after the setup's.
        let all = f.rows("SELECT state FROM process_invocation ORDER BY intent_ms, rowid");
        let interrupted: Vec<String> = all.into_iter().skip(setup_rows).collect();
        match case.recorded {
            None => assert!(interrupted.is_empty(), "{}: {interrupted:?}", case.name),
            Some(state) => assert_eq!(interrupted, [state], "{}", case.name),
        }
        let processes = f.rows("SELECT state FROM tool_process ORDER BY created_ms, rowid");
        match case.process {
            None => assert!(processes.is_empty(), "{}: {processes:?}", case.name),
            Some(state) => assert_eq!(
                processes.last().map(String::as_str),
                Some(state),
                "{}",
                case.name
            ),
        }
        evidence(
            &format!("crash-{}", case.name),
            case.recorded.unwrap_or("NOTHING-RECORDED"),
        );
    }
}
