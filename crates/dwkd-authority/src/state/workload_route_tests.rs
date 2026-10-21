//! The public sandboxed `process.exec`'s state machine in this crate's unit
//! tests (M5d.2, ADR-0052 §§2, 4, 8, 9, OD-9): a real authority — a store, a
//! policy, runs admitted over the in-process DWKP dispatcher — and an
//! **in-process fake broker** that prepares, measures, lists and destroys
//! environments and starts and collects workloads from a script, recording
//! what it was asked and what was durable when it was. A fake runs nothing
//! and contains nothing, and these tests do not claim it does: they prove
//! what the authority routes, decides, records, refuses, parks, settles and
//! never repeats. Containment is `make sandbox-workload-evidence`'s, on a
//! real runtime.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dwk_proto::brokerp::sandbox::{
    ContainerRef, ContainerRole, ImageId, InvariantCheck, InvariantChecks, Milliseconds,
    NetworkTopology, RuntimeVersion, SandboxInvariant, Verdict,
};
use dwk_proto::brokerp::workload::{ProcessCount, WorkloadEnding, WorkloadRunDone, WorkloadSpec};
use dwk_proto::brokerp::{
    BrokerGeneration, BrokerRefusal, ContainerState, DestroyState, EnvironmentDestroyDone,
    EnvironmentListDone, EnvironmentMeasureDone, EnvironmentMeasurement, EnvironmentPrepareDone,
    Indeterminate, OwnedEnvironment, OwnedEnvironments, ProcessStreamSnapshot,
};
use dwk_proto::dwkp::sandboxops::{
    ExecLaunch, ExecutionAssurance, ResidueVerdict, SandboxEnding, SandboxedExecResult,
    ToolFailureReasonV5 as F, ToolPlanV5, ToolRefusalReasonV5 as R,
};
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{
    ActionEnvironment, AgentProfileName, ByteCount, DecisionEffect, Epoch, ProcessDecisionReason,
    StreamContent,
};

use sha2::Digest as _;

use super::{Dispatched, Parked};
use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, Collected, EffectBroker, Operation,
    Unreachable,
};
use crate::capability::PrivacyClass;
use crate::sandbox::{SandboxConfig, WorkloadBudget, WorkspaceSetting};
use crate::scratch::Scratch;
use crate::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, CrashHook, CrashPoint,
    HookAction, ManualClock, Mode, PolicySet, PolicySource, Reply, StartOptions, StartupConfig,
    WorkspaceId, WorkspaceSensitivity,
};

const START_MS: u64 = 1_760_000_000_000;

static NEXT_MESSAGE: AtomicU64 = AtomicU64::new(0);

/// The image every test but the image-change one is configured with.
const IMAGE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_IMAGE: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const PROBE: &str = "3333333333333333333333333333333333333333333333333333333333333333";
/// The manifest's executables and their pinned digests.
const FIXTURE: &str = "/opt/tools/fixture";
const FIXTURE_SHA: &str = "abababababababababababababababababababababababababababababababab";
const HYGIENIC: &str = "/opt/tools/hygienic";
const CAPPED: &str = "/opt/tools/capped";
/// A host executable the manifest also names, under the manifest's digest.
const TRUE: &str = "/usr/bin/true";
/// Balanced's known tools, in the image.
const GIT: &str = "/usr/bin/git";
const PYTEST: &str = "/usr/local/bin/pytest";
const CARGO: &str = "/usr/bin/cargo";
const NPM: &str = "/usr/bin/npm";
const TRUE_IN_IMAGE_SHA: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// Sandbox rules only, and a default deny: **not** a shipped pack.
const POLICY: &str = r#"schema_version = 1

[meta]
name = "m5d2"

[[rule]]
id = "hygiene"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["hygienic", "git", "pytest", "cargo", "npm"]
obligations = ["workspace_exec_hygiene"]

[[rule]]
id = "capped"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["capped"]
obligations = ["max_output_bytes=64"]

[[rule]]
id = "allow-sandbox-exec"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"

[[rule]]
id = "allow-fs"
effect = "ALLOW"
when.verb = ["fs.read", "fs.stat"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

fn uuid(n: u64) -> u128 {
    let ts = u128::from(START_MS);
    let n = u128::from(n);
    (ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | (n & ((1 << 62) - 1))
}

fn decode(json: &str) -> DwkpMessage {
    dwkp::decode_body(json.as_bytes()).unwrap_or_else(|e| panic!("decodes: {e}\n{json}"))
}

fn generation(c: char) -> BrokerGeneration {
    BrokerGeneration::new(c.to_string().repeat(32)).unwrap()
}

fn passing() -> EnvironmentMeasurement {
    EnvironmentMeasurement {
        checks: InvariantChecks::new(
            SandboxInvariant::ALL
                .iter()
                .map(|invariant| InvariantCheck {
                    invariant: *invariant,
                    verdict: Verdict::Pass,
                })
                .collect(),
        )
        .unwrap(),
        runtime_version: RuntimeVersion::new("29.8.2".to_owned()),
        measure_ms: Milliseconds::new(5).unwrap(),
    }
}

fn snapshot(bytes: &[u8], observed: u64) -> ProcessStreamSnapshot {
    ProcessStreamSnapshot {
        content: StreamContent::from_bytes(bytes).unwrap(),
        observed: ByteCount::new(observed).unwrap(),
        truncated: observed > u64::try_from(bytes.len()).unwrap(),
    }
}

/// A run that ended as `ending` says, boxed as the link delivers it.
#[allow(clippy::unnecessary_box_returns, reason = "the delivery's own shape")]
fn ran(ending: WorkloadEnding, stdout: &[u8], residue: Verdict) -> Box<WorkloadRunDone> {
    let observed = u64::try_from(stdout.len()).unwrap();
    Box::new(WorkloadRunDone {
        ending,
        exit_code: (ending == WorkloadEnding::Exited)
            .then(|| dwk_proto::wire::scalar::ExitCode::new(3).unwrap()),
        signal: (ending == WorkloadEnding::Killed)
            .then(|| dwk_proto::wire::scalar::SignalNumber::new(9).unwrap()),
        stdout: snapshot(stdout, observed),
        stderr: snapshot(b"", 0),
        elapsed_ms: Milliseconds::new(42).unwrap(),
        residue,
        ended_processes: ProcessCount::new(2).unwrap(),
        remaining_processes: ProcessCount::new(u32::from(residue == Verdict::Fail)).unwrap(),
        redactions: None,
    })
}

type Answer = Result<BrokerDelivery, BrokerError>;

/// What a secret-bearing start handed the fake (M5d.3): the secret as
/// the launcher would be told it, the digest and length of what its pipe
/// held, and what was durable when it arrived.
#[derive(Debug, Clone)]
struct SecretAsked {
    invocation: InvocationId,
    secret: dwk_proto::brokerp::workload::WorkloadSecret,
    digest: [u8; 32],
    len: usize,
    /// `secret_injection` rows open (`INTENT`) when the order arrived.
    intents: i64,
    /// Workload rows `LAUNCHING` when it arrived.
    launching: i64,
}

/// What the fake was asked, beside the operation's name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Asked {
    operation: &'static str,
    invocation: InvocationId,
    workload: Option<WorkloadSpec>,
    generation: Option<BrokerGeneration>,
    /// Workload rows `LAUNCHING` when the order arrived: a start's intent
    /// is durable before it is sent.
    launching: i64,
}

#[derive(Debug, Default)]
struct Fake {
    /// The environments it holds: id, run, container, image.
    live: Mutex<Vec<(EnvironmentId, RunId, ContainerRef, ImageId)>>,
    starts: Mutex<VecDeque<Answer>>,
    collects: Mutex<VecDeque<Answer>>,
    /// Whether each preparation, in order, is kept; then every one is.
    prepares: Mutex<VecDeque<bool>>,
    /// Failures the next preparations end in, before any answer: a
    /// deadline that expired after the order left, say.
    prepare_errors: Mutex<VecDeque<BrokerError>>,
    asked: Mutex<Vec<Asked>>,
    store: Mutex<Option<PathBuf>>,
    containers: AtomicU64,
    /// Every secret-bearing start, in order (M5d.3).
    secrets: Mutex<Vec<SecretAsked>>,
    /// How the next writes end (M5d.4); then each is a clean creation.
    writes: Mutex<VecDeque<Answer>>,
    /// How the next reclamations end (M5d.4); then each finds nothing.
    reclaims: Mutex<VecDeque<Answer>>,
}

impl Fake {
    fn launching(&self) -> i64 {
        self.store.lock().unwrap().as_ref().map_or(0, |db| {
            rusqlite::Connection::open(db)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM workload WHERE state = 'LAUNCHING'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        })
    }

    fn intents(&self) -> i64 {
        self.store.lock().unwrap().as_ref().map_or(0, |db| {
            rusqlite::Connection::open(db)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM secret_injection WHERE state = 'INTENT'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        })
    }

    /// Whether `invocation` was started with a secret.
    fn secret_bearing(&self, invocation: &InvocationId) -> bool {
        self.secrets
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.invocation == *invocation)
    }

    fn record(
        &self,
        operation: &'static str,
        invocation: InvocationId,
        (workload, generation): (Option<WorkloadSpec>, Option<BrokerGeneration>),
    ) {
        let launching = self.launching();
        self.asked.lock().unwrap().push(Asked {
            operation,
            invocation,
            workload,
            generation,
            launching,
        });
    }

    fn operations(&self) -> Vec<&'static str> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.operation)
            .collect()
    }

    fn asked_for(&self, operation: &str) -> Vec<Asked> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.operation == operation)
            .cloned()
            .collect()
    }

    fn then_start(&self, answer: Answer) {
        self.starts.lock().unwrap().push_back(answer);
    }

    fn then_collect(&self, answer: Answer) {
        self.collects.lock().unwrap().push_back(answer);
    }

    fn running(&self, times: usize) {
        for _ in 0..times {
            self.then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Running)));
        }
    }
}

impl EffectBroker for Fake {
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        let (invocation, operation) = order.into_parts();
        match operation {
            Operation::EnvironmentList { .. } => {
                self.record("environment.list", invocation, (None, None));
                let environments = self
                    .live
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(environment, run, container, image)| OwnedEnvironment {
                        container: container.clone(),
                        state: ContainerState::Running,
                        image: Some(image.clone()),
                        environment_id: Some(environment.clone()),
                        run_id: Some(run.clone()),
                        role: Some(ContainerRole::Environment),
                        labels_exact: true,
                    })
                    .collect();
                Ok(BrokerDelivery::EnvironmentListed(EnvironmentListDone {
                    environments: OwnedEnvironments::new(environments).unwrap(),
                    complete: true,
                }))
            }
            Operation::EnvironmentPrepare { spec, .. } => {
                self.record("environment.prepare", invocation, (None, None));
                if let Some(error) = self.prepare_errors.lock().unwrap().pop_front() {
                    return Err(error);
                }
                let n = self.containers.fetch_add(1, Ordering::SeqCst);
                let container = ContainerRef::new(format!("{n:064x}")).unwrap();
                if !self.prepares.lock().unwrap().pop_front().unwrap_or(true) {
                    // Refused and removed: nothing remains.
                    return Ok(BrokerDelivery::EnvironmentPrepared(
                        EnvironmentPrepareDone {
                            container: None,
                            retained: false,
                            measurement: None,
                            prepare_ms: Milliseconds::new(7).unwrap(),
                        },
                    ));
                }
                self.live.lock().unwrap().push((
                    spec.environment_id.clone(),
                    spec.run_id.clone(),
                    container.clone(),
                    spec.image.clone(),
                ));
                Ok(BrokerDelivery::EnvironmentPrepared(
                    EnvironmentPrepareDone {
                        container: Some(container),
                        retained: true,
                        measurement: Some(passing()),
                        prepare_ms: Milliseconds::new(7).unwrap(),
                    },
                ))
            }
            Operation::EnvironmentMeasure { .. } => {
                self.record("environment.measure", invocation, (None, None));
                Ok(BrokerDelivery::EnvironmentMeasured(
                    EnvironmentMeasureDone {
                        state: ContainerState::Running,
                        measurement: Some(passing()),
                        egress: None,
                    },
                ))
            }
            Operation::EnvironmentDestroy {
                environment,
                container,
                ..
            } => {
                self.record("environment.destroy", invocation, (None, None));
                self.live
                    .lock()
                    .unwrap()
                    .retain(|(id, ..)| *id != environment.0);
                Ok(BrokerDelivery::EnvironmentDestroyed(
                    EnvironmentDestroyDone {
                        state: if container.is_some() {
                            DestroyState::Removed
                        } else {
                            DestroyState::AlreadyGone
                        },
                        container,
                        destroy_ms: Milliseconds::new(3).unwrap(),
                        egress: None,
                    },
                ))
            }
            Operation::WorkloadStart { workload, .. } => {
                self.record("workload.start", invocation, (Some(workload), None));
                self.starts
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(BrokerDelivery::WorkloadStarted(generation('a'))))
            }
            // A secret-bearing start (M5d.3): the pipe read once, its
            // digest kept, never its bytes.
            Operation::WorkloadSecretStart {
                workload,
                secret,
                pipe,
                ..
            } => {
                use std::io::Read as _;
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                std::io::PipeReader::from(pipe.into_transfer_descriptor())
                    .read_to_end(&mut bytes)
                    .unwrap();
                let asked = SecretAsked {
                    invocation: invocation.clone(),
                    secret,
                    digest: sha2::Sha256::digest(&*bytes).into(),
                    len: bytes.len(),
                    intents: self.intents(),
                    launching: self.launching(),
                };
                self.secrets.lock().unwrap().push(asked);
                self.record("workload.secret_start", invocation, (Some(workload), None));
                self.starts
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(BrokerDelivery::WorkloadStarted(generation('a'))))
            }
            Operation::WorkloadCollect { generation, .. } => {
                let secret_bearing = self.secret_bearing(&invocation);
                self.record("workload.collect", invocation, (None, Some(generation)));
                self.collects
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| {
                        let mut done = ran(WorkloadEnding::Exited, b"hello", Verdict::Pass);
                        if secret_bearing {
                            done.redactions = dwk_proto::brokerp::workload::RedactionCount::new(0);
                        }
                        Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(done)))
                    })
            }
            // A file operation's, for the shared key namespace's tests.
            Operation::Stat { .. } => {
                self.record("fs.stat", invocation, (None, None));
                Ok(BrokerDelivery::Stat(crate::broker::StatDelivery {
                    kind: dwk_proto::wire::scalar::StatKind::Directory,
                    size: 4096,
                    link_count: 2,
                    mode: 0o755,
                }))
            }
            // A name change and a reclamation (M5d.4), for the workspace's
            // exclusion: the fake performs nothing.
            Operation::Write { .. } => {
                self.record("fs.write", invocation, (None, None));
                self.writes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Ok(BrokerDelivery::Write {
                        created: true,
                        debris: false,
                    }))
            }
            Operation::Reclaim { .. } => {
                self.record("fs.reclaim", invocation, (None, None));
                self.reclaims
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Ok(BrokerDelivery::Reclaim {
                        state: dwk_proto::brokerp::ReclaimState::Absent,
                        holds: None,
                        held: None,
                    }))
            }
            other => panic!("not a sandbox operation: {}", other.name()),
        }
    }
}

struct Fixture {
    scratch: Scratch,
    authority: Option<Authority>,
    fake: Arc<Fake>,
    clock: Arc<ManualClock>,
    caller: Option<CallerContext>,
    session: SessionId,
    epoch: Epoch,
    config: StartupConfig,
}

/// What every fixture's operator profile declares, unless a test asks for
/// more.
const DECLARED: &[&str] = &["process.exec:*", "fs.read:*", "fs.stat:*"];

fn startup(policy: PolicySet, declared: &[&str]) -> StartupConfig {
    StartupConfig::new(
        policy,
        Mode::Balanced,
        declared.iter().map(|c| (*c).to_owned()).collect(),
    )
}

fn custom() -> PolicySet {
    PolicySet {
        profile: "m5d2".to_owned(),
        sources: vec![PolicySource {
            name: "m5d2.toml".to_owned(),
            text: POLICY.to_owned(),
        }],
    }
}

fn stop_at(point: CrashPoint) -> CrashHook {
    Arc::new(move |at| {
        if at == point {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    })
}

fn sandbox(image: &str, manifest: &[(&str, &str)]) -> SandboxConfig {
    SandboxConfig::new(
        TRUE,
        "/run/dw-fake-runtime.sock",
        image,
        PROBE,
        NetworkTopology::NoNetwork,
        WorkspaceSetting::UnverifiedEvidence,
    )
    .unwrap()
    .with_workloads(manifest, WorkloadBudget::default())
    .unwrap()
}

fn manifest() -> Vec<(&'static str, &'static str)> {
    vec![
        (FIXTURE, FIXTURE_SHA),
        (HYGIENIC, FIXTURE_SHA),
        (CAPPED, FIXTURE_SHA),
        (TRUE, TRUE_IN_IMAGE_SHA),
        (GIT, FIXTURE_SHA),
        (PYTEST, FIXTURE_SHA),
        (CARGO, FIXTURE_SHA),
        (NPM, FIXTURE_SHA),
    ]
}

impl Fixture {
    fn new(policy: PolicySet) -> Self {
        Self::with(policy, None)
    }

    /// A fixture whose authority stops at `hook`'s point.
    fn with(policy: PolicySet, hook: Option<CrashHook>) -> Self {
        Self::with_declared(policy, hook, DECLARED)
    }

    /// A fixture whose operator profile, and ceiling, declare `declared`.
    fn with_declared(policy: PolicySet, hook: Option<CrashHook>, declared: &[&str]) -> Self {
        let scratch = Scratch::new("workload-route");
        let root = scratch.path().join("ws");
        std::fs::create_dir_all(&root).unwrap();
        let fake = Arc::new(Fake::default());
        let clock = Arc::new(ManualClock::new(START_MS));
        let config = startup(policy, declared);
        let mut fx = Self {
            scratch,
            authority: None,
            fake,
            clock,
            caller: None,
            session: SessionId::from_uuid(uuid(1)).unwrap(),
            epoch: Epoch::new(1).unwrap(),
            config,
        };
        fx.start(hook);
        *fx.fake.store.lock().unwrap() = Some(fx.state().join("kernel.db"));
        let workspace = WorkspaceId::new("ws").unwrap();
        let session = fx.session.clone();
        {
            let mut operator = fx.authority().operator();
            operator
                .install_agent_profile(&AgentProfileSpec {
                    name: AgentProfileName::new("operator").unwrap(),
                    declared: declared.iter().map(|c| (*c).to_owned()).collect(),
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
        fx.lease();
        fx
    }

    fn start(&mut self, hook: Option<CrashHook>) {
        drop(self.authority.take());
        let broker: Arc<dyn EffectBroker> = self.fake.clone();
        let clock: Arc<dyn crate::state::Clock> = self.clock.clone();
        let (authority, _) = Authority::start(
            &self.state(),
            &self.config,
            StartOptions {
                clock,
                crash_hook: hook,
                broker: Some(broker),
            },
        )
        .unwrap();
        self.authority = Some(authority);
    }

    /// A new incarnation, after a crash: the same store, a new holder.
    fn restart(&mut self, image: Option<&str>) {
        self.start(None);
        if let Some(image) = image {
            self.attach(image);
        }
        self.clock.advance(1);
        self.lease();
    }

    fn lease(&mut self) {
        let caller = self
            .authority()
            .connect(AuthenticatedSubject::unix_uid(1000));
        let session = self.session.clone();
        let Reply::Done(epoch) = self.authority().acquire_lease(&caller, &session).unwrap() else {
            panic!("a lease")
        };
        self.caller = Some(caller);
        self.epoch = epoch;
    }

    fn attach(&mut self, image: &str) {
        self.authority()
            .attach_sandbox(sandbox(image, &manifest()))
            .unwrap();
    }

    fn authority(&mut self) -> &mut Authority {
        self.authority.as_mut().unwrap()
    }

    fn state(&self) -> PathBuf {
        self.scratch.path().join("state")
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.state().join("kernel.db")).unwrap()
    }

    fn one(&self, sql: &str) -> String {
        self.db().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.db().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn events(&self) -> Vec<String> {
        crate::state::read_audit_log(&self.state().join("audit.log"))
            .unwrap()
            .iter()
            .map(|r| r.event().to_owned())
            .collect()
    }

    fn run(&mut self, key: &str, requested: &[&str]) -> RunId {
        let caps: Vec<String> = requested.iter().map(|c| format!("\"{c}\"")).collect();
        let message = decode(&format!(
            r#"{{"v":1,"id":"msg_{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-10-18T10:00:01.000Z","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"agent_profile":"operator","skills":[],"requested_capabilities":[{caps}]}}}}"#,
            id = encode_uuid(uuid(10_000 + NEXT_MESSAGE.fetch_add(1, Ordering::SeqCst))),
            session = self.session.as_str(),
            epoch = self.epoch.get(),
            caps = caps.join(","),
        ));
        let caller = self.caller.unwrap();
        match self.authority().admit_run(&caller, &message).unwrap() {
            Reply::Done(admission) => admission.run_id().clone(),
            Reply::Refused(why) => panic!("admitted: {why:?}"),
        }
    }

    /// The run's environment, prepared and `READY`.
    fn ready(&mut self, run: &RunId) -> EnvironmentId {
        let reply = self.authority().environment_prepare(run).unwrap();
        let crate::state::EnvironmentReply::Ready { report, .. } = reply else {
            panic!("ready: {reply:?}")
        };
        report.environment
    }

    fn message(
        &self,
        run: &RunId,
        version: u8,
        schema: &str,
        key: Option<&str>,
        payload: &str,
    ) -> DwkpMessage {
        let n = NEXT_MESSAGE.fetch_add(1, Ordering::SeqCst);
        decode(&format!(
            r#"{{"v":1,"id":"msg_{id}","type":"request","schema":"{schema}","schema_version":{version},"ts":"2026-10-18T10:00:02.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
            id = encode_uuid(uuid(20_000 + n)),
            session = self.session.as_str(),
            run = run.as_str(),
            epoch = self.epoch.get(),
            key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#)),
        ))
    }

    /// A version-5 `process.exec`, as the server would dispatch it.
    fn exec(&mut self, run: &RunId, key: &str, call: &str) -> Dispatched {
        let message = self.message(
            run,
            5,
            "direwolf.tool.invoke",
            Some(key),
            &format!(r#"{{"process_exec":{call}}}"#),
        );
        let caller = self.caller.unwrap();
        self.authority()
            .dispatch_parkable(&caller, &message)
            .unwrap()
    }

    fn preview(&mut self, run: &RunId, call: &str) -> DwkpBody {
        let message = self.message(
            run,
            5,
            "direwolf.tool.preview",
            None,
            &format!(r#"{{"process_exec":{call}}}"#),
        );
        let caller = self.caller.unwrap();
        self.authority().dispatch(&caller, &message).unwrap()
    }

    /// Any request, answered.
    fn ask(&mut self, message: &DwkpMessage) -> DwkpBody {
        let caller = self.caller.unwrap();
        self.authority().dispatch(&caller, message).unwrap()
    }

    /// Collect a parked launch until it is answered.
    fn settle(&mut self, mut parked: Box<Parked>) -> DwkpBody {
        for _ in 0..100 {
            if let Some(body) = self.authority().resume(&mut parked).unwrap() {
                return body;
            }
        }
        panic!("never ended")
    }

    /// A launch that must have been answered at once.
    fn answered(&mut self, run: &RunId, key: &str, call: &str) -> DwkpBody {
        match self.exec(run, key, call) {
            Dispatched::Answer(body) => body,
            Dispatched::Parked(_) => panic!("parked"),
        }
    }

    /// A launch run to its answer.
    fn ran(&mut self, run: &RunId, key: &str, call: &str) -> DwkpBody {
        match self.exec(run, key, call) {
            Dispatched::Answer(body) => body,
            Dispatched::Parked(parked) => self.settle(parked),
        }
    }
}

fn fixture() -> Fixture {
    let mut fx = Fixture::new(custom());
    fx.attach(IMAGE);
    fx
}

fn call(executable: &str, args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        r#"{{"executable":"{executable}","args":[{}]}}"#,
        args.join(",")
    )
}

fn result(body: &DwkpBody) -> (&ToolPlanV5, &SandboxedExecResult) {
    match body {
        DwkpBody::ToolResultV5(r) => (&r.plan, r.output.process_exec_sandboxed.as_ref().unwrap()),
        other => panic!("not a sandboxed result: {other:?}"),
    }
}

fn refused(body: &DwkpBody) -> R {
    match body {
        DwkpBody::ToolRefusedV5(r) => r.reason,
        other => panic!("not refused: {other:?}"),
    }
}

fn denied(body: &DwkpBody) -> (ActionEnvironment, ProcessDecisionReason, String) {
    match body {
        DwkpBody::ToolDeniedV5(d) => {
            let action = &d.plan.actions.as_slice()[0];
            let decision = action
                .workload
                .as_ref()
                .map(|w| (w.decision.reason, w.decision.rule_id.as_str().to_owned()))
                .or_else(|| {
                    action
                        .process
                        .as_ref()
                        .map(|p| (p.decision.reason, p.decision.rule_id.as_str().to_owned()))
                })
                .unwrap();
            (d.plan.environment, decision.0, decision.1)
        }
        other => panic!("not denied: {other:?}"),
    }
}

fn failed(body: &DwkpBody) -> (F, Option<bool>) {
    match body {
        DwkpBody::ToolFailedV5(f) => (f.reason, f.environment_destroyed),
        other => panic!("not failed: {other:?}"),
    }
}

/// One line of `make sandbox-workload-evidence`'s in-process half, printed
/// only after the assertions before it held. A fake broker: not containment.
fn evidence(case: &str, outcome: &str) {
    println!(
        "WORKLOAD-EVIDENCE {{\"suite\":\"authority-public-exec\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

const GRANT: &str = "process.exec:*";

#[test]
fn a_sandboxed_exec_is_started_parked_collected_and_says_where_and_how_it_ran() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT, "fs.stat:*"]);
    let environment = fx.ready(&run);
    fx.fake.running(3);
    let Dispatched::Parked(mut parked) = fx.exec(&run, "k1", &call(FIXTURE, &["--flag", "a b"]))
    else {
        panic!("a running launch is parked")
    };
    // Started once, its intent durable before the broker heard of it.
    let starts = fx.fake.asked_for("workload.start");
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].launching, 1, "the intent precedes the start");
    let spec = starts[0].workload.clone().unwrap();
    assert_eq!(spec.executable.as_str(), FIXTURE);
    assert_eq!(spec.executable_sha256.as_str(), FIXTURE_SHA);
    let args: Vec<&str> = spec
        .args
        .iter()
        .map(dwk_proto::wire::scalar::ProcessArg::as_str)
        .collect();
    assert_eq!(args, ["--flag", "a b"]);
    assert_eq!(spec.wall_clock.get(), 600);
    assert_eq!(spec.stream_limit.get(), 131_072);
    evidence("public-exec-routed-to-sandbox", "workload.start");
    // While it runs, the authority answers other requests.
    let stat = fx.message(
        &run,
        4,
        "direwolf.tool.invoke",
        Some("stat-1"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    assert!(
        matches!(fx.ask(&stat), DwkpBody::ToolResultV4(_)),
        "a parked launch holds nothing up"
    );
    evidence("parked-launch-blocks-no-request", "answered");
    for _ in 0..3 {
        assert_eq!(fx.authority().resume(&mut parked).unwrap(), None);
    }
    let body = fx.authority().resume(&mut parked).unwrap().unwrap();
    // Every collection named the start's invocation and generation.
    let collects = fx.fake.asked_for("workload.collect");
    assert_eq!(collects.len(), 4);
    assert!(
        collects
            .iter()
            .all(|c| c.invocation == starts[0].invocation && c.generation == Some(generation('a')))
    );
    let (plan, out) = result(&body);
    assert_eq!(plan.environment, ActionEnvironment::Sandbox);
    assert_eq!(plan.effect, DecisionEffect::Allow);
    let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.environment_id.as_ref(), Some(&environment));
    assert_eq!(action.executable.image.as_str(), IMAGE);
    assert_eq!(action.decision.rule_id.as_str(), "allow-sandbox-exec");
    assert_eq!(action.launch, ExecLaunch::Direct);
    assert_eq!(out.environment_id, environment);
    assert_eq!(out.assurance, ExecutionAssurance::ContainerIsolation);
    assert_eq!(out.executable.image.as_str(), IMAGE);
    assert_eq!(out.executable.path.as_str(), FIXTURE);
    assert_eq!(out.executable.sha256.as_str(), FIXTURE_SHA);
    assert_eq!(out.ending, SandboxEnding::Exited);
    assert_eq!(
        out.exit_code.map(dwk_proto::wire::scalar::ExitCode::get),
        Some(3)
    );
    assert_eq!(out.stdout.content.to_bytes(), b"hello");
    assert_eq!(out.stdout.observed.get(), 5);
    assert!(!out.stdout.truncated);
    assert_eq!(out.residue, ResidueVerdict::Pass);
    assert_eq!(out.ended_processes.get(), 2);
    assert!(!out.environment_destroyed);
    evidence(
        "public-exec-result-names-environment-level-identity",
        "complete",
    );
    assert_eq!(
        fx.one("SELECT state FROM workload WHERE idempotency_key = 'k1'"),
        "COMPLETED"
    );
    assert_eq!(fx.count("SELECT count(*) FROM workload_idempotency"), 1);
    let events = fx.events();
    let intent = events
        .iter()
        .position(|e| e == "workload.intent_recorded")
        .unwrap();
    let outcome = events.iter().position(|e| e == "workload.outcome").unwrap();
    assert!(intent < outcome);
}

#[test]
fn the_authority_prepares_the_environment_a_permitted_launch_needs_and_nothing_falls_back() {
    // No sandbox attached: version 4's host path, refused by the floor.
    let mut fx = Fixture::new(custom());
    let run = fx.run("r1", &[GRANT]);
    let body = fx.answered(&run, "k1", &call(TRUE, &[]));
    let (environment, reason, _) = denied(&body);
    assert_eq!(environment, ActionEnvironment::Host);
    assert_eq!(reason, ProcessDecisionReason::HostExecutionDisabled);
    assert!(fx.fake.operations().is_empty());
    evidence("no-sandbox-host-floor-denies", "HOST_EXECUTION_DISABLED");

    // A sandbox, and no environment for the run yet: the authority prepares
    // one -- recorded and measured -- and the launch runs there.
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let body = fx.ran(&run, "k1", &call(FIXTURE, &[]));
    let (plan, out) = result(&body);
    assert_eq!(plan.environment, ActionEnvironment::Sandbox);
    assert_eq!(
        fx.fake.operations(),
        [
            "environment.list",
            "environment.prepare",
            "workload.start",
            "workload.collect"
        ]
    );
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{}'",
            out.environment_id.as_str()
        )),
        "READY"
    );
    evidence("environment-prepared-by-the-authority", "READY");
    // The next launch reuses it.
    let _ = fx.ran(&run, "k2", &call(FIXTURE, &[]));
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), 1);
    // A destroyed one is replaced, not routed around.
    fx.authority()
        .environment_destroy(&out.environment_id)
        .unwrap();
    let body = fx.ran(&run, "k3", &call(FIXTURE, &[]));
    let (_, again) = result(&body);
    assert_ne!(again.environment_id, out.environment_id);
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), 2);
    evidence("destroyed-environment-replaced-no-fallback", "prepared");

    // A denied launch prepares nothing and names no environment.
    let mut fx = fixture();
    let bare = fx.run("r1", &["fs.read:*"]);
    let body = fx.answered(&bare, "d1", &call(FIXTURE, &[]));
    let DwkpBody::ToolDeniedV5(denial) = &body else {
        panic!("denied: {body:?}")
    };
    let action = denial.plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.environment_id, None);
    assert_eq!(action.decision.reason, ProcessDecisionReason::NoCapability);
    assert!(fx.fake.asked_for("environment.prepare").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM environment"), 0);
    evidence("denied-launch-prepares-nothing", "NO_CAPABILITY");
}

#[test]
fn an_environment_that_cannot_be_prepared_refuses_and_its_attempts_are_bounded() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    fx.fake.prepares.lock().unwrap().extend([false; 16]);
    let body = fx.answered(&run, "p1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentUnavailable);
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
    evidence(
        "unpreparable-environment-refused-no-fallback",
        "ENVIRONMENT_UNAVAILABLE",
    );
    // Every attempt is an environment of the run: at most eight, ever.
    let max = usize::try_from(super::super::workload::MAX_ENVIRONMENTS_PER_RUN).unwrap();
    for n in 1..max {
        let body = fx.answered(&run, &format!("p{}", n + 1), &call(FIXTURE, &[]));
        assert_eq!(refused(&body), R::EnvironmentUnavailable, "{n}");
    }
    let body = fx.answered(&run, "p-last", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::BudgetExhausted);
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), max);
    evidence("environment-attempts-bounded", "BUDGET_EXHAUSTED");
}

#[test]
fn a_preparation_past_its_deadline_is_unknown_refused_and_never_on_the_host() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    // The deadline expired after the order left: nothing proves whether a
    // container exists.
    fx.fake
        .prepare_errors
        .lock()
        .unwrap()
        .push_back(BrokerError::after_sending(BrokerFailure::Unreachable(
            Unreachable::Timeout,
        )));
    let body = fx.answered(&run, "t1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentUnavailable);
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
    assert_eq!(
        fx.count("SELECT count(*) FROM environment WHERE state = 'UNKNOWN'"),
        1
    );
    evidence(
        "preparation-timeout-unknown-refused",
        "ENVIRONMENT_UNAVAILABLE",
    );
    // The run's next launch is refused at once: the uncertain environment
    // is its one, and no second broker exchange is made for it.
    let prepares = fx.fake.asked_for("environment.prepare").len();
    let body = fx.answered(&run, "t2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentNotReady);
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), prepares);
    // Another run's launch first ends it -- its destruction is its only end
    // -- then prepares its own and runs there.
    let other = fx.run("r2", &[GRANT]);
    let body = fx.ran(&other, "o1", &call(FIXTURE, &[]));
    let (_, out) = result(&body);
    assert_eq!(out.residue, ResidueVerdict::Pass);
    assert_eq!(fx.fake.asked_for("environment.destroy").len(), 1);
    assert_eq!(
        fx.count("SELECT count(*) FROM environment WHERE state = 'UNKNOWN'"),
        0
    );
    let operations = fx.fake.operations();
    let first_destroy = operations.iter().position(|o| *o == "environment.destroy");
    let last_prepare = operations.iter().rposition(|o| *o == "environment.prepare");
    assert!(first_destroy < last_prepare, "{operations:?}");
    evidence(
        "uncertain-environment-reclaimed-before-another",
        "destroyed",
    );
}

#[test]
fn an_ended_runs_environment_is_reclaimed_and_live_environments_are_bounded() {
    let mut fx = fixture();
    let first = fx.run("r1", &[GRANT]);
    let body = fx.ran(&first, "a1", &call(FIXTURE, &[]));
    let (_, out) = result(&body);
    let ended = out.environment_id.clone();
    let (caller, session, epoch) = (fx.caller.unwrap(), fx.session.clone(), fx.epoch);
    assert!(matches!(
        fx.authority()
            .release_run(&caller, &session, &first, epoch)
            .unwrap(),
        Reply::Done(())
    ));
    // Released, its environment idles until the next preparation ends it.
    let second = fx.run("r2", &[GRANT]);
    let _ = fx.ran(&second, "b1", &call(FIXTURE, &[]));
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{}'",
            ended.as_str()
        )),
        "DESTROYED"
    );
    assert_eq!(fx.fake.asked_for("environment.destroy").len(), 1);
    evidence("ended-runs-environment-reclaimed", "destroyed");
    // Live environments are bounded across runs: with as many as the broker
    // supervises, another launch is refused before anything is prepared.
    let max = usize::try_from(super::super::workload::MAX_LIVE_ENVIRONMENTS).unwrap();
    let mut runs = Vec::new();
    for n in 1..max {
        let run = fx.run(&format!("f{n}"), &[GRANT]);
        fx.ready(&run);
        runs.push(run);
    }
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM environment \
             WHERE state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')"
        ),
        i64::try_from(max).unwrap()
    );
    let extra = fx.run("x1", &[GRANT]);
    let prepares = fx.fake.asked_for("environment.prepare").len();
    let workloads = fx.count("SELECT count(*) FROM workload");
    let body = fx.answered(&extra, "x1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::BudgetExhausted);
    assert_eq!(fx.fake.asked_for("environment.prepare").len(), prepares);
    assert_eq!(fx.count("SELECT count(*) FROM workload"), workloads);
    evidence("live-environments-bounded", "BUDGET_EXHAUSTED");
    // One of them ends: the next launch reclaims it and runs.
    let (caller, epoch) = (fx.caller.unwrap(), fx.epoch);
    let freed = runs.pop().unwrap();
    assert!(matches!(
        fx.authority()
            .release_run(&caller, &session, &freed, epoch)
            .unwrap(),
        Reply::Done(())
    ));
    let body = fx.ran(&extra, "x2", &call(FIXTURE, &[]));
    let (_, out) = result(&body);
    assert_eq!(out.residue, ResidueVerdict::Pass);
    evidence("live-environment-freed-by-an-ended-run", "ran");
}

#[test]
fn nothing_the_call_says_moves_the_launch_and_its_bounds_only_narrow() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    fx.ready(&run);
    let refusal = |fx: &mut Fixture, key: &str, call: &str| refused(&fx.answered(&run, key, call));
    assert_eq!(
        refusal(
            &mut fx,
            "c1",
            r#"{"executable":"/opt/tools/fixture","args":[],"cwd":"/workspace/src"}"#
        ),
        R::WorkingDirectoryUnsupported
    );
    evidence(
        "cwd-other-than-workspace-refused",
        "WORKING_DIRECTORY_UNSUPPORTED",
    );
    assert_eq!(
        refusal(&mut fx, "c2", &call("/opt/tools/not-in-manifest", &[])),
        R::ExecutableNotInImage
    );
    assert_eq!(
        refusal(&mut fx, "c3", &call("/usr/bin/env", &[])),
        R::ExecutableNotInImage
    );
    evidence(
        "executable-not-in-manifest-refused",
        "EXECUTABLE_NOT_IN_IMAGE",
    );
    assert!(fx.fake.asked_for("workload.start").is_empty());
    // A narrowing is honoured; the workspace root is the one directory.
    let body = fx.ran(
        &run,
        "c4",
        r#"{"executable":"/opt/tools/fixture","args":[],"cwd":"/workspace","timeout_seconds":7,"max_stream_bytes":512}"#,
    );
    let (plan, _) = result(&body);
    let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.timeout_seconds.get(), 7);
    assert_eq!(action.max_stream_bytes.get(), 512);
    let spec = fx.fake.asked_for("workload.start")[0]
        .workload
        .clone()
        .unwrap();
    assert_eq!(spec.wall_clock.get(), 7);
    assert_eq!(spec.stream_limit.get(), 512);
    evidence("narrowed-bounds-honoured", "7s-512B");
    // A policy cap narrows further, never widens.
    let body = fx.ran(&run, "c5", &call(CAPPED, &[]));
    let (plan, _) = result(&body);
    let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.max_stream_bytes.get(), 32);
    evidence("policy-cap-narrows-stream-bound", "32B");
}

#[test]
fn one_key_names_one_invocation_across_every_tool_and_a_launch_is_never_run_twice() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT, "fs.stat:*"]);
    fx.ready(&run);
    fx.fake.running(2);
    let Dispatched::Parked(parked) = fx.exec(&run, "k1", &call(FIXTURE, &[])) else {
        panic!("parked")
    };
    // A concurrent duplicate, while the first runs: refused, nothing started.
    let body = fx.answered(&run, "k1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::IdempotencyKeyReused);
    evidence("concurrent-duplicate-key-refused", "IDEMPOTENCY_KEY_REUSED");
    // Another key, the same environment: one at a time.
    let body = fx.answered(&run, "k2", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::EnvironmentBusy);
    evidence("second-launch-while-running-refused", "ENVIRONMENT_BUSY");
    // The workload's key is bound for a file operation too.
    let stat = fx.message(
        &run,
        4,
        "direwolf.tool.invoke",
        Some("k1"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    match fx.ask(&stat) {
        DwkpBody::ToolRefusedV4(r) => assert_eq!(r.reason.as_str(), "IDEMPOTENCY_KEY_REUSED"),
        other => panic!("not refused: {other:?}"),
    }
    let _ = fx.settle(parked);
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    // A file operation's key is bound for a launch.
    let stat = fx.message(
        &run,
        4,
        "direwolf.tool.invoke",
        Some("f1"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    assert!(matches!(fx.ask(&stat), DwkpBody::ToolResultV4(_)));
    let body = fx.answered(&run, "f1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::IdempotencyKeyReused);
    // And once ended, the same key is still never run again.
    let body = fx.answered(&run, "k1", &call(FIXTURE, &[]));
    assert_eq!(refused(&body), R::IdempotencyKeyReused);
    assert_eq!(fx.fake.asked_for("workload.start").len(), 1);
    evidence("key-one-namespace-every-tool", "IDEMPOTENCY_KEY_REUSED");
}

#[test]
fn a_preview_decides_where_it_would_run_and_runs_or_prepares_nothing() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    // No environment yet: the plan, with none named -- and none prepared.
    let body = fx.preview(&run, &call(FIXTURE, &[]));
    let DwkpBody::ToolPreviewedV5(preview) = body else {
        panic!("previewed: {body:?}")
    };
    let action = preview.plan.actions.as_slice()[0]
        .workload
        .as_ref()
        .unwrap();
    assert_eq!(action.environment_id, None);
    assert_eq!(preview.plan.effect, DecisionEffect::Allow);
    assert!(fx.fake.asked_for("environment.prepare").is_empty());
    let environment = fx.ready(&run);
    let body = fx.preview(&run, &call(FIXTURE, &[]));
    let DwkpBody::ToolPreviewedV5(preview) = body else {
        panic!("previewed: {body:?}")
    };
    assert_eq!(preview.plan.environment, ActionEnvironment::Sandbox);
    let action = preview.plan.actions.as_slice()[0]
        .workload
        .as_ref()
        .unwrap();
    assert_eq!(action.environment_id.as_ref(), Some(&environment));
    assert_eq!(
        action.assurance,
        Some(ExecutionAssurance::ContainerIsolation)
    );
    assert!(fx.fake.asked_for("workload.start").is_empty());
    assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
    assert_eq!(fx.count("SELECT count(*) FROM workload_idempotency"), 0);
    evidence("preview-decides-runs-nothing", "SANDBOX");
}

#[test]
fn workspace_exec_hygiene_is_kept_by_the_trusted_launcher_or_denied() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    fx.ready(&run);
    // Kept: the launcher starts it, and the plan says so.
    let body = fx.ran(&run, "h1", &call(HYGIENIC, &["a"]));
    let (plan, _) = result(&body);
    let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.launch, ExecLaunch::Hygiene);
    assert_eq!(action.decision.rule_id.as_str(), "hygiene");
    let start = fx.fake.asked_for("workload.start").pop().unwrap();
    let spec = start.workload.unwrap();
    assert_eq!(
        spec.launch,
        dwk_proto::brokerp::workload::WorkloadLaunch::Hygiene
    );
    evidence("hygiene-kept-by-the-launcher", "HYGIENE");
    // pytest: its cache disabled first, then exactly the call's arguments.
    let body = fx.ran(&run, "h2", &call(PYTEST, &["-q", "tests"]));
    let (plan, _) = result(&body);
    let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
    assert_eq!(action.arg_count.get(), 4);
    let spec = fx
        .fake
        .asked_for("workload.start")
        .pop()
        .unwrap()
        .workload
        .unwrap();
    let args: Vec<&str> = spec
        .args
        .iter()
        .map(dwk_proto::wire::scalar::ProcessArg::as_str)
        .collect();
    assert_eq!(args, ["-p", "no:cacheprovider", "-q", "tests"]);
    evidence("hygiene-pytest-cache-disabled-first", "-p no:cacheprovider");
    // Undone by the call's own arguments, or no real-tool evidence: denied.
    let starts = fx.fake.asked_for("workload.start").len();
    for (key, executable, args) in [
        ("u1", GIT, &["-c", "core.pager=less", "log"][..]),
        ("u2", PYTEST, &["-p", "cacheprovider"]),
        ("u3", CARGO, &["build"]),
        ("u4", NPM, &["install"]),
    ] {
        let body = fx.answered(&run, key, &call(executable, args));
        let (environment, reason, rule) = denied(&body);
        assert_eq!(environment, ActionEnvironment::Sandbox, "{executable}");
        assert_eq!(
            reason,
            ProcessDecisionReason::ObligationUnenforceable,
            "{executable}"
        );
        assert_eq!(rule, "hygiene");
    }
    assert_eq!(fx.fake.asked_for("workload.start").len(), starts);
    evidence(
        "hygiene-undone-or-unevidenced-denied",
        "OBLIGATION_UNENFORCEABLE",
    );
}

#[test]
fn the_shipped_packs_sandbox_rules_run_with_hygiene_kept_or_deny_honestly() {
    // (pack, executable, args, what happens, the rule that decided it)
    for (pack, executable, args, runs, want, want_rule) in [
        // A known tool runs, its hygiene kept by the launcher.
        (
            "balanced",
            GIT,
            &["status"][..],
            true,
            None,
            "allow-known-tools",
        ),
        // A known tool whose hygiene has no real-tool evidence yet: denied.
        (
            "balanced",
            CARGO,
            &["build"],
            false,
            Some(ProcessDecisionReason::ObligationUnenforceable),
            "allow-known-tools",
        ),
        // An unknown one needs an approval, which an unattended run cannot
        // get before M6.
        (
            "balanced",
            TRUE,
            &[],
            false,
            Some(ProcessDecisionReason::DeniedByRule),
            "deny-approval-needed-when-unattended",
        ),
        ("power", TRUE, &[], true, None, "allow-sandbox-exec"),
    ] {
        let mut fx = Fixture::new(PolicySet::shipped(pack).unwrap());
        fx.attach(IMAGE);
        let run = fx.run("r1", &[GRANT]);
        fx.ready(&run);
        let body = fx.ran(&run, "s1", &call(executable, args));
        if runs {
            let (plan, _) = result(&body);
            let action = plan.actions.as_slice()[0].workload.as_ref().unwrap();
            assert_eq!(action.decision.rule_id.as_str(), want_rule, "{pack}");
            assert_eq!(action.launch, ExecLaunch::Hygiene, "{pack} {executable}");
            assert_eq!(fx.fake.asked_for("workload.start").len(), 1, "{pack}");
            evidence(&format!("shipped-{pack}-{want_rule}-runs"), "HYGIENE");
        } else {
            let (environment, reason, rule) = denied(&body);
            assert_eq!(environment, ActionEnvironment::Sandbox, "{pack}");
            assert_eq!(Some(reason), want, "{pack} {executable} {rule}");
            assert_eq!(rule, want_rule, "{pack} {executable}");
            assert!(fx.fake.asked_for("workload.start").is_empty(), "{pack}");
            assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
            evidence(&format!("shipped-{pack}-{rule}-denied"), reason.as_str());
        }
    }
}

#[test]
fn od9_a_concrete_grant_means_the_manifests_executable_in_the_runs_image() {
    let mut fx = fixture();
    // Resolved against the manifest: covers the image's executable.
    let concrete = format!("process.exec:{FIXTURE}");
    let run = fx.run("r1", &[&concrete]);
    fx.ready(&run);
    let body = fx.ran(&run, "o1", &call(FIXTURE, &[]));
    let _ = result(&body);
    assert_eq!(
        fx.one("SELECT capability FROM run_grant WHERE capability LIKE 'process.exec:%'"),
        format!("process.exec:{FIXTURE}@{FIXTURE_SHA}")
    );
    assert_eq!(fx.count("SELECT count(*) FROM run_image"), 1);
    assert_eq!(fx.one("SELECT image FROM run_image"), IMAGE);
    evidence("od9-concrete-grant-resolved-against-manifest", "covers");
    // It covers nothing else.
    let body = fx.answered(&run, "o2", &call(CAPPED, &[]));
    let (_, reason, _) = denied(&body);
    assert_eq!(reason, ProcessDecisionReason::NoCapability);
    // A path the manifest does not name, or another pinned digest: withheld.
    let run2 = fx.run(
        "r2",
        &[
            "process.exec:/opt/tools/absent",
            &format!("process.exec:{FIXTURE}@{TRUE_IN_IMAGE_SHA}"),
        ],
    );
    assert_eq!(
        fx.count(&format!(
            "SELECT count(*) FROM run_grant WHERE run_id = '{}' AND capability LIKE 'process.exec:%'",
            run2.as_str()
        )),
        0
    );
    evidence("od9-unmanifested-grant-withheld", "withheld");
}

#[test]
fn od9_a_host_resolved_grant_covers_no_image_executable() {
    // Admitted before an execution environment was configured: the grant
    // means the host's file, whose digest is not the manifest's.
    let mut fx = Fixture::new(custom());
    let concrete = format!("process.exec:{TRUE}");
    let run = fx.run("r1", &[&concrete]);
    let host = fx.one("SELECT capability FROM run_grant WHERE capability LIKE 'process.exec:%'");
    // The host's canonical file, whichever it is, and its own digest.
    assert!(host.starts_with("process.exec:/usr/"), "{host}");
    assert!(!host.ends_with(TRUE_IN_IMAGE_SHA));
    fx.attach(IMAGE);
    fx.ready(&run);
    let body = fx.answered(&run, "h1", &call(TRUE, &[]));
    let (environment, reason, _) = denied(&body);
    assert_eq!(environment, ActionEnvironment::Sandbox);
    assert_eq!(reason, ProcessDecisionReason::NoCapability);
    assert!(fx.fake.asked_for("workload.start").is_empty());
    evidence("od9-host-resolved-grant-covers-nothing", "NO_CAPABILITY");
}

/// A run never outlives its incarnation and an incarnation attaches one
/// configuration, so a run bound to another image than its environment's,
/// or to another manifest than the authority's, is never produced by the
/// authority itself. The binding is planted in the store -- the one row a
/// test writes -- to prove the guard that stands behind that, before the
/// database's own trigger would.
#[test]
fn od9_a_run_bound_to_another_image_or_manifest_runs_nothing() {
    for (case, image, planted) in [
        ("image", OTHER_IMAGE, None),
        ("manifest", IMAGE, Some("ef".repeat(32))),
    ] {
        let mut fx = Fixture::new(custom());
        let run = fx.run("r1", &[GRANT]);
        let bound = planted.unwrap_or_else(|| {
            super::super::workload::ImageBinding::of(&sandbox(IMAGE, &manifest())).manifest_sha256
        });
        fx.db()
            .execute(
                "INSERT INTO run_image (run_id, image, manifest_sha256, recorded_ms)                  VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![run.as_str(), image, bound],
            )
            .unwrap();
        fx.attach(IMAGE);
        fx.ready(&run);
        let body = fx.answered(&run, "i1", &call(FIXTURE, &[]));
        assert_eq!(refused(&body), R::ImageChanged, "{case}");
        assert!(fx.fake.asked_for("workload.start").is_empty());
        assert_eq!(fx.count("SELECT count(*) FROM workload"), 0);
        evidence(&format!("od9-{case}-changed-refused"), "IMAGE_CHANGED");
    }
}

#[test]
fn an_uncertain_collection_is_unknown_and_costs_the_environment() {
    for (case, answer) in [
        (
            "indeterminate",
            Err(BrokerError::after_sending(BrokerFailure::Indeterminate(
                Indeterminate::WorkloadUnconfirmed,
            ))),
        ),
        (
            "unreachable",
            Err(BrokerError::before_sending(BrokerFailure::Unreachable(
                Unreachable::Connect,
            ))),
        ),
        (
            // A refusal of the collection says nothing of the workload.
            "collection-refused",
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::ChannelMismatch,
            ))),
        ),
        (
            "environment-gone",
            Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(ran(
                WorkloadEnding::EnvironmentGone,
                b"",
                Verdict::Unobservable,
            )))),
        ),
    ] {
        let mut fx = fixture();
        let run = fx.run("r1", &[GRANT]);
        let environment = fx.ready(&run);
        fx.fake.running(1);
        fx.fake.then_collect(answer);
        let body = fx.ran(&run, "u1", &call(FIXTURE, &[]));
        let (reason, destroyed) = failed(&body);
        assert_eq!(reason, F::OutcomeUnknown, "{case}");
        assert_eq!(destroyed, Some(true), "{case}");
        assert_eq!(
            fx.one("SELECT state FROM workload WHERE idempotency_key = 'u1'"),
            "UNKNOWN"
        );
        assert_eq!(
            fx.one(&format!(
                "SELECT state FROM environment WHERE environment_id = '{}'",
                environment.as_str()
            )),
            "DESTROYED",
            "{case}"
        );
        assert!(fx.fake.operations().contains(&"environment.destroy"));
        evidence(
            &format!("collection-{case}-unknown-destroyed"),
            "OUTCOME_UNKNOWN",
        );
    }
}

#[test]
fn a_run_that_never_began_or_a_refused_start_fails_and_runs_nothing() {
    // The supervisor could not start the runtime's client after answering.
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::NeverRan(
            BrokerRefusal::ExecSetupFailed,
        ))));
    let body = fx.ran(&run, "n1", &call(FIXTURE, &[]));
    let (reason, destroyed) = failed(&body);
    assert_eq!(reason, F::BrokerExecutionError);
    assert_eq!(destroyed, Some(false));
    assert_eq!(
        fx.one("SELECT state FROM workload WHERE idempotency_key = 'n1'"),
        "FAILED"
    );
    evidence("never-ran-failed-kept", "FAILED");
    // A start refused for the executable's bytes, or a drifted environment.
    for (refusal, expected, destroys) in [
        (BrokerRefusal::DigestMismatch, F::ExecutableChanged, false),
        (
            BrokerRefusal::EnvironmentNotClean,
            F::EnvironmentNotClean,
            true,
        ),
        (BrokerRefusal::WorkloadInUse, F::BrokerExecutionError, false),
    ] {
        let mut fx = fixture();
        let run = fx.run("r1", &[GRANT]);
        fx.ready(&run);
        fx.fake
            .then_start(Err(BrokerError::after_sending(BrokerFailure::Refused(
                refusal,
            ))));
        let body = fx.answered(&run, "s1", &call(FIXTURE, &[]));
        let (reason, destroyed) = failed(&body);
        assert_eq!(reason, expected, "{refusal:?}");
        assert_eq!(destroyed, Some(destroys), "{refusal:?}");
        assert!(fx.fake.asked_for("workload.collect").is_empty());
        evidence(
            &format!("start-refused-{}", refusal.as_str().to_lowercase()),
            expected.as_str(),
        );
    }
    let _ = environment;
}

#[test]
fn a_residue_not_proved_clean_is_answered_and_takes_the_environment_down() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let environment = fx.ready(&run);
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::TimedOut, b"partial", Verdict::Fail),
        ))));
    let body = fx.ran(&run, "r1", &call(FIXTURE, &[]));
    let (_, out) = result(&body);
    assert_eq!(out.ending, SandboxEnding::TimedOut);
    assert_eq!(out.residue, ResidueVerdict::Fail);
    assert!(out.environment_destroyed);
    assert_eq!(
        fx.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{}'",
            environment.as_str()
        )),
        "DESTROYED"
    );
    evidence("residue-fail-environment-destroyed", "destroyed");
}

/// W8–W11 (ADR-0052 §9) through the public route: a crash at each window,
/// then a restart -- the workload `UNKNOWN` (or its outcome kept), its
/// environment destroyed when nothing proves it quiet, and the key never
/// run again.
#[test]
fn a_crash_in_every_window_of_the_public_route_is_never_run_again() {
    for (point, state, destroyed) in [
        (CrashPoint::WorkloadAfterIntent, "UNKNOWN", true),
        (CrashPoint::WorkloadAfterStart, "UNKNOWN", true),
        (CrashPoint::WorkloadAfterBroker, "UNKNOWN", true),
        (CrashPoint::WorkloadAfterOutcome, "COMPLETED", false),
    ] {
        let mut fx = Fixture::with(custom(), Some(stop_at(point)));
        fx.attach(IMAGE);
        let run = fx.run("r1", &[GRANT]);
        let environment = fx.ready(&run);
        let message = fx.message(
            &run,
            5,
            "direwolf.tool.invoke",
            Some("w1"),
            &format!(r#"{{"process_exec":{}}}"#, call(FIXTURE, &[])),
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
        let starts = fx.fake.asked_for("workload.start").len();
        fx.restart(Some(IMAGE));
        assert_eq!(
            fx.one("SELECT state FROM workload WHERE idempotency_key = 'w1'"),
            state,
            "{point}"
        );
        let environment_state = fx.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{}'",
            environment.as_str()
        ));
        assert_eq!(
            environment_state == "DESTROYED",
            destroyed,
            "{point}: {environment_state}"
        );
        // The retry of the same key, after the restart: refused, never run.
        // The run is fenced by the new epoch; a run of the new one asks.
        let run = fx.run("r2", &[GRANT]);
        let message = fx.message(
            &run,
            5,
            "direwolf.tool.invoke",
            Some("w1"),
            &format!(r#"{{"process_exec":{}}}"#, call(FIXTURE, &[])),
        );
        assert_eq!(
            refused(&fx.ask(&message)),
            R::IdempotencyKeyReused,
            "{point}"
        );
        assert_eq!(fx.fake.asked_for("workload.start").len(), starts, "{point}");
        evidence(
            &format!("crash-{}-public-route", point.letter()),
            &format!("{state}-never-rerun"),
        );
    }
}

#[test]
fn the_broker_is_asked_only_what_the_authority_decided() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    fx.ready(&run);
    let hostile = [
        "--user",
        "0",
        "--privileged",
        "-e",
        "LD_PRELOAD=/x",
        "$(id)",
        "--workdir",
        "/",
    ];
    let _ = fx.ran(&run, "a1", &call(FIXTURE, &hostile));
    let spec = fx.fake.asked_for("workload.start")[0]
        .workload
        .clone()
        .unwrap();
    let args: Vec<&str> = spec
        .args
        .iter()
        .map(dwk_proto::wire::scalar::ProcessArg::as_str)
        .collect();
    // Exactly the arguments, as data; nothing else rides in the start.
    assert_eq!(args, hostile);
    assert_eq!(spec.executable.as_str(), FIXTURE);
    evidence("hostile-arguments-are-data", "exact");
}

// A sandboxed launch's credential (M5d.3): this fake, and real keyring values.
#[path = "workload_secret_tests.rs"]
mod secret;

/// M5d.4: the workspace contract on the authority's side.
#[path = "workspace_route_tests.rs"]
mod workspace;
