//! The public `process.exec` in an execution environment (M5d.2, ADR-0052
//! §2): tool messages at version 5.
//!
//! **The kernel decides where it runs** (OD-1). An authority with an
//! execution environment attached runs `process.exec` in the run's `READY`
//! environment, measured at `CONTAINER_ISOLATION` or above, and nowhere
//! else; one without runs version 4's host path, decided and refused by the
//! host floor. Nothing the request says moves it: the call names an
//! executable path, the arguments, at most the workspace root as its working
//! directory, and at most a narrowing of the wall clock and the stream bound.
//!
//! **No fallback.** A sandboxed launch whose environment cannot be prepared,
//! is not `READY`, is below the level, busy, of another image than the run
//! was admitted against, or drifts before it runs, is refused or fails — it
//! is never retried on the host.
//!
//! **The environment is the authority's.** A run gets one when a launch it
//! is permitted needs one: the operator's configuration names the image, the
//! probe, the topology and the manifest; the run's grants name its egress;
//! nothing the request says chooses any of it, and no DWKP operation reaches
//! the lifecycle. A denied launch prepares, and reveals, no environment.
//!
//! # The order
//!
//! | step | where | can it run? |
//! |---|---|---|
//! | 1. the fence, the run, the key in the one namespace every tool shares; the call's own bounds; the executable the manifest names | transaction | no |
//! | 2. both gates for a **sandbox** action; then the environment, the image binding, idle, the budget; the intent and the key, audited | the same transaction | no |
//! | 2a. a permitted launch whose run has no live environment: at most one environment that can never run a workload again is destroyed ([`workload::reclaimable`]); then, below [`workload::MAX_LIVE_ENVIRONMENTS`] across every run, the authority prepares one -- recorded, measured, judged (ADR-0047's lifecycle) -- within [`workload::MAX_ENVIRONMENTS_PER_RUN`], and step 2 again | the environment's own transactions | no |
//! | 3. the runtime client resolved and hashed; the workspace re-pinned; the broker's start | no transaction | the broker re-judges and proves first |
//! | 4. collections, between the worker's other requests, until it ends (the request is **parked**: [`Dispatched::Parked`]) | no transaction | yes |
//! | 5. the outcome, redacted output, taint, and — when uncertain — the environment's destruction | transaction | recorded |
//!
//! A key names one invocation for ever: a key bound to anything — a file
//! operation, a host process, a request, a workload — is refused
//! (`IDEMPOTENCY_KEY_REUSED`) and nothing is run again, before or after a
//! restart. A workload the restart found `LAUNCHING` is `UNKNOWN` and its
//! environment destroyed (W8–W10, `super::workload::reconcile_open`).
//!
//! # `workspace_exec_hygiene`
//!
//! Kept by the **trusted launcher** (ADR-0052 §5a): the broker starts the
//! workload through the digest-pinned probe, which sets the obligation's
//! fixed variables and executes the program; the tool's neutralising
//! arguments go first in the argv the plan states. An invocation whose own
//! arguments would undo it, or a tool with no real-tool evidence yet, is
//! `OBLIGATION_UNENFORCEABLE` (`resource::exec::hygiene`). It neutralises
//! configuration from outside the invocation, never the workspace's own
//! code: the environment contains that.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::sandbox::{AssuranceLevel, ImageId, Verdict};
use dwk_proto::brokerp::workload::WorkloadEnding;
use dwk_proto::dwkp::netops::CoreToolV4;
use dwk_proto::dwkp::procops::{ProcessActionDecision, ProcessExecCall, ProcessStreamSnapshot};
use dwk_proto::dwkp::sandboxops::{
    CanonicalPreviewResultV5, ExecLaunch, ExecMilliseconds, ExecSeconds, ExecStreamLimit,
    ExecutionAssurance, ImageDigest, ImageExecutableRef, MAX_EXEC_STREAM_BYTES, PlannedActionV5,
    PlannedActionsV5, PlannedWorkloadAction, ProcessExecCallV5, ReapedCount, ResidueVerdict,
    SandboxEnding, SandboxedExecResult, ToolCallV5, ToolDenialV5, ToolFailureReasonV5,
    ToolFailureV5, ToolOutputV5, ToolPlanV5, ToolRefusalReasonV5, ToolRefusalV5, ToolResultV5,
};
use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{EnvironmentId, RunId, SessionId};
use dwk_proto::wire::scalar::{
    ActionEnvironment, ActionRole, ArgCount, ArgvSafetyClass, ByteCount, ContentDigest,
    DecisionEffect, Epoch, HostPath, IdempotencyKey, ProcessDecisionReason, ProcessVerb,
    StreamContent, ToolOperation,
};
use rusqlite::OptionalExtension as _;

use crate::resource::exec::argv::ArgvClass;

use super::Authority;
use super::Work;
use super::audit::{AuditEvent, Fields};
use super::crash::CrashPoint;
use super::environment_ops::Attached;
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease;
use super::policy_state::ActiveAuthority;
use super::tool;
use super::wire::{self, WireGap};
use super::workload::{
    self, Begun, Binding, Checked, Decided, ImageBinding, Missing, Previewed, ReadyEnvironment,
    WorkloadPlan, WorkloadRequest,
};
use super::workload_ops::{self, Launched, Started, WorkloadOutcome, WorkloadReply};

/// How long the worker waits between two collections of one workload.
const COLLECT_EVERY: Duration = Duration::from_millis(250);

/// The most sandboxed launches a server holds parked: as many as the broker
/// supervises.
pub const MAX_PARKED: usize = dwk_proto::brokerp::workload::MAX_SUPERVISED_WORKLOADS;

/// What a dispatched request came to.
#[allow(
    clippy::large_enum_variant,
    reason = "an answer is moved once, to its connection; a parked launch is boxed"
)]
#[derive(Debug)]
pub enum Dispatched {
    /// Its answer.
    Answer(DwkpBody),
    /// A sandboxed launch the broker supervises: [`Authority::resume`]
    /// collects it, and answers it once it ends.
    Parked(Box<Parked>),
}

/// A sandboxed `process.exec` the broker is running (ADR-0052 §8). Its
/// intent, its key and its budget are durable; only the authority that
/// started it collects and settles it. Dropped unsettled — the authority
/// stopped — it is `UNKNOWN` at the next start, and its environment
/// destroyed.
#[derive(Debug)]
pub struct Parked {
    started: Started,
    answer: Answer,
    next: Instant,
}

impl Parked {
    /// When it should next be collected.
    #[must_use]
    pub const fn due(&self) -> Instant {
        self.next
    }
}

/// What a sandboxed launch's answer states besides its ending.
#[derive(Debug, Clone)]
struct Answer {
    plan: ToolPlanV5,
    environment: EnvironmentId,
    assurance: ExecutionAssurance,
    executable: ImageExecutableRef,
}

/// Who asks, about what.
struct Asked<'a> {
    caller: &'a CallerContext,
    session: &'a SessionId,
    run: &'a RunId,
    epoch: Epoch,
    key: Option<&'a IdempotencyKey>,
    operation: ToolOperation,
}

/// What step 1 and 2 decided.
enum Route {
    Refused(ToolRefusalReasonV5),
    Denied(Box<Decided>, Box<Checked>),
    Previewed(Box<Decided>, Box<Checked>),
    /// Permitted, and the run has no live environment: prepare one.
    NeedsEnvironment,
    Intent(Box<workload::Intent>, Box<Checked>),
}

fn unrepresentable(_: WireGap) -> AuthorityError {
    AuthorityError::Invariant("a stored value does not fit the wire type that carries it")
}

/// The refusal class a ledger reason is answered with. The bounds a typed
/// call cannot break are a bug if they are ever reached.
fn refusal(reason: &str) -> Result<ToolRefusalReasonV5, AuthorityError> {
    use ToolRefusalReasonV5 as R;
    Ok(match reason {
        "UNKNOWN_RUN" | "RUN_NOT_ACTIVE" => R::UnknownRun,
        "NO_WORKSPACE" | "NO_WORKSPACE_ROOT" => R::WorkspaceUnbound,
        "WORKSPACE_UNAVAILABLE" => R::RootUnavailable,
        "IDEMPOTENCY_KEY_REUSED" => R::IdempotencyKeyReused,
        "EXECUTABLE_NOT_IN_MANIFEST" => R::ExecutableNotInImage,
        "ARGV_TOO_LARGE" | "ARGUMENT_INVALID" => R::ArgvTooLarge,
        "WORKING_DIRECTORY_UNSUPPORTED" => R::WorkingDirectoryUnsupported,
        "NO_ENVIRONMENT" => R::NoEnvironment,
        "ENVIRONMENT_NOT_READY" => R::EnvironmentNotReady,
        "ENVIRONMENT_UNAVAILABLE" => R::EnvironmentUnavailable,
        "ASSURANCE_INSUFFICIENT" => R::AssuranceInsufficient,
        "ENVIRONMENT_BUSY" => R::EnvironmentBusy,
        "IMAGE_CHANGED" => R::ImageChanged,
        "BUDGET_EXHAUSTED" | "ENVIRONMENT_BUDGET_EXHAUSTED" | "LIVE_ENVIRONMENTS_EXHAUSTED" => {
            R::BudgetExhausted
        }
        _ => {
            return Err(AuthorityError::Invariant(
                "a typed sandboxed launch broke a bound its type holds",
            ));
        }
    })
}

/// The failure class a recorded failure is answered with.
fn failure(reason: &str) -> ToolFailureReasonV5 {
    use ToolFailureReasonV5 as F;
    match reason {
        "ENVIRONMENT_NOT_CLEAN" => F::EnvironmentNotClean,
        "ENVIRONMENT_NOT_FOUND" | "FOREIGN_ENVIRONMENT" | "ENVIRONMENT_AMBIGUOUS" => {
            F::EnvironmentUnavailable
        }
        "EXECUTABLE_DIGEST_MISMATCH" => F::ExecutableChanged,
        "IMAGE_MISSING"
        | "RUNTIME_UNAVAILABLE"
        | "RUNTIME_FAILED"
        | "RUNTIME_OUTPUT_MALFORMED"
        | "TOPOLOGY_UNAVAILABLE"
        | "PROXY_UNAVAILABLE"
        | "RUNTIME_CLIENT_UNTRUSTED"
        | "RUNTIME_CLIENT_CHANGED"
        | "RUNTIME_CWD_UNAVAILABLE" => F::RuntimeUnavailable,
        "BROKER_UNAVAILABLE" => F::BrokerUnavailable,
        "BROKER_PROTOCOL_ERROR" => F::BrokerProtocolError,
        _ => F::BrokerExecutionError,
    }
}

const fn assurance(level: AssuranceLevel) -> ExecutionAssurance {
    match level {
        AssuranceLevel::None => ExecutionAssurance::None,
        AssuranceLevel::ProcessIsolation => ExecutionAssurance::ProcessIsolation,
        AssuranceLevel::ContainerIsolation => ExecutionAssurance::ContainerIsolation,
        AssuranceLevel::VmIsolation => ExecutionAssurance::VmIsolation,
    }
}

/// Step 1's own checks of a typed call: the working directory, then the
/// manifest and the bounds ([`workload::check`]). The wall clock and the
/// stream bound are the authority's, narrowed only if the call narrows them.
fn checked(
    call: &ProcessExecCallV5,
    key: &str,
    config: &crate::sandbox::SandboxConfig,
) -> Result<Checked, &'static str> {
    if call
        .cwd
        .as_ref()
        .is_some_and(|cwd| cwd.as_str() != "/workspace")
    {
        return Err("WORKING_DIRECTORY_UNSUPPORTED");
    }
    let request = WorkloadRequest {
        executable: call.executable.as_str().to_owned(),
        args: call.args.iter().map(|a| a.as_str().to_owned()).collect(),
        stream_limit: call
            .max_stream_bytes
            .map_or(MAX_EXEC_STREAM_BYTES, ExecStreamLimit::get),
        wall_clock_seconds: call
            .timeout_seconds
            .map_or(config.workload_max_seconds(), ExecSeconds::get)
            .min(config.workload_max_seconds()),
        key: key.to_owned(),
    };
    workload::check(&request, config)
}

/// Whether a key is bound in any of the four ledgers.
fn key_bound(work: &Work<'_>, asked: &Asked<'_>, key: &str) -> Result<bool, AuthorityError> {
    let found: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM workload_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3 UNION ALL SELECT 1 FROM tool_idempotency WHERE \
             subject = ?1 AND session_id = ?2 AND idempotency_key = ?3 UNION ALL SELECT 1 \
             FROM process_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3 UNION ALL SELECT 1 FROM net_idempotency WHERE \
             subject = ?1 AND session_id = ?2 AND idempotency_key = ?3 LIMIT 1",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                key
            ],
            |row| row.get(0),
        )
        .optional())?;
    Ok(found.is_some())
}

/// Record a refusal of the fence, the run or the key, and answer it.
fn refused(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: ToolRefusalReasonV5,
) -> Result<Route, AuthorityError> {
    work.audit(
        AuditEvent::ToolRefused,
        Fields::new()
            .text("operation", asked.operation.as_str())
            .text("tool", "process.exec")
            .int("protocol_version", 5)
            .text("environment", "SANDBOX")
            .text("subject", asked.caller.subject().storage_key())
            .text("session_id", asked.session.as_str())
            .text("run_id", asked.run.as_str())
            .text("reason", reason.as_str()),
    )?;
    Ok(Route::Refused(reason))
}

/// Steps 1 and 2, in one transaction.
fn route(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    call: &ProcessExecCallV5,
    (attached, active, image): (&Attached, &ActiveAuthority, &ImageBinding),
    prepared: bool,
) -> Result<Route, AuthorityError> {
    if !lease::fence(work, asked.caller, asked.session, asked.epoch)? {
        return refused(work, asked, ToolRefusalReasonV5::StaleEpoch);
    }
    if !tool::run_is_held(
        work,
        asked.caller,
        asked.session,
        asked.run,
        asked.epoch,
        active,
    )? {
        return refused(work, asked, ToolRefusalReasonV5::UnknownRun);
    }
    if let Some(key) = asked.key
        && key_bound(work, asked, key.as_str())?
    {
        return refused(work, asked, ToolRefusalReasonV5::IdempotencyKeyReused);
    }
    // A preview binds no key; the check needs one in its grammar.
    let key = asked.key.map_or("preview", IdempotencyKey::as_str);
    let checked = match checked(call, key, &attached.config) {
        Ok(checked) => checked,
        Err(reason) => {
            workload::refuse(work, asked.run, call.executable.as_str(), reason)?;
            return Ok(Route::Refused(refusal(reason)?));
        }
    };
    let budget = attached.config.workload_budget();
    let subject = asked.caller.subject().storage_key();
    let binding = Binding::Session {
        subject: &subject,
        session: asked.session,
    };
    if asked.key.is_none() {
        return Ok(
            match workload::preview(work, asked.run, &checked, (budget, active, image), &binding)? {
                Previewed::Refused(reason) => Route::Refused(refusal(reason)?),
                Previewed::Decided(decided) => Route::Previewed(decided, Box::new(checked)),
            },
        );
    }
    let missing = if prepared {
        Missing::Refuse
    } else {
        Missing::Prepare
    };
    Ok(
        match workload::begin(
            work,
            asked.run,
            &checked,
            (budget, active, image),
            (&binding, missing),
        )? {
            Begun::Refused(reason) => Route::Refused(refusal(reason)?),
            Begun::Denied(decided) => Route::Denied(decided, Box::new(checked)),
            // The in-process API bound this key in the run: never run twice.
            Begun::Replayed(_) => Route::Refused(ToolRefusalReasonV5::IdempotencyKeyReused),
            Begun::NeedsEnvironment => Route::NeedsEnvironment,
            Begun::Intent(intent) => Route::Intent(intent, Box::new(checked)),
        },
    )
}

/// The executable a sandboxed launch is decided on: the image's.
fn executable(checked: &Checked, image: &ImageId) -> Result<ImageExecutableRef, WireGap> {
    Ok(ImageExecutableRef {
        image: ImageDigest::new(image.as_str()).ok_or(WireGap::Unrepresentable("an image"))?,
        path: HostPath::new(checked.executable.as_str())
            .ok_or(WireGap::Unrepresentable("an image path"))?,
        sha256: ContentDigest::new(checked.sha256.as_str())
            .ok_or(WireGap::Unrepresentable("an executable digest"))?,
    })
}

/// A sandboxed launch's plan on the version-5 wire: its one action, both
/// gates, the environment chosen, its level, and the bounds. Never the
/// arguments: those are in the audit record.
fn plan(
    environment: Option<&ReadyEnvironment>,
    decided: &WorkloadPlan,
    checked: &Checked,
    image: &ImageId,
) -> Result<ToolPlanV5, WireGap> {
    let executed = decided.executed(checked);
    let policy = decided.record.policy();
    let (rule_id, rule_source) = wire::rule(policy.rule_id().as_str(), policy.rule_source())?;
    let reason = decided.reason();
    let reason = ProcessDecisionReason::ALL
        .iter()
        .copied()
        .find(|r| r.as_str() == reason)
        .ok_or(WireGap::Unrepresentable("a decision reason"))?;
    let effect = if decided.permits() {
        DecisionEffect::Allow
    } else {
        DecisionEffect::Deny
    };
    let action = PlannedWorkloadAction {
        role: ActionRole::Target,
        verb: ProcessVerb::ProcessExec,
        executable: executable(checked, image)?,
        environment_id: environment.map(|e| e.environment.clone()),
        assurance: environment.map(|e| assurance(e.level)),
        launch: match decided.launch {
            dwk_proto::brokerp::workload::WorkloadLaunch::Direct => ExecLaunch::Direct,
            dwk_proto::brokerp::workload::WorkloadLaunch::Hygiene => ExecLaunch::Hygiene,
        },
        arg_count: u16::try_from(executed.len())
            .ok()
            .and_then(ArgCount::new)
            .ok_or(WireGap::Unrepresentable("an argument count"))?,
        argv_sha256: ContentDigest::new(workload::argv_digest(&executed).to_hex())
            .ok_or(WireGap::Unrepresentable("an argv digest"))?,
        argv_safety: match decided.class {
            ArgvClass::Safe => ArgvSafetyClass::Safe,
            ArgvClass::Reinterpreting { .. } => ArgvSafetyClass::Reinterpreting,
        },
        timeout_seconds: ExecSeconds::new(checked.wall_clock.get())
            .ok_or(WireGap::Unrepresentable("a wall clock"))?,
        max_stream_bytes: ExecStreamLimit::new(decided.stream_limit)
            .ok_or(WireGap::Unrepresentable("a stream bound"))?,
        decision: ProcessActionDecision {
            effect,
            reason,
            capability_result: wire::gate(decided.record.capability_satisfied()),
            policy_result: wire::gate(decided.record.policy_satisfied()),
            rule_id,
            rule_source,
        },
    };
    Ok(ToolPlanV5 {
        tool: CoreToolV4::ProcessExec,
        environment: ActionEnvironment::Sandbox,
        effect,
        actions: PlannedActionsV5::new(vec![PlannedActionV5 {
            fs: None,
            process: None,
            workload: Some(action),
            net: None,
            injection: None,
        }])
        .ok_or(WireGap::Unrepresentable("a plan"))?,
    })
}

fn stream(kept: &[u8], observed: u64, truncated: bool) -> Result<ProcessStreamSnapshot, WireGap> {
    let length = u64::try_from(kept.len()).unwrap_or(u64::MAX);
    Ok(ProcessStreamSnapshot {
        content: StreamContent::from_bytes(kept).ok_or(WireGap::Unrepresentable("a stream"))?,
        observed: ByteCount::new(observed.max(length))
            .ok_or(WireGap::Unrepresentable("a byte count"))?,
        truncated,
    })
}

/// A completed launch's output.
fn result(answer: &Answer, done: &WorkloadOutcome) -> Result<SandboxedExecResult, WireGap> {
    let ending = match done.ending {
        WorkloadEnding::Exited => SandboxEnding::Exited,
        WorkloadEnding::Killed => SandboxEnding::Killed,
        WorkloadEnding::TimedOut => SandboxEnding::TimedOut,
        // Never a completion: recorded UNKNOWN.
        _ => return Err(WireGap::Unrepresentable("an ending a completion has not")),
    };
    Ok(SandboxedExecResult {
        environment_id: answer.environment.clone(),
        assurance: answer.assurance,
        executable: answer.executable.clone(),
        ending,
        exit_code: done
            .exit_code
            .map(|c| {
                dwk_proto::wire::scalar::ExitCode::new(c)
                    .ok_or(WireGap::Unrepresentable("an exit code"))
            })
            .transpose()?,
        signal: done
            .signal
            .map(|s| {
                dwk_proto::wire::scalar::SignalNumber::new(s)
                    .ok_or(WireGap::Unrepresentable("a signal"))
            })
            .transpose()?,
        stdout: stream(&done.stdout, done.stdout_observed, done.stdout_truncated)?,
        stderr: stream(&done.stderr, done.stderr_observed, done.stderr_truncated)?,
        elapsed_ms: ExecMilliseconds::new(done.elapsed_ms)
            .ok_or(WireGap::Unrepresentable("an elapsed time"))?,
        residue: match done.residue {
            Verdict::Pass => ResidueVerdict::Pass,
            Verdict::Fail => ResidueVerdict::Fail,
            Verdict::Unobservable => ResidueVerdict::Unobservable,
        },
        ended_processes: ReapedCount::new(done.ended_processes)
            .ok_or(WireGap::Unrepresentable("a process count"))?,
        environment_destroyed: done.environment_destroyed,
    })
}

/// A settled launch's answer.
fn answered(answer: &Answer, reply: &WorkloadReply) -> Result<DwkpBody, WireGap> {
    Ok(match reply {
        WorkloadReply::Completed(done) => DwkpBody::ToolResultV5(ToolResultV5 {
            invocation_id: done.invocation.clone(),
            plan: answer.plan.clone(),
            output: ToolOutputV5 {
                fs_read: None,
                fs_list: None,
                fs_search: None,
                fs_stat: None,
                fs_write: None,
                fs_patch: None,
                fs_move: None,
                fs_delete: None,
                process_exec: None,
                process_exec_sandboxed: Some(result(answer, done)?),
                process_status: None,
                process_kill: None,
                net_http: None,
            },
        }),
        WorkloadReply::Failed {
            invocation,
            reason,
            environment_destroyed,
        } => DwkpBody::ToolFailedV5(ToolFailureV5 {
            invocation_id: invocation.clone(),
            reason: failure(reason),
            environment_id: Some(answer.environment.clone()),
            environment_destroyed: Some(*environment_destroyed),
        }),
        WorkloadReply::Unknown {
            invocation,
            environment_destroyed,
            ..
        } => DwkpBody::ToolFailedV5(ToolFailureV5 {
            invocation_id: invocation.clone(),
            reason: ToolFailureReasonV5::OutcomeUnknown,
            environment_id: Some(answer.environment.clone()),
            environment_destroyed: Some(*environment_destroyed),
        }),
        WorkloadReply::Refused(_) | WorkloadReply::Denied(_) | WorkloadReply::Replayed(_) => {
            return Err(WireGap::Unrepresentable(
                "a settled launch that never began",
            ));
        }
    })
}

impl Authority {
    /// Answer one decoded authority request — or, for a sandboxed
    /// `process.exec` the broker now runs, park it (M5d.2): the caller
    /// collects it with [`Authority::resume`] between other requests, so no
    /// request waits behind a workload's wall clock. The authority's server
    /// is the one caller that parks; [`Authority::dispatch`] waits.
    ///
    /// # Errors
    ///
    /// As [`Authority::dispatch`].
    pub fn dispatch_parkable(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
    ) -> Result<Dispatched, AuthorityError> {
        if let DwkpBody::ToolInvokeV5(call) = &message.body
            && let Some(exec) = &call.process_exec
            && self.attached().is_some()
        {
            return self.sandboxed(caller, message, exec, true);
        }
        self.dispatch_answer(caller, message)
            .map(Dispatched::Answer)
    }

    /// Collect a parked launch once: `None` while it runs; its answer, once
    /// it ended and its outcome is durable.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook at
    /// a [`CrashPoint::WORKLOAD`] point poisons the store, as a crash would.
    pub fn resume(&mut self, parked: &mut Parked) -> Result<Option<DwkpBody>, AuthorityError> {
        let Some(attached) = self.attached() else {
            return Err(AuthorityError::Invariant(
                "a parked launch's sandbox is no longer attached",
            ));
        };
        let Some(ending) = workload_ops::collect(&attached, &parked.started)? else {
            parked.next = Instant::now() + COLLECT_EVERY;
            return Ok(None);
        };
        let run = parked.started.run.clone();
        let reply = self.settle_workload(&run, &parked.started.intent, ending)?;
        answered(&parked.answer, &reply)
            .map(Some)
            .map_err(unrepresentable)
    }

    /// Wait for a parked launch: collect it until it ends.
    pub(super) fn finish(&mut self, mut parked: Box<Parked>) -> Result<DwkpBody, AuthorityError> {
        loop {
            if let Some(body) = self.resume(&mut parked)? {
                return Ok(body);
            }
            std::thread::sleep(parked.due().saturating_duration_since(Instant::now()));
        }
    }

    /// `tool.invoke` or `canonical.preview` at version 5. A `process.exec`
    /// with an execution environment attached is sandboxed; everything else
    /// is version 4's, answered in version 5's shapes — a host
    /// `process.exec` decided, and refused, by the host floor.
    pub(super) fn dispatch_v5(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
        call: &ToolCallV5,
        invoke: bool,
    ) -> Result<DwkpBody, AuthorityError> {
        if let Some(exec) = &call.process_exec
            && self.attached().is_some()
        {
            return match self.sandboxed(caller, message, exec, invoke)? {
                Dispatched::Answer(body) => Ok(body),
                Dispatched::Parked(parked) => self.finish(parked),
            };
        }
        let recoded = dwk_proto::dwkp::netops::ToolCallV4 {
            fs_read: call.fs_read.clone(),
            fs_list: call.fs_list.clone(),
            fs_search: call.fs_search.clone(),
            fs_stat: call.fs_stat.clone(),
            fs_write: call.fs_write.clone(),
            fs_patch: call.fs_patch.clone(),
            fs_move: call.fs_move.clone(),
            fs_delete: call.fs_delete.clone(),
            // On the host there is nothing to narrow: the floor refuses it.
            process_exec: call.process_exec.as_ref().map(|exec| ProcessExecCall {
                executable: exec.executable.clone(),
                args: exec.args.clone(),
                cwd: exec.cwd.clone(),
            }),
            process_status: call.process_status.clone(),
            process_kill: call.process_kill.clone(),
            net_http: call.net_http.clone(),
        };
        let body = self.dispatch_v4(caller, message, &recoded, invoke)?;
        wire::v5_from_v4(body).map_err(unrepresentable)
    }

    /// Steps 1 and 2 -- and, when a permitted launch's run has none, the
    /// authority's own preparation of its environment (step 2a: recorded,
    /// measured and judged by the environment's lifecycle), then steps 1 and
    /// 2 again, from the fence on.
    fn routed(
        &mut self,
        asked: &Asked<'_>,
        call: &ProcessExecCallV5,
        context: (&Attached, &ActiveAuthority, &ImageBinding),
    ) -> Result<Route, AuthorityError> {
        let routed = self.transact(|work| route(work, asked, call, context, false))?;
        if !matches!(routed, Route::NeedsEnvironment) {
            return Ok(routed);
        }
        // Environments are bounded across runs (ADR-0052 §2a): first at most
        // one that can never run a workload again ends, then the live ones
        // are counted. Each step is one broker exchange within the
        // environment deadline, so a launch that needs an environment holds
        // the worker for at most one destruction and one preparation.
        self.reclaim_one()?;
        let full = self.transact(|work| {
            Ok(workload::live_environments(work)? >= workload::MAX_LIVE_ENVIRONMENTS)
        })?;
        if full {
            return self.transact(|work| {
                workload::refuse(
                    work,
                    asked.run,
                    call.executable.as_str(),
                    "LIVE_ENVIRONMENTS_EXHAUSTED",
                )
                .map(|_| Route::Refused(ToolRefusalReasonV5::BudgetExhausted))
            });
        }
        let usable = matches!(
            self.environment_prepare(asked.run)?,
            crate::state::EnvironmentReply::Ready { .. }
        );
        if usable {
            return self.transact(|work| route(work, asked, call, context, true));
        }
        self.transact(|work| {
            workload::refuse(
                work,
                asked.run,
                call.executable.as_str(),
                "ENVIRONMENT_UNAVAILABLE",
            )
            .map(|_| Route::Refused(ToolRefusalReasonV5::EnvironmentUnavailable))
        })
    }

    /// End at most one environment that can never run a workload again
    /// ([`workload::reclaimable`]): its destruction durable first, then the
    /// broker's, as every destruction (ADR-0047). One whose destruction does
    /// not complete stays `DESTROYING`, and is tried again the next time.
    fn reclaim_one(&mut self) -> Result<(), AuthorityError> {
        let begun = self.transact(|work| match workload::reclaimable(work)? {
            Some(environment) => {
                super::environment::begin_destroy(work, &environment, "RECLAIMED").map(Some)
            }
            None => Ok(None),
        })?;
        if let Some(super::environment::DestroyBegun::Pending { record, invocation }) = begun {
            self.perform_destroy(record, invocation)?;
        }
        Ok(())
    }

    /// A sandboxed `process.exec`: steps 1 to 3, and either its answer or the
    /// parked launch.
    fn sandboxed(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
        call: &ProcessExecCallV5,
        invoke: bool,
    ) -> Result<Dispatched, AuthorityError> {
        let header = &message.header;
        let missing = || AuthorityError::Invariant("a decoded request lacks an envelope field");
        let Some(attached) = self.attached() else {
            return Err(AuthorityError::Invariant("no sandbox is attached"));
        };
        let shared = Arc::clone(&attached.shared);
        let active = shared.active()?;
        let image = ImageBinding::of(&attached.config);
        let key = if invoke {
            Some(header.idempotency_key.as_ref().ok_or_else(missing)?)
        } else {
            None
        };
        let asked = Asked {
            caller,
            session: header.session_id.as_ref().ok_or_else(missing)?,
            run: header.run_id.as_ref().ok_or_else(missing)?,
            epoch: header.epoch.ok_or_else(missing)?,
            key,
            operation: if invoke {
                ToolOperation::ToolInvoke
            } else {
                ToolOperation::CanonicalPreview
            },
        };
        let routed = self.routed(&asked, call, (&attached, active, &image))?;
        let plan_of = |decided: &Decided, checked: &Checked| {
            plan(
                decided.environment.as_ref(),
                &decided.plan,
                checked,
                attached.config.image(),
            )
            .map_err(unrepresentable)
        };
        let (intent, checked) = match routed {
            Route::Refused(reason) => {
                return Ok(Dispatched::Answer(DwkpBody::ToolRefusedV5(ToolRefusalV5 {
                    operation: asked.operation,
                    reason,
                })));
            }
            Route::Denied(decided, checked) => {
                return Ok(Dispatched::Answer(DwkpBody::ToolDeniedV5(ToolDenialV5 {
                    plan: plan_of(&decided, &checked)?,
                })));
            }
            Route::Previewed(decided, checked) => {
                return Ok(Dispatched::Answer(DwkpBody::ToolPreviewedV5(
                    CanonicalPreviewResultV5 {
                        plan: plan_of(&decided, &checked)?,
                    },
                )));
            }
            Route::Intent(intent, checked) => (intent, checked),
            Route::NeedsEnvironment => {
                return Err(AuthorityError::Invariant(
                    "a prepared environment was asked for again",
                ));
            }
        };
        shared.crash(CrashPoint::WorkloadAfterIntent)?;
        let answer = Answer {
            plan: plan(
                Some(&intent.environment),
                &intent.plan,
                &checked,
                attached.config.image(),
            )
            .map_err(unrepresentable)?,
            environment: intent.environment.environment.clone(),
            assurance: assurance(intent.environment.level),
            executable: executable(&checked, attached.config.image()).map_err(unrepresentable)?,
        };
        let spec = workload::spec(&checked, &intent)?;
        match workload_ops::start(&attached, asked.run, *intent, spec)? {
            Launched::Running(started) => Ok(Dispatched::Parked(Box::new(Parked {
                started: *started,
                answer,
                next: Instant::now() + COLLECT_EVERY,
            }))),
            Launched::Ended(intent, ending) => {
                let reply = self.settle_workload(asked.run, &intent, ending)?;
                answered(&answer, &reply)
                    .map(Dispatched::Answer)
                    .map_err(unrepresentable)
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "workload_route_tests.rs"]
mod tests;
