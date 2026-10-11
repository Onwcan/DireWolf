//! Workloads' durable lifecycle (M5d.1, ADR-0052 §§2, 4, 8–10): one bounded
//! program, run in the run's `READY` environment, decided by both gates and
//! recorded before the broker hears of it.
//!
//! # The order
//!
//! | step | where | can it run? |
//! |---|---|---|
//! | 1. the request's own bounds; the executable named by the image manifest | no transaction | no |
//! | 2. the run active with a pinned workspace; the key; the run's environment `READY` at `CONTAINER_ISOLATION`, idle; the budget; both gates for a **sandbox** action; the intent, `LAUNCHING`, audited | transaction | no |
//! | 3. the runtime client resolved and hashed; the workspace re-pinned | no transaction | no |
//! | 4. the broker re-judges the environment, proves the executable, runs it, ends what it left | the broker | yes |
//! | 5. the outcome, redacted output, taint — and, when the ending or the residue is uncertain, the environment's destruction | transaction | recorded |
//!
//! # Crash windows (ADR-0052 §9)
//!
//! | window | durable state | on restart | semantics |
//! |---|---|---|---|
//! | W8 intent durable, nothing sent | `LAUNCHING` | `UNKNOWN`; the environment destroyed | NON-RETRYABLE |
//! | W9 the broker running it | `LAUNCHING` | as W8: the runtime keeps an `exec`'d process when its client dies, so only the environment's destruction ends it | UNKNOWN |
//! | W10 answered, outcome not durable | `LAUNCHING` | as W8 | UNKNOWN |
//! | W11 outcome durable, destruction pending | `COMPLETED`/`UNKNOWN`, `DESTROYING` | the destruction completes (W6, W7) | RETRY-SAFE |
//!
//! A workload is never run again: a key bound to one answers with its
//! record, and an `UNKNOWN` one stays unknown.
//!
//! # No host fallback
//!
//! Nothing here can start a process on the host: the only effect is the
//! broker's `workload_run`, in the environment the run's record names. A run
//! without a `READY` environment is refused, never redirected to M4d's host
//! path (whose floor is unchanged: no production host launch before M6).

use dwk_proto::brokerp::sandbox::{AssuranceLevel, ContainerRef, Verdict};
use dwk_proto::brokerp::workload::{ImagePath, WorkloadEnding, WorkloadRunDone, WorkloadSeconds};
use dwk_proto::brokerp::{ProcessArgs, StreamLimit};
use dwk_proto::limits::{MAX_PROCESS_ARG_BYTES, MAX_PROCESS_ARGV_BYTES};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, ProcessArg};
use rusqlite::OptionalExtension as _;

use crate::capability::{
    Action, ArgvAllowlist, ArgvToken, Capability, ConstraintSet, Namespace, Scope, Verb,
};
use crate::policy::{ArgvSafety, CanonicalAction, Effect, Environment, Obligation, TaintLevel};
use crate::resource::ExecutableIdentity;
use crate::resource::exec::argv::{self, ArgvClass};
use crate::sandbox::{SandboxConfig, WorkloadBudget};

use super::Work;
use super::audit::{AuditEvent, Field, Fields};
use super::config::RootBinding;
use super::digest::{self, DomainHash, Sha256Hash};
use super::environment::{self, DestroyBegun};
use super::error::AuthorityError;
use super::lease::to_sql;
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord, TaintCause};
use super::resolution::{self, ResolutionRefused};

/// Where a workload is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadState {
    /// The intent is durable; the broker may be running it.
    Launching,
    /// It ran and ended as `ending` says.
    Completed,
    /// Refused after its intent; provably nothing ran.
    Failed,
    /// It may have run and nothing proves how it ended.
    Unknown,
}

impl WorkloadState {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Launching => "LAUNCHING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// The state a stored spelling names.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "LAUNCHING" => Self::Launching,
            "COMPLETED" => Self::Completed,
            "FAILED" => Self::Failed,
            "UNKNOWN" => Self::Unknown,
            _ => return None,
        })
    }
}

/// What a caller asks for: one workload in its run's environment. The
/// in-process API's request (M5d.1): no DWKP route reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRequest {
    /// The executable's absolute path in the image; the manifest must name
    /// it.
    pub executable: String,
    /// The arguments after `argv[0]`, as exact bytes of text: data, never a
    /// command line.
    pub args: Vec<String>,
    /// How many bytes of each output stream come back (1 to 131 072).
    pub stream_limit: u32,
    /// The wall clock, in seconds (1 to 600).
    pub wall_clock_seconds: u32,
    /// The idempotency key: one workload per key per run, never run twice.
    pub key: String,
}

/// A request whose bounds hold and whose executable the manifest names.
#[derive(Debug, Clone)]
pub(super) struct Checked {
    pub(super) executable: ImagePath,
    pub(super) sha256: ContentDigest,
    pub(super) identity: ExecutableIdentity,
    pub(super) args: Vec<String>,
    pub(super) wire_args: ProcessArgs,
    pub(super) stream_limit: StreamLimit,
    pub(super) wall_clock: WorkloadSeconds,
    pub(super) key: String,
}

/// The longest idempotency key, in bytes.
const MAX_KEY_BYTES: usize = 128;

/// Step 1: the request's own bounds, and the executable the manifest names.
/// Pure; nothing is recorded.
///
/// # Errors
///
/// The refusal's class.
pub(super) fn check(
    request: &WorkloadRequest,
    config: &SandboxConfig,
) -> Result<Checked, &'static str> {
    let key = &request.key;
    if key.is_empty() || key.len() > MAX_KEY_BYTES || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("IDEMPOTENCY_KEY_INVALID");
    }
    let (executable, sha256) = config
        .executable(&request.executable)
        .ok_or("EXECUTABLE_NOT_IN_MANIFEST")?;
    let identity =
        crate::resource::exec::image_executable_identity(executable.as_str(), sha256.as_str())
            .map_err(|_| "EXECUTABLE_NOT_IN_MANIFEST")?;
    let mut total = 0usize;
    let mut wire = Vec::with_capacity(request.args.len());
    for arg in &request.args {
        if arg.len() > MAX_PROCESS_ARG_BYTES {
            return Err("ARGV_TOO_LARGE");
        }
        total = total.saturating_add(arg.len());
        wire.push(ProcessArg::new(arg.as_str()).ok_or("ARGUMENT_INVALID")?);
    }
    if total > MAX_PROCESS_ARGV_BYTES {
        return Err("ARGV_TOO_LARGE");
    }
    let wire_args = ProcessArgs::new(wire).ok_or("ARGV_TOO_LARGE")?;
    let stream_limit = StreamLimit::new(request.stream_limit).ok_or("STREAM_LIMIT_INVALID")?;
    let wall_clock =
        WorkloadSeconds::new(request.wall_clock_seconds).ok_or("WALL_CLOCK_INVALID")?;
    Ok(Checked {
        executable: executable.clone(),
        sha256: sha256.clone(),
        identity,
        args: request.args.clone(),
        wire_args,
        stream_limit,
        wall_clock,
        key: key.clone(),
    })
}

/// The arguments' digest: their count, then each, length-prefixed — the
/// process tools' domain, so a workload's and a launch's arguments digest
/// alike.
fn argv_digest(args: &[String]) -> Sha256Hash {
    let mut hash =
        DomainHash::new(digest::PROCESS_ARGV).int(u64::try_from(args.len()).unwrap_or(u64::MAX));
    for arg in args {
        hash = hash.text(arg);
    }
    hash.finish()
}

/// What a key is bound to: the run, the executable, the arguments, the
/// bounds.
fn request_digest(run: &RunId, checked: &Checked) -> Sha256Hash {
    DomainHash::new(digest::WORKLOAD_REQUEST)
        .text(run.as_str())
        .text(checked.executable.as_str())
        .text(checked.sha256.as_str())
        .bytes(argv_digest(&checked.args).as_bytes())
        .int(u64::from(checked.stream_limit.get()))
        .int(u64::from(checked.wall_clock.get()))
        .finish()
}

/// A workload's plan: the canonical action, both gates' records, and the
/// per-stream bound the obligations leave.
#[derive(Debug, Clone)]
pub(super) struct WorkloadPlan {
    pub(super) action: CanonicalAction,
    pub(super) record: DecisionRecord,
    pub(super) class: ArgvClass,
    pub(super) obligations_enforced: bool,
    pub(super) stream_limit: u32,
}

impl WorkloadPlan {
    /// Both gates, and every obligation enforced.
    pub(super) fn permits(&self) -> bool {
        self.record.capability_satisfied()
            && self.record.policy_satisfied()
            && self.obligations_enforced
    }

    /// Why it was decided as it was, in the process tools' order: an
    /// unevaluable input, policy, the capability, the obligations, an
    /// approval.
    pub(super) fn reason(&self) -> &'static str {
        let policy = self.record.policy();
        if self.permits() {
            return "ALLOWED_BY_RULE";
        }
        if policy.unevaluable().is_some() {
            return "UNRESOLVED_POLICY_INPUT";
        }
        match policy.effect() {
            Effect::Deny if policy.rule_id().is_default() => "DEFAULT_DENY",
            Effect::Deny => "DENIED_BY_RULE",
            _ if !self.record.capability_satisfied() => "NO_CAPABILITY",
            Effect::Allow if !self.obligations_enforced => "OBLIGATION_UNENFORCEABLE",
            // REQUIRE_APPROVAL: no approval exists before M6.
            _ => "APPROVAL_REQUIRED",
        }
    }
}

/// The capability a workload requires: `process.exec` for the executable's
/// identity in the image, with its first argument as the argv selector when
/// it is a token an allowlist can name (ADR-0045 §7's rule, unchanged).
fn required_capability(checked: &Checked) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Process, Action::Exec)
        .ok_or(AuthorityError::Invariant("process.exec is not a verb"))?;
    let argv_allowlist = checked
        .args
        .first()
        .and_then(|selector| ArgvToken::new(selector))
        .and_then(|token| ArgvAllowlist::new(vec![token]));
    let constraints = ConstraintSet {
        argv_allowlist,
        ..ConstraintSet::unconstrained()
    };
    Capability::new(
        verb,
        Scope::Executable(checked.identity.clone()),
        constraints,
    )
    .map_err(|_| AuthorityError::Invariant("a workload capability does not assemble"))
}

/// Whether the authority keeps every obligation, for a workload in an
/// environment, and the per-stream bound it leaves (ADR-0052 §10):
///
/// | obligation | a workload |
/// |---|---|
/// | `max_output_bytes=N` | each stream keeps its first `N / 2` bytes (`N >= 2`) |
/// | `audit_level=full` | the intent record carries the full argv |
/// | `workspace_exec_hygiene` | **not yet enforceable** (M5d.2): denied |
/// | anything else | **not enforceable**: denied |
fn obligations(record: &DecisionRecord, requested: u32) -> (bool, u32) {
    let mut stream_limit = requested;
    let mut enforced = true;
    for obligation in record.policy().obligations().as_slice() {
        let ok = match obligation {
            Obligation::MaxOutputBytes(limit) => {
                let per_stream = limit.checked_div(2).unwrap_or(0);
                if per_stream == 0 {
                    false
                } else {
                    stream_limit = stream_limit.min(u32::try_from(per_stream).unwrap_or(u32::MAX));
                    true
                }
            }
            Obligation::AuditLevel(_) => true,
            _ => false,
        };
        enforced &= ok;
    }
    (enforced, stream_limit)
}

/// Both gates for a **sandbox** action. Pure: reads what the caller loaded.
fn decide_plan(
    checked: &Checked,
    admission: &super::admission::Admission,
    context: &crate::policy::PolicyContext,
    active: &ActiveAuthority,
) -> Result<WorkloadPlan, AuthorityError> {
    let capability = required_capability(checked)?;
    let refs: Vec<&str> = checked.args.iter().map(String::as_str).collect();
    let class = argv::classify(&checked.identity, &refs);
    let action =
        CanonicalAction::new(capability, Environment::Sandbox).with_argv_safety(match class {
            ArgvClass::Safe => ArgvSafety::Safe,
            ArgvClass::Reinterpreting { .. } => ArgvSafety::Reinterpreting,
        });
    let record = query::decide(&action, admission, context, active);
    let (obligations_enforced, stream_limit) = obligations(&record, checked.stream_limit.get());
    Ok(WorkloadPlan {
        action,
        record,
        class,
        obligations_enforced,
        stream_limit,
    })
}

/// The plan's fields: the action, both gates, the reason.
fn plan_fields(active: &ActiveAuthority, checked: &Checked, plan: &WorkloadPlan) -> Fields {
    let record = &plan.record;
    let policy = record.policy();
    let class = match plan.class {
        ArgvClass::Safe => Fields::new().text("argv_safety", "SAFE"),
        ArgvClass::Reinterpreting { rule, index } => Fields::new()
            .text("argv_safety", "REINTERPRETING")
            .text("argv_rule", rule.code())
            .maybe_int(
                "argv_rule_index",
                index.map(|i| u64::try_from(i).unwrap_or(u64::MAX)),
            ),
    };
    let mut fields = Fields::new()
        .text("environment", plan.action.environment().as_str())
        .text("policy_revision", active.revision.to_hex())
        .text("executable", checked.executable.as_str())
        .text("executable_sha256", checked.sha256.as_str())
        .text(
            "required_capability",
            record.required().to_canonical_string(),
        )
        .flag("capability_satisfied", record.capability_satisfied())
        .maybe_text(
            "covering_cap_id",
            record.covering_grant().map(|c| c.as_str().to_owned()),
        )
        .text("policy_effect", policy.effect().as_str())
        .flag("policy_satisfied", record.policy_satisfied())
        .text("rule_id", policy.rule_id().as_str())
        .text("rule_source", policy.rule_source().to_string())
        .list(
            "obligations",
            policy
                .obligations()
                .as_slice()
                .iter()
                .map(|o| Field::Text(o.to_string()))
                .collect(),
        )
        .maybe_text("unevaluable", policy.unevaluable().map(|u| u.to_string()))
        .int(
            "arg_count",
            u64::try_from(checked.args.len()).unwrap_or(u64::MAX),
        )
        .text("argv_sha256", argv_digest(&checked.args).to_hex())
        // The full canonical command (SANDBOX.md §4): argv is an array,
        // recorded as one. Output is never recorded.
        .list(
            "argv",
            std::iter::once(checked.executable.as_str().to_owned())
                .chain(checked.args.iter().cloned())
                .map(Field::Text)
                .collect(),
        )
        .int("stream_limit", u64::from(plan.stream_limit))
        .int("wall_clock_s", u64::from(checked.wall_clock.get()))
        .text("reason", plan.reason());
    fields.extend(class);
    fields.text("effect", if plan.permits() { "ALLOW" } else { "DENY" })
}

/// A workload's record, as the ledger holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    /// Its invocation.
    pub invocation: InvocationId,
    /// Its run.
    pub run: RunId,
    /// Its environment.
    pub environment: EnvironmentId,
    /// Where it is.
    pub state: WorkloadState,
    /// Its failure or unknown class.
    pub failure: Option<String>,
    /// How it ended, when that is known.
    pub ending: Option<String>,
    /// Its exit code, for an exit.
    pub exit_code: Option<u8>,
    /// The signal that ended it, for a kill.
    pub signal: Option<u8>,
    /// What `reap` found after it.
    pub residue: Option<String>,
}

type RecordRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

fn record_of(row: RecordRow) -> Result<WorkloadRecord, AuthorityError> {
    let malformed = || AuthorityError::Invariant("a stored workload is malformed");
    let (invocation, run, environment, state, failure, ending, exit_code, signal, residue) = row;
    Ok(WorkloadRecord {
        invocation: InvocationId::parse(&invocation).ok_or_else(malformed)?,
        run: RunId::parse(&run).ok_or_else(malformed)?,
        environment: EnvironmentId::parse(&environment).ok_or_else(malformed)?,
        state: WorkloadState::parse(&state).ok_or_else(malformed)?,
        failure,
        ending,
        exit_code: exit_code
            .map(|c| u8::try_from(c).map_err(|_| malformed()))
            .transpose()?,
        signal: signal
            .map(|s| u8::try_from(s).map_err(|_| malformed()))
            .transpose()?,
        residue,
    })
}

const RECORD_COLUMNS: &str = "invocation_id, run_id, environment_id, state, failure, ending, \
                              exit_code, signal, residue";

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

/// One workload's record.
pub(super) fn record(
    work: &Work<'_>,
    invocation: &InvocationId,
) -> Result<Option<WorkloadRecord>, AuthorityError> {
    let row: Option<RecordRow> = work.db(work
        .tx
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM workload WHERE invocation_id = ?1"),
            [invocation.as_str()],
            read_row,
        )
        .optional())?;
    row.map(record_of).transpose()
}

/// The environment a workload is decided in: the run's live one, `READY`.
#[derive(Debug, Clone)]
pub(super) struct ReadyEnvironment {
    pub(super) environment: EnvironmentId,
    pub(super) container: ContainerRef,
}

/// What starting a workload decided.
#[derive(Debug)]
pub(super) enum Begun {
    /// Refused before anything was recorded; audited.
    Refused(&'static str),
    /// A gate denied it; audited.
    Denied(&'static str),
    /// Its key is bound to a workload already: that one's record.
    Replayed(Box<WorkloadRecord>),
    /// The intent is durable.
    Intent(Box<Intent>),
}

/// A workload both gates allowed, whose intent is durable.
#[derive(Debug)]
pub(super) struct Intent {
    pub(super) invocation: InvocationId,
    pub(super) environment: ReadyEnvironment,
    pub(super) binding: RootBinding,
    pub(super) stream_limit: u32,
}

const fn resolution_class(refused: &ResolutionRefused) -> &'static str {
    match refused {
        ResolutionRefused::UnknownRun => "UNKNOWN_RUN",
        ResolutionRefused::RunNotActive => "RUN_NOT_ACTIVE",
        ResolutionRefused::NoWorkspace => "NO_WORKSPACE",
        ResolutionRefused::NoWorkspaceRoot => "NO_WORKSPACE_ROOT",
        ResolutionRefused::Root(_)
        | ResolutionRefused::Resolve(_)
        | ResolutionRefused::Authority(_) => "WORKSPACE_UNAVAILABLE",
    }
}

/// Record a refusal before any intent, and return it.
pub(super) fn refuse(
    work: &mut Work<'_>,
    run: &RunId,
    executable: &str,
    reason: &'static str,
) -> Result<Begun, AuthorityError> {
    work.audit(
        AuditEvent::WorkloadRefused,
        Fields::new()
            .text("run_id", run.as_str())
            .text("environment", "sandbox")
            .text(
                "executable",
                executable.chars().take(255).collect::<String>(),
            )
            .text("reason", reason),
    )?;
    Ok(Begun::Refused(reason))
}

/// The run's live environment, if it is `READY` at a level a workload
/// needs, or why not.
fn ready_environment(
    work: &Work<'_>,
    run: &RunId,
) -> Result<Result<ReadyEnvironment, &'static str>, AuthorityError> {
    let row: Option<(String, String, Option<String>, Option<String>)> = work.db(work
        .tx
        .query_row(
            "SELECT environment_id, state, container, effective FROM environment \
             WHERE run_id = ?1 AND state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')",
            [run.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional())?;
    let Some((environment, state, container, effective)) = row else {
        return Ok(Err("NO_ENVIRONMENT"));
    };
    if state != "READY" {
        return Ok(Err("ENVIRONMENT_NOT_READY"));
    }
    let malformed = AuthorityError::Invariant("a ready environment is malformed");
    let level = effective
        .as_deref()
        .and_then(|text| {
            AssuranceLevel::ALL
                .iter()
                .copied()
                .find(|level| level.as_str() == text)
        })
        .ok_or_else(|| malformed.clone())?;
    // A workload needs the container's isolation, measured: never less.
    if level.rank() < AssuranceLevel::ContainerIsolation.rank() {
        return Ok(Err("ASSURANCE_INSUFFICIENT"));
    }
    Ok(Ok(ReadyEnvironment {
        environment: EnvironmentId::parse(&environment).ok_or_else(|| malformed.clone())?,
        container: container.and_then(ContainerRef::new).ok_or(malformed)?,
    }))
}

/// Step 2: decide the workload and record its intent.
pub(super) fn begin(
    work: &mut Work<'_>,
    run: &RunId,
    checked: &Checked,
    budget: WorkloadBudget,
    active: &ActiveAuthority,
) -> Result<Begun, AuthorityError> {
    let executable = checked.executable.as_str();
    let binding = match resolution::run_root(work, run.as_str())? {
        Ok(binding) => binding,
        Err(refused) => return refuse(work, run, executable, resolution_class(&refused)),
    };
    let digest = request_digest(run, checked);
    let bound: Option<(String, String)> = work.db(work
        .tx
        .query_row(
            "SELECT invocation_id, request_digest FROM workload \
             WHERE run_id = ?1 AND idempotency_key = ?2",
            rusqlite::params![run.as_str(), checked.key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    if let Some((invocation, bound_digest)) = bound {
        if bound_digest != digest.to_hex() {
            return refuse(work, run, executable, "IDEMPOTENCY_KEY_REUSED");
        }
        let invocation = InvocationId::parse(&invocation)
            .ok_or(AuthorityError::Invariant("a stored workload is malformed"))?;
        let found = record(work, &invocation)?
            .ok_or(AuthorityError::Invariant("a bound key names no workload"))?;
        return Ok(Begun::Replayed(Box::new(found)));
    }
    let environment = match ready_environment(work, run)? {
        Ok(environment) => environment,
        Err(reason) => return refuse(work, run, executable, reason),
    };
    let busy: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM workload WHERE environment_id = ?1 AND state = 'LAUNCHING'",
            [environment.environment.as_str()],
            |row| row.get(0),
        )
        .optional())?;
    if busy.is_some() {
        return refuse(work, run, executable, "ENVIRONMENT_BUSY");
    }
    // The budget: what the run's rows were charged, never refunded.
    let (count, seconds): (i64, i64) = work.db(work.tx.query_row(
        "SELECT count(*), COALESCE(sum(wall_clock_s), 0) FROM workload WHERE run_id = ?1",
        [run.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))?;
    let count = u64::try_from(count).unwrap_or(u64::MAX);
    let seconds = u64::try_from(seconds).unwrap_or(u64::MAX);
    if count.saturating_add(1) > budget.workloads
        || seconds.saturating_add(u64::from(checked.wall_clock.get())) > budget.seconds
    {
        return refuse(work, run, executable, "BUDGET_EXHAUSTED");
    }
    let admission = super::admission::load(work, run.as_str())?;
    let context = query::policy_context(work, run.as_str(), active)?;
    let plan = decide_plan(checked, &admission, &context, active)?;
    let mut fields = Fields::new()
        .text("run_id", run.as_str())
        .text("environment_id", environment.environment.as_str());
    fields.extend(plan_fields(active, checked, &plan));
    if !plan.permits() {
        work.audit(AuditEvent::WorkloadDenied, fields)?;
        return Ok(Begun::Denied(plan.reason()));
    }
    let invocation = work.invocation_id()?;
    work.db(work.tx.execute(
        "INSERT INTO workload (invocation_id, run_id, environment_id, idempotency_key, \
         request_digest, executable_path, executable_sha256, arg_count, argv_sha256, \
         stream_limit, wall_clock_s, incarnation, state, intent_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'LAUNCHING', ?13)",
        rusqlite::params![
            invocation.as_str(),
            run.as_str(),
            environment.environment.as_str(),
            checked.key,
            digest.to_hex(),
            checked.executable.as_str(),
            checked.sha256.as_str(),
            i64::try_from(checked.args.len()).unwrap_or(i64::MAX),
            argv_digest(&checked.args).to_hex(),
            i64::from(plan.stream_limit),
            i64::from(checked.wall_clock.get()),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    fields.extend(
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("idempotency_key", checked.key.as_str())
            .text("request_digest", digest.to_hex())
            .text("container", environment.container.as_str()),
    );
    work.audit(AuditEvent::WorkloadIntentRecorded, fields)?;
    Ok(Begun::Intent(Box::new(Intent {
        invocation,
        environment,
        binding,
        stream_limit: plan.stream_limit,
    })))
}

/// How a workload ended, before it is recorded.
#[derive(Debug)]
pub(super) enum Ending {
    /// It ran and ended as the broker says — exited, killed, timed out.
    Completed(Box<WorkloadRunDone>),
    /// It may have run; nothing proves how it ended. The broker's answer,
    /// when there is one (an ending it could not observe).
    Unknown {
        reason: &'static str,
        done: Option<Box<WorkloadRunDone>>,
    },
    /// Provably nothing ran.
    Failed { reason: &'static str },
}

/// Whether a refusal says the environment is not what was recorded: it is
/// then destroyed, as a drifted measurement is.
const fn environment_drifted(reason: &str) -> bool {
    matches!(
        reason.as_bytes(),
        b"ENVIRONMENT_NOT_CLEAN" | b"ENVIRONMENT_NOT_FOUND" | b"FOREIGN_ENVIRONMENT"
    )
}

fn ending_str(ending: WorkloadEnding) -> &'static str {
    ending.as_str()
}

/// What a recorded outcome left to do.
#[derive(Debug)]
pub(super) struct Recorded {
    /// The environment's destruction, when it was begun here.
    pub(super) destroy: Option<DestroyBegun>,
}

/// Step 5: record how the workload ended — and, when its ending or its
/// residue is uncertain, or its environment proved not to be what was
/// recorded, begin the environment's destruction in the same transaction.
/// Output that reached the authority taints the run (`LOCAL_UNVERIFIED`)
/// before anything is answered.
pub(super) fn record_outcome(
    work: &mut Work<'_>,
    run: &RunId,
    intent: &Intent,
    ending: &Ending,
    output: Option<(u64, u64, bool)>,
) -> Result<Recorded, AuthorityError> {
    let now = to_sql(work.now)?;
    let invocation = intent.invocation.as_str();
    let environment = &intent.environment.environment;
    let mut fields = Fields::new()
        .text("run_id", run.as_str())
        .text("invocation_id", invocation)
        .text("environment_id", environment.as_str());
    let (destroy_reason, state): (Option<&'static str>, WorkloadState) = match ending {
        Ending::Completed(done) => {
            let (stdout, stderr, truncated) = output.unwrap_or((0, 0, false));
            work.db(work.tx.execute(
                "UPDATE workload SET state = 'COMPLETED', ending = ?2, exit_code = ?3, \
                 signal = ?4, stdout_bytes = ?5, stderr_bytes = ?6, output_truncated = ?7, \
                 residue = ?8, elapsed_ms = ?9, ended_ms = ?10 WHERE invocation_id = ?1",
                rusqlite::params![
                    invocation,
                    ending_str(done.ending),
                    done.exit_code.map(|c| i64::from(c.get())),
                    done.signal.map(|s| i64::from(s.get())),
                    i64::try_from(stdout).unwrap_or(i64::MAX),
                    i64::try_from(stderr).unwrap_or(i64::MAX),
                    i64::from(truncated),
                    done.residue.as_str(),
                    i64::from(done.elapsed_ms.get()),
                    now
                ],
            ))?;
            fields = done_fields(fields, done)
                .int("stdout_bytes", stdout)
                .int("stderr_bytes", stderr)
                .flag("output_truncated", truncated);
            let destroy = (done.residue != Verdict::Pass).then_some("WORKLOAD_RESIDUE");
            (destroy, WorkloadState::Completed)
        }
        Ending::Unknown { reason, done } => {
            work.db(work.tx.execute(
                "UPDATE workload SET state = 'UNKNOWN', failure = ?2, ending = ?3, \
                 residue = ?4, elapsed_ms = ?5, ended_ms = ?6 WHERE invocation_id = ?1",
                rusqlite::params![
                    invocation,
                    reason,
                    done.as_ref().map(|d| ending_str(d.ending)),
                    done.as_ref().map(|d| d.residue.as_str()),
                    done.as_ref().map(|d| i64::from(d.elapsed_ms.get())),
                    now
                ],
            ))?;
            fields = fields.text("reason", *reason);
            if let Some(done) = done {
                fields = done_fields(fields, done);
            }
            (Some("WORKLOAD_UNKNOWN"), WorkloadState::Unknown)
        }
        Ending::Failed { reason } => {
            work.db(work.tx.execute(
                "UPDATE workload SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
                 WHERE invocation_id = ?1",
                rusqlite::params![invocation, reason, now],
            ))?;
            fields = fields.text("reason", *reason);
            (
                environment_drifted(reason).then_some("DRIFTED"),
                WorkloadState::Failed,
            )
        }
    };
    if output.is_some_and(|(stdout, stderr, _)| stdout > 0 || stderr > 0) {
        // A workload's output is content the environment produced:
        // LOCAL_UNVERIFIED, never lower, raised before it can reach
        // cognition.
        let taint = query::raise_taint(
            work,
            run,
            TaintLevel::LocalUnverified,
            TaintCause::ToolResult,
        )?;
        fields = fields.text("taint", taint.as_str());
    }
    fields = fields.text("state", state.as_str());
    let destroy = match destroy_reason {
        Some(reason) => {
            fields = fields.text("environment_destroyed_for", reason);
            Some(environment::begin_destroy(work, environment, reason)?)
        }
        None => None,
    };
    work.audit(AuditEvent::WorkloadOutcome, fields)?;
    Ok(Recorded { destroy })
}

fn done_fields(fields: Fields, done: &WorkloadRunDone) -> Fields {
    fields
        .text("ending", done.ending.as_str())
        .maybe_int("exit_code", done.exit_code.map(|c| u64::from(c.get())))
        .maybe_int("signal", done.signal.map(|s| u64::from(s.get())))
        .text("residue", done.residue.as_str())
        .int("ended_processes", u64::from(done.ended_processes.get()))
        .int(
            "remaining_processes",
            u64::from(done.remaining_processes.get()),
        )
        .int("elapsed_ms", u64::from(done.elapsed_ms.get()))
}

/// A `LAUNCHING` workload a previous incarnation left (W8–W10): `UNKNOWN`,
/// audited, never run again — and its environment destroyed, because
/// nothing proves the workload is not still running in it.
///
/// Called only while a new incarnation begins, before anything else.
pub(super) fn reconcile_open(work: &mut Work<'_>) -> Result<u64, AuthorityError> {
    let now = to_sql(work.now)?;
    let mut statement = work.db(work.tx.prepare(
        "UPDATE workload SET state = 'UNKNOWN', failure = 'INTERRUPTED', ended_ms = ?1 \
         WHERE state = 'LAUNCHING' RETURNING invocation_id, run_id, environment_id",
    ))?;
    let rows = work.db(statement.query_map([now], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    }))?;
    let mut found = Vec::new();
    for row in rows {
        found.push(work.db(row)?);
    }
    drop(statement);
    for (invocation, run, environment) in &found {
        let id = EnvironmentId::parse(environment)
            .ok_or(AuthorityError::Invariant("a stored workload is malformed"))?;
        let begun = environment::begin_destroy(work, &id, "WORKLOAD_INTERRUPTED")?;
        work.audit(
            AuditEvent::WorkloadOutcome,
            Fields::new()
                .text("run_id", run.as_str())
                .text("invocation_id", invocation.as_str())
                .text("environment_id", environment.as_str())
                .text("state", "UNKNOWN")
                .text("reason", "INTERRUPTED")
                .flag(
                    "environment_destroy_pending",
                    matches!(begun, DestroyBegun::Pending { .. }),
                ),
        )?;
    }
    Ok(u64::try_from(found.len()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{WorkloadRequest, WorkloadState, check};
    use crate::sandbox::{SandboxConfig, WorkloadBudget};
    use dwk_proto::brokerp::sandbox::NetworkTopology;

    fn config() -> SandboxConfig {
        let Ok(config) = SandboxConfig::new(
            "/usr/bin/docker",
            "/var/run/docker.sock",
            &format!("sha256:{}", "a".repeat(64)),
            &"b".repeat(64),
            NetworkTopology::NoNetwork,
        ) else {
            unreachable!("a valid configuration")
        };
        let Ok(config) = config.with_workloads(
            &[("/usr/libexec/direwolf/sandbox-fixture", &"c".repeat(64))],
            WorkloadBudget::default(),
        ) else {
            unreachable!("a valid manifest")
        };
        config
    }

    fn request() -> WorkloadRequest {
        WorkloadRequest {
            executable: "/usr/libexec/direwolf/sandbox-fixture".to_owned(),
            args: vec!["status".to_owned()],
            stream_limit: 4096,
            wall_clock_seconds: 30,
            key: "w-1".to_owned(),
        }
    }

    #[test]
    fn a_workload_is_only_what_the_manifest_names_within_its_bounds() {
        assert!(check(&request(), &config()).is_ok());
        let refused = |change: fn(&mut WorkloadRequest)| {
            let mut asked = request();
            change(&mut asked);
            check(&asked, &config()).err()
        };
        assert_eq!(
            refused(|r| r.executable = "/usr/bin/sh".to_owned()),
            Some("EXECUTABLE_NOT_IN_MANIFEST")
        );
        assert_eq!(
            refused(|r| r.executable = "/usr/libexec/direwolf/../sandbox-fixture".to_owned()),
            Some("EXECUTABLE_NOT_IN_MANIFEST")
        );
        assert_eq!(
            refused(|r| r.stream_limit = 0),
            Some("STREAM_LIMIT_INVALID")
        );
        assert_eq!(
            refused(|r| r.stream_limit = 131_073),
            Some("STREAM_LIMIT_INVALID")
        );
        assert_eq!(
            refused(|r| r.wall_clock_seconds = 0),
            Some("WALL_CLOCK_INVALID")
        );
        assert_eq!(
            refused(|r| r.wall_clock_seconds = 601),
            Some("WALL_CLOCK_INVALID")
        );
        assert_eq!(
            refused(|r| r.key = String::new()),
            Some("IDEMPOTENCY_KEY_INVALID")
        );
        assert_eq!(
            refused(|r| r.key = "a key".to_owned()),
            Some("IDEMPOTENCY_KEY_INVALID")
        );
        assert_eq!(
            refused(|r| r.args = vec!["a\0b".to_owned()]),
            Some("ARGUMENT_INVALID")
        );
        assert_eq!(
            refused(|r| r.args = vec!["x".to_owned(); 129]),
            Some("ARGV_TOO_LARGE")
        );
    }

    #[test]
    fn a_workload_state_has_one_spelling() {
        for state in [
            WorkloadState::Launching,
            WorkloadState::Completed,
            WorkloadState::Failed,
            WorkloadState::Unknown,
        ] {
            assert_eq!(WorkloadState::parse(state.as_str()), Some(state));
        }
        assert_eq!(WorkloadState::parse("RUNNING"), None);
    }
}
