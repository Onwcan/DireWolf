//! `process.exec`, `process.status` and `process.kill` (M4d, [ADR-0045]): a
//! canonical plan, both gates, the kernel's host-execution floor, and — for an
//! invocation that passes all of them — one brokered process operation.
//!
//! # The order, the same as the filesystem tools'
//!
//! ```text
//! 1  (transaction)  locate: the fence, the run, the key; the call's type and
//!                   bounds; for a launch the run's root binding, for a status
//!                   or a kill the process the run launched and its STORED
//!                   identity (read by grammar, never looked up)
//! 2  (none)         a launch only: the executable resolver (O_PATH handles;
//!                   the hash descriptor is closed before it returns) and the
//!                   working directory beneath the pinned root
//! 3  (transaction)  decide: the fence, the run and the key again; the plan;
//!                   both gates; the obligations; the host floor. A preview
//!                   records its plan and stops, a denial likewise. Otherwise:
//!                   the invocation id, for a launch the process id and its
//!                   LAUNCHING row, the key -- the INTENT; COMMIT, fsync
//!   4  (none)       a launch only: the executable opened for reading by its
//!                   one name and proved to be the object hashed; the working
//!                   directory opened and proved
//!   5  (none)       the broker: one authorisation
//!   6  (transaction) the outcome and the process's recorded state, and for
//!                   a status with output the taint; COMMIT, fsync; answer
//! ```
//!
//! # The host floor
//!
//! Every process this milestone can start runs **on the host**, with the
//! broker's privileges: there is no execution environment until M5
//! (`SANDBOX.md` §4). The kernel therefore performs a host `process.exec` only
//! if **both** hold, whatever policy says:
//!
//! 1. the operator opted in (`--allow-host-execution`, policy's
//!    `security.allow_host_execution`) — otherwise `HOST_EXECUTION_DISABLED`;
//! 2. a **per-invocation approval** exists — otherwise `APPROVAL_REQUIRED`.
//!
//! Approvals are M6's. **No production build of M4d has one**, so no
//! production `process.exec` launches anything: it is planned, decided, audited
//! and refused. There is no flag, feature or environment variable that
//! supplies an approval. The one stand-in is `#[cfg(test)]` — it exists in this
//! crate's unit tests only, where the durable machinery after the floor is
//! exercised against an in-process fake broker (ADR-0045 §2, evidence D); the
//! broker's own launch path is exercised by the real broker binary through a
//! test authority peer (evidence C).
//!
//! `process.status` and `process.kill` run nothing, so the floor does not
//! apply to them; they can only name a process a launch recorded, which
//! production never records.
//!
//! [ADR-0045]: ../../../../../docs/adr/0045-m4d-process-execution-broker.md

use dwk_proto::brokerp::{BrokerGeneration, BrokerRefusal, ExecEnvironment};
use dwk_proto::dwkp::procops::ToolCallV3;
use dwk_proto::json;
use dwk_proto::limits::{MAX_PROCESS_ARGV_BYTES, MAX_PROCESS_STREAM_BYTES};
use dwk_proto::wire::WireType as _;
use dwk_proto::wire::id::{InvocationId, ProcessId, RunId, SessionId};
use dwk_proto::wire::scalar::{
    CoreTool, Epoch, IdempotencyKey, KillOutcome, ProcessDecisionReason, ProcessState, ProcessVerb,
    ToolFailureReasonV3, ToolOperation, ToolRefusalReasonV3,
};
use rusqlite::OptionalExtension as _;

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, Operation, ProcessStartDelivery,
    ProcessStatusDelivery,
};
use crate::capability::{
    Action, ArgvAllowlist, ArgvToken, Capability, ConstraintSet, DeclaredPath, Namespace, Scope,
    Verb,
};
use crate::policy::{ArgvSafety, CanonicalAction, Effect, Environment, Obligation, TaintLevel};
use crate::resource::exec::argv::{self, ArgvClass};
use crate::resource::exec::{self, ExecError, ResolvedExecutable};
use crate::resource::fs::{Access, Expect, PinnedRoot, ResolvedResource};
use crate::resource::{CanonicalPath, ExecutableIdentity};

use super::Work;
use super::admission;
use super::audit::{AuditEvent, Field, Fields};
use super::config::RootBinding;
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::plan::RetryClass;
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord, TaintCause};
use super::resolution::{self, ResolutionRefused};
use super::scopes;
use super::tool;

// ---------------------------------------------------------------------------
// The request and the answer.
// ---------------------------------------------------------------------------

/// A process tool request, as the state layer takes it: a version-3 call
/// naming one of the three process tools, and — for an invocation — its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRequest {
    call: ToolCallV3,
    key: Option<IdempotencyKey>,
}

impl ProcessRequest {
    /// A process request, or `None` if `call` names a filesystem tool.
    #[must_use]
    pub fn new(call: ToolCallV3, key: Option<IdempotencyKey>) -> Option<Self> {
        let process = call.process_exec.is_some()
            || call.process_status.is_some()
            || call.process_kill.is_some();
        process.then_some(Self { call, key })
    }

    /// The call.
    #[must_use]
    pub const fn call(&self) -> &ToolCallV3 {
        &self.call
    }

    /// The idempotency key.
    #[must_use]
    pub const fn key(&self) -> Option<&IdempotencyKey> {
        self.key.as_ref()
    }

    /// Which tool.
    #[must_use]
    pub const fn tool(&self) -> CoreTool {
        if self.call.process_status.is_some() {
            CoreTool::ProcessStatus
        } else if self.call.process_kill.is_some() {
            CoreTool::ProcessKill
        } else {
            CoreTool::ProcessExec
        }
    }
}

/// One output stream, as the broker retained it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSnapshot {
    /// Its first bytes, at most the launch's per-stream bound.
    pub content: Vec<u8>,
    /// Every byte written to it so far.
    pub observed: u64,
    /// Whether more was written than retained.
    pub truncated: bool,
}

/// What a process tool produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutput {
    /// `process.exec`: the process was started and is supervised.
    Launched {
        /// The authority's handle for it.
        process_id: ProcessId,
        /// Its state when the launch was confirmed.
        state: ProcessState,
        /// Its exit code, if it had already exited.
        exit_code: Option<u8>,
        /// The signal that ended it, if one already had.
        signal: Option<u8>,
    },
    /// `process.status`.
    Observed {
        /// The handle.
        process_id: ProcessId,
        /// Its state.
        state: ProcessState,
        /// Its exit code, once it exited.
        exit_code: Option<u8>,
        /// The signal that ended it, once one did.
        signal: Option<u8>,
        /// Whether the broker's wall clock ended it.
        timed_out: bool,
        /// `stdout`.
        stdout: StreamSnapshot,
        /// `stderr`.
        stderr: StreamSnapshot,
    },
    /// `process.kill`.
    Killed {
        /// The handle.
        process_id: ProcessId,
        /// Whether the signal was sent or the process had already exited.
        outcome: KillOutcome,
    },
}

/// How a process tool operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessReply {
    /// Performed and recorded.
    Done {
        /// The authority's id for the invocation.
        invocation: InvocationId,
        /// The plan.
        plan: ProcessPlan,
        /// What it produced.
        output: Box<ProcessOutput>,
    },
    /// The plan's action was refused. Nothing was opened, launched or sent.
    Denied(ProcessPlan),
    /// A preview: the plan an invocation would decide on.
    Previewed(ProcessPlan),
    /// Refused before any effect was authorised.
    Refused(ToolOperation, ToolRefusalReasonV3),
    /// An authorised invocation produced no result.
    Failed {
        /// The authority's id for it.
        invocation: InvocationId,
        /// Why.
        reason: ToolFailureReasonV3,
    },
}

// ---------------------------------------------------------------------------
// The call, typed.
// ---------------------------------------------------------------------------

/// A process call, typed: its executable still only declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Call {
    /// Start a process.
    Exec {
        /// The executable, as spelled.
        executable: String,
        /// The arguments after `argv[0]`.
        args: Vec<String>,
        /// The working directory.
        cwd: DeclaredPath,
    },
    /// Observe one this run launched.
    Status {
        /// Its handle.
        process: ProcessId,
    },
    /// Kill one this run launched.
    Kill {
        /// Its handle.
        process: ProcessId,
    },
}

/// Every argument's bytes, together.
fn argv_bytes(args: &[String]) -> usize {
    args.iter().map(String::len).fold(0, usize::saturating_add)
}

impl Call {
    /// Type a wire call, refusing what no resolution could make sense of.
    ///
    /// # Errors
    ///
    /// `ARGV_TOO_LARGE` (the aggregate bound, which the decoder does not
    /// check), `PATH_NOT_CANONICAL` (a working directory that is not even a
    /// path).
    fn from_wire(call: &ToolCallV3) -> Result<Self, ToolRefusalReasonV3> {
        if let Some(launch) = &call.process_exec {
            let args: Vec<String> = launch.args.iter().map(|a| a.as_str().to_owned()).collect();
            if argv_bytes(&args) > MAX_PROCESS_ARGV_BYTES {
                return Err(ToolRefusalReasonV3::ArgvTooLarge);
            }
            let cwd = launch.cwd.as_ref().map_or("/workspace", |c| c.as_str());
            let cwd = DeclaredPath::new(cwd).ok_or(ToolRefusalReasonV3::PathNotCanonical)?;
            return Ok(Self::Exec {
                executable: launch.executable.as_str().to_owned(),
                args,
                cwd,
            });
        }
        if let Some(status) = &call.process_status {
            return Ok(Self::Status {
                process: status.process_id.clone(),
            });
        }
        if let Some(kill) = &call.process_kill {
            return Ok(Self::Kill {
                process: kill.process_id.clone(),
            });
        }
        Err(ToolRefusalReasonV3::UnknownProcess)
    }
}

/// The retry class of each process tool: a launch and a kill are effects, and
/// repeating one is a second effect; a status converges.
pub(super) const fn retry_class(tool: CoreTool) -> RetryClass {
    match tool {
        CoreTool::ProcessStatus => RetryClass::RetrySafe,
        _ => RetryClass::NonRetryable,
    }
}

/// Whether a process tool has an effect: it can end `UNKNOWN`, never
/// `INTERRUPTED`.
pub(super) const fn has_effect(tool: CoreTool) -> bool {
    matches!(tool, CoreTool::ProcessExec | CoreTool::ProcessKill)
}

// ---------------------------------------------------------------------------
// Reason vocabularies.
// ---------------------------------------------------------------------------

/// The refusal for an executable the resolver refused.
pub(super) const fn exec_refusal(error: ExecError) -> ToolRefusalReasonV3 {
    match error {
        ExecError::PathInvalid => ToolRefusalReasonV3::ExecutablePathInvalid,
        ExecError::NotFound => ToolRefusalReasonV3::ExecutableNotFound,
        ExecError::NotADirectory => ToolRefusalReasonV3::NotADirectory,
        ExecError::NotRegular => ToolRefusalReasonV3::ExecutableNotRegular,
        ExecError::NotExecutable => ToolRefusalReasonV3::ExecutableNotExecutable,
        ExecError::SymlinkLimit => ToolRefusalReasonV3::ExecutableSymlinkLimit,
        ExecError::Untrusted(_) => ToolRefusalReasonV3::ExecutableUntrusted,
        ExecError::TooLarge => ToolRefusalReasonV3::ExecutableTooLarge,
        ExecError::Script => ToolRefusalReasonV3::ScriptUnsupported,
        ExecError::NotNative => ToolRefusalReasonV3::NotNativeExecutable,
        ExecError::Race => ToolRefusalReasonV3::ExecutableRace,
        ExecError::PermissionDenied => ToolRefusalReasonV3::PermissionDenied,
        ExecError::Io(_) => ToolRefusalReasonV3::IoError,
        ExecError::Unsupported => ToolRefusalReasonV3::UnsupportedPlatform,
    }
}

/// A filesystem refusal class, in the version-3 vocabulary (same spelling).
pub(super) fn widen_refusal(
    reason: dwk_proto::wire::scalar::FsRefusalReason,
) -> ToolRefusalReasonV3 {
    ToolRefusalReasonV3::ALL
        .iter()
        .copied()
        .find(|r| r.as_str() == reason.as_str())
        .unwrap_or(ToolRefusalReasonV3::IoError)
}

/// A filesystem failure class, in the version-3 vocabulary (same spelling).
pub(super) fn widen_failure(
    reason: dwk_proto::wire::scalar::FsFailureReason,
) -> ToolFailureReasonV3 {
    ToolFailureReasonV3::ALL
        .iter()
        .copied()
        .find(|r| r.as_str() == reason.as_str())
        .unwrap_or(ToolFailureReasonV3::BrokerExecutionError)
}

/// The wire class of a broker failure that provably changed nothing, or of any
/// failure of `process.status`.
pub(super) const fn failure_reason(failure: BrokerFailure) -> ToolFailureReasonV3 {
    match failure {
        BrokerFailure::NotConfigured
        | BrokerFailure::Unreachable(_)
        | BrokerFailure::PeerRefused { .. } => ToolFailureReasonV3::BrokerUnavailable,
        BrokerFailure::Protocol(_) => ToolFailureReasonV3::BrokerProtocolError,
        BrokerFailure::Refused(refusal) => match refusal {
            BrokerRefusal::DigestMismatch | BrokerRefusal::ExecutableUntrusted => {
                ToolFailureReasonV3::ExecutableChanged
            }
            BrokerRefusal::IdentityMismatch => ToolFailureReasonV3::ObjectChanged,
            BrokerRefusal::ExecSetupFailed | BrokerRefusal::ExecFailed => {
                ToolFailureReasonV3::ExecFailed
            }
            BrokerRefusal::InheritedDescriptor => ToolFailureReasonV3::BrokerEnvironmentUnsafe,
            BrokerRefusal::ProcessTableFull => ToolFailureReasonV3::ProcessTableFull,
            BrokerRefusal::UnknownProcess | BrokerRefusal::StaleGeneration => {
                ToolFailureReasonV3::ProcessUnobservable
            }
            BrokerRefusal::ChannelMismatch
            | BrokerRefusal::DescriptorCount
            | BrokerRefusal::DescriptorNotRegular
            | BrokerRefusal::DescriptorNotDirectory
            | BrokerRefusal::DescriptorNotReadable
            | BrokerRefusal::DescriptorNotPath
            | BrokerRefusal::ReadFailed
            | BrokerRefusal::Unsupported
            | BrokerRefusal::DirectoryTooLarge
            | BrokerRefusal::IoError
            | BrokerRefusal::ObjectChanged
            | BrokerRefusal::TargetOccupied
            | BrokerRefusal::Conflict
            | BrokerRefusal::DirectoryNotEmpty
            | BrokerRefusal::WriteDenied
            | BrokerRefusal::AttributesNotPreserved
            | BrokerRefusal::SharedDirectory
            | BrokerRefusal::ProcessIdInUse => ToolFailureReasonV3::BrokerExecutionError,
        },
        BrokerFailure::Indeterminate(_) => ToolFailureReasonV3::BrokerExecutionError,
    }
}

// ---------------------------------------------------------------------------
// The approval stand-in.
// ---------------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    static TEST_APPROVAL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Run `work` as though every host `process.exec` it decides carried a
/// per-invocation approval. **`#[cfg(test)]`**: it exists in this crate's unit
/// tests only — never in a build a user runs, never behind a feature, and not
/// reachable from an integration test, which links the library compiled
/// without `cfg(test)`. It stands in for M6 so that the durable machinery
/// after the floor can be tested against an in-process fake broker; it proves
/// nothing about approvals themselves. Its callers resolve real executables,
/// which only Linux does.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn with_test_approval<T>(work: impl FnOnce() -> T) -> T {
    TEST_APPROVAL.with(|slot| slot.set(true));
    let result = work();
    TEST_APPROVAL.with(|slot| slot.set(false));
    result
}

/// Whether a per-invocation approval exists for a host launch. In every
/// production build: **no** — approvals are M6's.
fn approved() -> bool {
    #[cfg(test)]
    {
        TEST_APPROVAL.with(core::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// The plan.
// ---------------------------------------------------------------------------

/// Where the kernel's host floor left a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    /// Not a launch: the floor does not apply.
    NotApplicable,
    /// The operator has not opted in to host execution.
    HostExecutionDisabled,
    /// Opted in, and no per-invocation approval exists.
    ApprovalRequired,
    /// Opted in and approved.
    Passed,
}

/// What a launch plan records about its argv and its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    cwd: CanonicalPath,
    cwd_object: (u64, u64),
    args: Vec<String>,
    argv_sha256: Sha256Hash,
    class: ArgvClass,
    environment: ExecEnvironment,
    stream_limit: u32,
}

impl Launch {
    /// The working directory's canonical path.
    #[must_use]
    pub const fn cwd(&self) -> &CanonicalPath {
        &self.cwd
    }

    /// How many arguments follow `argv[0]`.
    #[must_use]
    pub fn arg_count(&self) -> usize {
        self.args.len()
    }

    /// The digest of the arguments.
    #[must_use]
    pub const fn argv_sha256(&self) -> &Sha256Hash {
        &self.argv_sha256
    }

    /// The argv classification.
    #[must_use]
    pub const fn class(&self) -> ArgvClass {
        self.class
    }

    /// Whether the classification is `REINTERPRETING`.
    #[must_use]
    pub const fn reinterpreting(&self) -> bool {
        matches!(self.class, ArgvClass::Reinterpreting { .. })
    }

    /// The environment profile the process would get.
    #[must_use]
    pub const fn environment(&self) -> ExecEnvironment {
        self.environment
    }

    /// The per-stream output bound.
    #[must_use]
    pub const fn stream_limit(&self) -> u32 {
        self.stream_limit
    }
}

/// A process plan's one action, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessAction {
    verb: ProcessVerb,
    executable: ExecutableIdentity,
    object: (u64, u64),
    process: Option<ProcessId>,
    launch: Option<Launch>,
    action: CanonicalAction,
    record: DecisionRecord,
    obligations_enforced: bool,
    floor: Floor,
}

impl ProcessAction {
    /// The capability verb.
    #[must_use]
    pub const fn verb(&self) -> ProcessVerb {
        self.verb
    }

    /// The executable's identity.
    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentity {
        &self.executable
    }

    /// The executable's device and inode.
    #[must_use]
    pub const fn object(&self) -> (u64, u64) {
        self.object
    }

    /// The process a status or a kill names.
    #[must_use]
    pub const fn process(&self) -> Option<&ProcessId> {
        self.process.as_ref()
    }

    /// A launch's working directory, argv and environment.
    #[must_use]
    pub const fn launch(&self) -> Option<&Launch> {
        self.launch.as_ref()
    }

    /// The canonical action policy decided on.
    #[must_use]
    pub const fn action(&self) -> &CanonicalAction {
        &self.action
    }

    /// Both gates' results.
    #[must_use]
    pub const fn record(&self) -> &DecisionRecord {
        &self.record
    }

    /// The host floor.
    #[must_use]
    pub const fn floor(&self) -> Floor {
        self.floor
    }

    /// Whether the policy gate is satisfied: the rule allows, and every
    /// obligation it imposes is one this authority enforces.
    #[must_use]
    pub fn policy_satisfied(&self) -> bool {
        self.record.policy_satisfied() && self.obligations_enforced
    }

    /// Both gates and the floor.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.record.capability_satisfied()
            && self.policy_satisfied()
            && matches!(self.floor, Floor::NotApplicable | Floor::Passed)
    }

    /// Why it was decided as it was — in the order ADR-0045 §3 fixes: an
    /// unevaluable input, then the host floor's opt-in, then policy, then the
    /// capability, then the obligations, then the approval.
    #[must_use]
    pub fn reason(&self) -> ProcessDecisionReason {
        let policy = self.record.policy();
        if self.permits() {
            return ProcessDecisionReason::AllowedByRule;
        }
        if policy.unevaluable().is_some() {
            return ProcessDecisionReason::UnresolvedPolicyInput;
        }
        if self.floor == Floor::HostExecutionDisabled {
            return ProcessDecisionReason::HostExecutionDisabled;
        }
        match policy.effect() {
            Effect::Deny if policy.rule_id().is_default() => ProcessDecisionReason::DefaultDeny,
            Effect::Deny => ProcessDecisionReason::DeniedByRule,
            _ if !self.record.capability_satisfied() => ProcessDecisionReason::NoCapability,
            Effect::Allow if !self.obligations_enforced => {
                ProcessDecisionReason::ObligationUnenforceable
            }
            // REQUIRE_APPROVAL, or ALLOW with the floor's approval missing:
            // either way no approval exists.
            _ => ProcessDecisionReason::ApprovalRequired,
        }
    }
}

/// A process call's complete plan: one action, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPlan {
    tool: CoreTool,
    action: ProcessAction,
}

impl ProcessPlan {
    /// The tool.
    #[must_use]
    pub const fn tool(&self) -> CoreTool {
        self.tool
    }

    /// Its one action.
    #[must_use]
    pub const fn action(&self) -> &ProcessAction {
        &self.action
    }

    /// Its retry class.
    #[must_use]
    pub const fn retry_class(&self) -> RetryClass {
        retry_class(self.tool)
    }

    /// Whether it is permitted: the only condition under which anything is
    /// performed.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.action.permits()
    }
}

/// The argv digest: the count, then every argument, length-prefixed.
fn argv_digest(args: &[String]) -> Sha256Hash {
    let mut hash =
        DomainHash::new(digest::PROCESS_ARGV).int(u64::try_from(args.len()).unwrap_or(u64::MAX));
    for arg in args {
        hash = hash.text(arg);
    }
    hash.finish()
}

/// The capability an action requires. `process.exec` binds the first
/// argument as `argv_allowlist` when it is a token an allowlist can name
/// (ADR-0045 §7): a grant with an allowlist covers the invocation only if the
/// allowlist lists that selector. An invocation with no argument, or whose
/// first argument is not a token, requires the capability with no allowlist,
/// which only an unconstrained grant covers. Nothing on the wire states it.
fn required_capability(
    verb: ProcessVerb,
    executable: &ExecutableIdentity,
    args: &[String],
) -> Result<Capability, AuthorityError> {
    let action = match verb {
        ProcessVerb::ProcessExec => Action::Exec,
        ProcessVerb::ProcessInspect => Action::Inspect,
        ProcessVerb::ProcessSignal => Action::Signal,
    };
    let verb = Verb::new(Namespace::Process, action)
        .ok_or(AuthorityError::Invariant("a process action is not a verb"))?;
    let argv_allowlist = if action == Action::Exec {
        args.first()
            .and_then(|selector| ArgvToken::new(selector))
            .and_then(|token| ArgvAllowlist::new(vec![token]))
    } else {
        None
    };
    let constraints = ConstraintSet {
        argv_allowlist,
        ..ConstraintSet::unconstrained()
    };
    Capability::new(verb, Scope::Executable(executable.clone()), constraints)
        .map_err(|_| AuthorityError::Invariant("a process capability does not assemble"))
}

/// Whether the authority enforces every obligation `record`'s decision
/// carries, for this action — and the environment profile and per-stream
/// bound a launch will then carry. ADR-0045 §14:
///
/// | obligation | `process.exec` | `process.status` | `process.kill` |
/// |---|---|---|---|
/// | `max_output_bytes=N` | each stream keeps its first `N / 2` bytes (`N >= 2`) | the launch's bound is within `N` | enforced: no output |
/// | `workspace_exec_hygiene` | **not enforceable** (below) | — | — |
/// | `audit_level=full` | the intent record carries the full argv | enforced | enforced |
/// | anything else | **not enforceable** | **not enforceable** | **not enforceable** |
///
/// `network_deny`, `force_environment`, `read_only_workspace` and the rest
/// need an execution environment (M5) or approvals (M6): a rule imposing one
/// is an obligation this build cannot keep, so the action is denied
/// `OBLIGATION_UNENFORCEABLE`, never performed without it.
///
/// `workspace_exec_hygiene` is among them. Its environment forms are undone
/// by the arguments of the programs they target — `npm --ignore-scripts=false`,
/// `cargo --config net.offline=false`, a later pytest `-p` — and none of them
/// reaches the configuration a repository carries itself (`.git/config`,
/// `.git/hooks`, `conftest.py`, `build.rs`). Setting them would claim a
/// neutralisation the host cannot deliver; on the host only an execution
/// environment (M5) can (ADR-0045 §11).
fn obligations(
    verb: ProcessVerb,
    record: &DecisionRecord,
    launched_stream_limit: Option<u32>,
) -> (bool, ExecEnvironment, u32) {
    let environment = ExecEnvironment::Base;
    let mut stream_limit = u32::try_from(MAX_PROCESS_STREAM_BYTES).unwrap_or(u32::MAX);
    let mut enforced = true;
    for obligation in record.policy().obligations().as_slice() {
        let ok = match (obligation, verb) {
            (Obligation::MaxOutputBytes(limit), ProcessVerb::ProcessExec) => {
                let per_stream = limit.checked_div(2).unwrap_or(0);
                if per_stream == 0 {
                    false
                } else {
                    stream_limit = stream_limit.min(u32::try_from(per_stream).unwrap_or(u32::MAX));
                    true
                }
            }
            (Obligation::MaxOutputBytes(limit), ProcessVerb::ProcessInspect) => {
                launched_stream_limit.is_some_and(|per| u64::from(per).saturating_mul(2) <= *limit)
            }
            (Obligation::MaxOutputBytes(_), ProcessVerb::ProcessSignal)
            | (Obligation::AuditLevel(_), _) => true,
            _ => false,
        };
        enforced &= ok;
    }
    (enforced, environment, stream_limit)
}

/// What the plan is decided from.
enum Planned<'a> {
    Launch {
        executable: &'a ResolvedExecutable,
        cwd: &'a ResolvedResource,
        args: &'a [String],
    },
    Handle {
        verb: ProcessVerb,
        stored: &'a StoredProcess,
    },
}

/// Decide the one action. Pure: reads what the caller loaded.
fn decide_plan(
    tool: CoreTool,
    planned: &Planned<'_>,
    admission: &admission::Admission,
    context: &crate::policy::PolicyContext,
    active: &ActiveAuthority,
) -> Result<ProcessPlan, AuthorityError> {
    let (verb, executable, object, process, args, stored_limit) = match planned {
        Planned::Launch {
            executable, args, ..
        } => (
            ProcessVerb::ProcessExec,
            executable.identity().clone(),
            (executable.object().device(), executable.object().inode()),
            None,
            *args,
            None,
        ),
        Planned::Handle { verb, stored } => (
            *verb,
            stored.identity.clone(),
            stored.object,
            Some(stored.process_id.clone()),
            &[][..],
            Some(stored.stream_limit),
        ),
    };
    let capability = required_capability(verb, &executable, args)?;
    let mut action = CanonicalAction::new(capability, Environment::Host);
    let mut launch = None;
    if let Planned::Launch { cwd, args, .. } = planned {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let class = argv::classify(&executable, &refs);
        action = action.with_argv_safety(match class {
            ArgvClass::Safe => ArgvSafety::Safe,
            ArgvClass::Reinterpreting { .. } => ArgvSafety::Reinterpreting,
        });
        launch = Some(Launch {
            cwd: cwd.canonical_path().clone(),
            cwd_object: (cwd.identity().device(), cwd.identity().inode()),
            args: args.to_vec(),
            argv_sha256: argv_digest(args),
            class,
            environment: ExecEnvironment::Base,
            stream_limit: 0,
        });
    }
    let record = query::decide(&action, admission, context, active);
    let (obligations_enforced, environment, stream_limit) =
        obligations(verb, &record, stored_limit);
    if let Some(launch) = launch.as_mut() {
        launch.environment = environment;
        launch.stream_limit = stream_limit;
    }
    let floor = if verb == ProcessVerb::ProcessExec {
        if !active.flags.security_allow_host_execution {
            Floor::HostExecutionDisabled
        } else if approved() {
            Floor::Passed
        } else {
            Floor::ApprovalRequired
        }
    } else {
        Floor::NotApplicable
    };
    Ok(ProcessPlan {
        tool,
        action: ProcessAction {
            verb,
            executable,
            object,
            process,
            launch,
            action,
            record,
            obligations_enforced,
            floor,
        },
    })
}

// ---------------------------------------------------------------------------
// Steps 1-3.
// ---------------------------------------------------------------------------

/// Who asks, about what.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked<'a> {
    pub(super) caller: &'a CallerContext,
    pub(super) operation: ToolOperation,
    pub(super) session: &'a SessionId,
    pub(super) run: &'a RunId,
    pub(super) epoch: Epoch,
    pub(super) request: &'a ProcessRequest,
}

impl Asked<'_> {
    fn binding_key(&self) -> Option<&IdempotencyKey> {
        match self.operation {
            ToolOperation::ToolInvoke => self.request.key(),
            ToolOperation::CanonicalPreview => None,
        }
    }
}

/// A process the run launched, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoredProcess {
    process_id: ProcessId,
    identity: ExecutableIdentity,
    object: (u64, u64),
    generation: Option<BrokerGeneration>,
    state: String,
    stream_limit: u32,
}

/// What step 1 found.
#[derive(Debug)]
pub(super) enum Located {
    /// Refused, and recorded.
    Refused(ToolRefusalReasonV3),
    /// A launch, to be resolved beneath this binding.
    Launch {
        /// The call, typed.
        call: Call,
        /// The run's root binding.
        binding: RootBinding,
    },
    /// A status or a kill of a process the run launched.
    Handle {
        /// The call, typed.
        call: Call,
        /// The process.
        stored: StoredProcess,
    },
}

/// What step 2 found for a launch.
#[derive(Debug)]
pub(super) struct Resolved {
    executable: ResolvedExecutable,
    cwd: ResolvedResource,
}

/// What step 3 decided.
#[derive(Debug)]
pub(super) enum Decided {
    /// Refused (the fence, the run or the key changed), and recorded.
    Refused(ToolRefusalReasonV3),
    /// The action was refused.
    Denied(ProcessPlan),
    /// A preview's answer.
    Previewed(ProcessPlan),
    /// Authorised, the intent durable.
    Authorised {
        /// The plan.
        plan: ProcessPlan,
        /// The invocation.
        invocation: InvocationId,
        /// The process: minted for a launch, stored for a status or a kill.
        process: ProcessId,
    },
}

/// Whether an idempotency key is already bound, in either ledger.
fn key_bound(
    work: &Work<'_>,
    asked: &Asked<'_>,
    key: &IdempotencyKey,
) -> Result<bool, AuthorityError> {
    let found: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM process_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3 UNION ALL SELECT 1 FROM tool_idempotency WHERE \
             subject = ?1 AND session_id = ?2 AND idempotency_key = ?3 LIMIT 1",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                key.as_str()
            ],
            |row| row.get(0),
        )
        .optional())?;
    Ok(found.is_some())
}

/// The fence, the run and — for an invocation — the key.
fn standing(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<Option<ToolRefusalReasonV3>, AuthorityError> {
    if !lease::fence(work, asked.caller, asked.session, asked.epoch)? {
        return Ok(Some(ToolRefusalReasonV3::StaleEpoch));
    }
    if !tool::run_is_held(
        work,
        asked.caller,
        asked.session,
        asked.run,
        asked.epoch,
        active,
    )? {
        return Ok(Some(ToolRefusalReasonV3::UnknownRun));
    }
    if asked.operation == ToolOperation::ToolInvoke {
        let Some(key) = asked.request.key() else {
            return Err(AuthorityError::Invariant(
                "a version-3 invocation arrived without an idempotency key",
            ));
        };
        if key_bound(work, asked, key)? {
            return Ok(Some(ToolRefusalReasonV3::IdempotencyKeyReused));
        }
    }
    Ok(None)
}

/// Who asked, about what: the fields every process record starts with.
fn base_fields(asked: &Asked<'_>, tool: CoreTool) -> Fields {
    let fields = Fields::new()
        .text("operation", asked.operation.as_str())
        .text("tool", tool.as_str())
        .int("protocol_version", 3)
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get())
        .text("environment", "host");
    match asked.binding_key() {
        Some(key) => fields.text("idempotency_key", key.as_str()),
        None => fields,
    }
}

/// Record a refusal and return it.
fn refuse(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: ToolRefusalReasonV3,
    detail: Option<&str>,
) -> Result<ToolRefusalReasonV3, AuthorityError> {
    let mut fields = base_fields(asked, asked.request.tool()).text("refusal", reason.as_str());
    if let Some(detail) = detail {
        fields = fields.text("resolver", detail);
    }
    work.audit(AuditEvent::ToolRefused, fields)?;
    Ok(reason)
}

/// Record a resolution's refusal: the class, and the resolver's own code.
pub(super) fn refuse_resolution(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: ToolRefusalReasonV3,
    detail: &str,
) -> Result<ToolRefusalReasonV3, AuthorityError> {
    refuse(work, asked, reason, Some(detail))
}

impl StoredProcess {
    /// The per-stream bound its launch was given.
    pub(super) const fn stream_limit(&self) -> u32 {
        self.stream_limit
    }
}

/// A process the run launched and that can be observed or signalled: its
/// launch was confirmed. `None` for another run's, an unknown handle, or a
/// launch whose outcome is failed or unknown.
fn stored_process(
    work: &Work<'_>,
    run: &RunId,
    process: &ProcessId,
) -> Result<Option<StoredProcess>, AuthorityError> {
    type Row = (String, String, String, String, Option<String>, String, i64);
    let row: Option<Row> = work.db(work
        .tx
        .query_row(
            "SELECT executable_path, executable_sha256, executable_device, executable_inode, \
             broker_generation, state, stream_limit FROM tool_process \
             WHERE process_id = ?1 AND run_id = ?2",
            rusqlite::params![process.as_str(), run.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional())?;
    let Some((path, sha, device, inode, generation, state, limit)) = row else {
        return Ok(None);
    };
    if !matches!(
        state.as_str(),
        "RUNNING" | "EXITED" | "SIGNALED" | "UNOBSERVABLE"
    ) {
        return Ok(None);
    }
    let invariant = AuthorityError::Invariant("a stored process does not read back");
    // The stored identity, by grammar alone: nothing is looked up.
    let identity = scopes::stored_identity(&path, &sha).map_err(|_| invariant.clone())?;
    let object: (u64, u64) = (
        device.parse().map_err(|_| invariant.clone())?,
        inode.parse().map_err(|_| invariant.clone())?,
    );
    let generation = generation
        .map(|g| BrokerGeneration::new(g).ok_or(invariant.clone()))
        .transpose()?;
    Ok(Some(StoredProcess {
        process_id: process.clone(),
        identity,
        object,
        generation,
        state,
        stream_limit: u32::try_from(limit).map_err(|_| invariant)?,
    }))
}

/// Step 1.
pub(super) fn locate(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<Located, AuthorityError> {
    if let Some(reason) = standing(work, asked, active)? {
        return refuse(work, asked, reason, None).map(Located::Refused);
    }
    let call = match Call::from_wire(asked.request.call()) {
        Ok(call) => call,
        Err(reason) => return refuse(work, asked, reason, None).map(Located::Refused),
    };
    match &call {
        Call::Exec { .. } => match resolution::run_root(work, asked.run.as_str())? {
            Ok(binding) => Ok(Located::Launch { call, binding }),
            Err(ResolutionRefused::NoWorkspace | ResolutionRefused::NoWorkspaceRoot) => {
                refuse(work, asked, ToolRefusalReasonV3::WorkspaceUnbound, None)
                    .map(Located::Refused)
            }
            Err(_) => Err(AuthorityError::Invariant(
                "a live run's root binding could not be read",
            )),
        },
        Call::Status { process } | Call::Kill { process } => {
            match stored_process(work, asked.run, process)? {
                Some(stored) => Ok(Located::Handle { call, stored }),
                None => refuse(work, asked, ToolRefusalReasonV3::UnknownProcess, None)
                    .map(Located::Refused),
            }
        }
    }
}

/// Step 2, a launch only: the executable resolver, then the working directory
/// beneath the pinned root. `O_PATH` handles only. Call with no transaction
/// open.
///
/// # Errors
///
/// The refusal, and the resolver's own class for the audit record.
pub(super) fn resolve_launch(
    binding: &RootBinding,
    call: &Call,
    trusted_owner: u32,
) -> Result<Resolved, (ToolRefusalReasonV3, &'static str)> {
    let Call::Exec {
        executable, cwd, ..
    } = call
    else {
        return Err((ToolRefusalReasonV3::UnknownProcess, "NOT_A_LAUNCH"));
    };
    let executable = exec::resolve(executable, trusted_owner)
        .map_err(|error| (exec_refusal(error), error.code()))?;
    let root = PinnedRoot::reopen(&binding.host_path, &binding.fingerprint)
        .map_err(|error| (widen_refusal(tool::root_refusal(error)), "ROOT"))?;
    let cwd = root
        .resolve(cwd, Access::Observe, Expect::Directory)
        .map_err(|error| (widen_refusal(tool::resolve_refusal(error)), "CWD"))?;
    Ok(Resolved { executable, cwd })
}

/// The digest a key is bound to: the run and the canonical call.
fn request_digest(asked: &Asked<'_>) -> Result<Sha256Hash, AuthorityError> {
    let value = asked
        .request
        .call()
        .encode()
        .map_err(|_| AuthorityError::Invariant("a decoded call does not re-encode"))?;
    Ok(DomainHash::new(digest::TOOL_REQUEST)
        .text(asked.run.as_str())
        .bytes(&json::to_canonical_bytes(&value))
        .finish())
}

/// The plan's fields: the canonical action, both gates, the floor.
fn plan_fields(active: &ActiveAuthority, plan: &ProcessPlan) -> Fields {
    let action = plan.action();
    let record = action.record();
    let policy = record.policy();
    let mut fields = Fields::new()
        .text("policy_revision", active.revision.to_hex())
        .text("retry_class", plan.retry_class().as_str())
        .text("verb", action.verb().as_str())
        .text("executable", action.executable().path().to_string())
        .text(
            "executable_sha256",
            action.executable().digest().to_string(),
        )
        .text("executable_device", action.object().0.to_string())
        .text("executable_inode", action.object().1.to_string())
        .maybe_text(
            "process_id",
            action.process().map(|p| p.as_str().to_owned()),
        )
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
        .flag("policy_satisfied", action.policy_satisfied())
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
        .text(
            "host_floor",
            match action.floor() {
                Floor::NotApplicable => "NOT_APPLICABLE",
                Floor::HostExecutionDisabled => "HOST_EXECUTION_DISABLED",
                Floor::ApprovalRequired => "APPROVAL_REQUIRED",
                Floor::Passed => "PASSED",
            },
        )
        .text("reason", action.reason().as_str());
    if let Some(launch) = action.launch() {
        let class = match launch.class() {
            ArgvClass::Safe => Fields::new().text("argv_safety", "SAFE"),
            ArgvClass::Reinterpreting { rule, index } => Fields::new()
                .text("argv_safety", "REINTERPRETING")
                .text("argv_rule", rule.code())
                .maybe_int(
                    "argv_rule_index",
                    index.map(|i| u64::try_from(i).unwrap_or(u64::MAX)),
                ),
        };
        fields.extend(class);
        fields.extend(
            Fields::new()
                .text("cwd", launch.cwd().to_string())
                .text("cwd_device", launch.cwd_object.0.to_string())
                .text("cwd_inode", launch.cwd_object.1.to_string())
                .int("arg_count", u64::try_from(launch.arg_count()).unwrap_or(u64::MAX))
                .text("argv_sha256", launch.argv_sha256().to_hex())
                // The full canonical command (SANDBOX.md §4): argv is an
                // array, recorded as one. Output is never recorded.
                .list(
                    "argv",
                    std::iter::once(action.executable().path().to_string())
                        .chain(launch.args.iter().cloned())
                        .map(Field::Text)
                        .collect(),
                )
                .text("environment_profile", launch.environment().as_str())
                .int("stream_limit", u64::from(launch.stream_limit())),
        );
    }
    fields.text("effect", if plan.permits() { "ALLOW" } else { "DENY" })
}

/// A launch's process record, `LAUNCHING`, in the intent's transaction.
fn record_launching(
    work: &mut Work<'_>,
    run: &RunId,
    (invocation, process): (&InvocationId, &ProcessId),
    plan: &ProcessPlan,
    launch: &Launch,
) -> Result<(), AuthorityError> {
    let action = plan.action();
    work.db(work.tx.execute(
        "INSERT INTO tool_process (process_id, launch_invocation_id, run_id, \
         executable_path, executable_sha256, executable_device, executable_inode, cwd_path, \
         arg_count, argv_sha256, argv_safety, environment, stream_limit, broker_generation, \
         state, exit_code, signal, timed_out, created_ms, updated_ms) VALUES (?1, ?2, ?3, \
         ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, 'LAUNCHING', NULL, NULL, 0, ?14, \
         ?14)",
        rusqlite::params![
            process.as_str(),
            invocation.as_str(),
            run.as_str(),
            action.executable().path().to_string(),
            action.executable().digest().to_string(),
            action.object().0.to_string(),
            action.object().1.to_string(),
            launch.cwd().to_string(),
            i64::try_from(launch.arg_count()).unwrap_or(i64::MAX),
            launch.argv_sha256().to_hex(),
            if launch.reinterpreting() {
                "REINTERPRETING"
            } else {
                "SAFE"
            },
            launch.environment().as_str(),
            i64::from(launch.stream_limit()),
            to_sql(work.now)?
        ],
    ))?;
    Ok(())
}

/// Step 3.
pub(super) fn decide(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    located: &LocatedRef<'_>,
    active: &ActiveAuthority,
) -> Result<Decided, AuthorityError> {
    if let Some(reason) = standing(work, asked, active)? {
        return refuse(work, asked, reason, None).map(Decided::Refused);
    }
    let admission = admission::load(work, asked.run.as_str())?;
    let context = query::policy_context(work, asked.run.as_str(), active)?;
    let planned = match located {
        LocatedRef::Launch { call, resolved } => {
            let Call::Exec { args, .. } = call else {
                return Err(AuthorityError::Invariant("a launch that is not one"));
            };
            Planned::Launch {
                executable: &resolved.executable,
                cwd: &resolved.cwd,
                args,
            }
        }
        LocatedRef::Handle { call, stored } => {
            // The store may have moved on since step 1: re-read it, and refuse
            // a process that is no longer this run's to name.
            let Some(current) = stored_process(work, asked.run, &stored.process_id)? else {
                return refuse(work, asked, ToolRefusalReasonV3::UnknownProcess, None)
                    .map(Decided::Refused);
            };
            if current.identity != stored.identity {
                return Err(AuthorityError::Invariant(
                    "a stored process changed its identity",
                ));
            }
            Planned::Handle {
                verb: match call {
                    Call::Kill { .. } => ProcessVerb::ProcessSignal,
                    _ => ProcessVerb::ProcessInspect,
                },
                stored,
            }
        }
    };
    let plan = decide_plan(asked.request.tool(), &planned, &admission, &context, active)?;
    let mut fields = base_fields(asked, plan.tool());
    fields.extend(plan_fields(active, &plan));
    if asked.operation == ToolOperation::CanonicalPreview {
        work.audit(AuditEvent::ToolPreviewed, fields)?;
        return Ok(Decided::Previewed(plan));
    }
    if !plan.permits() {
        work.audit(AuditEvent::ToolDenied, fields)?;
        return Ok(Decided::Denied(plan));
    }
    // The durable intent, before any descriptor that could launch exists.
    let invocation = work.invocation_id()?;
    let process = match located {
        LocatedRef::Launch { .. } => work.process_id()?,
        LocatedRef::Handle { stored, .. } => stored.process_id.clone(),
    };
    work.db(work.tx.execute(
        "INSERT INTO process_invocation (invocation_id, run_id, tool, retry_class, process_id, \
         incarnation, state, failure, completion, output_bytes, intent_ms, ended_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'INTENT', NULL, NULL, NULL, ?7, NULL)",
        rusqlite::params![
            invocation.as_str(),
            asked.run.as_str(),
            plan.tool().as_str(),
            plan.retry_class().as_str(),
            process.as_str(),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    if let Some(launch) = plan.action().launch() {
        record_launching(work, asked.run, (&invocation, &process), &plan, launch)?;
    }
    if let Some(key) = asked.binding_key() {
        let digest = request_digest(asked)?;
        work.db(work.tx.execute(
            "INSERT INTO process_idempotency (subject, session_id, idempotency_key, \
             request_digest, invocation_id, recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                key.as_str(),
                digest.to_hex(),
                invocation.as_str(),
                to_sql(work.now)?
            ],
        ))?;
        fields.extend(Fields::new().text("request_digest", digest.to_hex()));
    }
    fields.extend(Fields::new().text("invocation_id", invocation.as_str()));
    if plan.action().process().is_none() {
        // A launch's handle is minted here; a status or a kill names its
        // process in the plan already.
        fields.extend(Fields::new().text("process_id", process.as_str()));
    }
    work.audit(AuditEvent::ToolIntentRecorded, fields)?;
    Ok(Decided::Authorised {
        plan,
        invocation,
        process,
    })
}

/// What step 3 decides from: a launch's resolution, or a stored process.
pub(super) enum LocatedRef<'a> {
    /// A launch.
    Launch {
        /// The call.
        call: &'a Call,
        /// What step 2 found.
        resolved: &'a Resolved,
    },
    /// A status or a kill.
    Handle {
        /// The call.
        call: &'a Call,
        /// The process.
        stored: &'a StoredProcess,
    },
}

// ---------------------------------------------------------------------------
// Step 4: the handoff.
// ---------------------------------------------------------------------------

/// Step 4: the operation, with exactly the descriptors it needs, made from
/// the checked objects and re-proved. A status or a kill carries none.
///
/// # Errors
///
/// The failure, when the executable or the working directory is no longer
/// what was checked.
pub(super) fn handoff(
    call: Call,
    resolved: Option<Resolved>,
    plan: &ProcessPlan,
    process: &ProcessId,
    stored: Option<&StoredProcess>,
) -> Result<Operation, (ToolFailureReasonV3, &'static str)> {
    match (call, resolved) {
        (Call::Exec { args, .. }, Some(resolved)) => {
            let launch = plan
                .action()
                .launch()
                .ok_or((ToolFailureReasonV3::BrokerExecutionError, "NO_LAUNCH"))?;
            let executable = resolved.executable.into_exec_handoff().map_err(|error| {
                (
                    match error {
                        ExecError::PermissionDenied | ExecError::Io(_) => {
                            ToolFailureReasonV3::ObjectUnreadable
                        }
                        _ => ToolFailureReasonV3::ExecutableChanged,
                    },
                    error.code(),
                )
            })?;
            let cwd = resolved
                .cwd
                .into_list_handoff()
                .map_err(|_| (ToolFailureReasonV3::ObjectChanged, "CWD"))?;
            Ok(Operation::ProcessStart {
                process_id: process.clone(),
                executable,
                cwd,
                args,
                environment: launch.environment(),
                stream_limit: launch.stream_limit(),
            })
        }
        (Call::Status { .. }, None) => {
            let generation = stored
                .and_then(|s| s.generation.clone())
                .ok_or((ToolFailureReasonV3::ProcessUnobservable, "NO_GENERATION"))?;
            Ok(Operation::ProcessStatus {
                process_id: process.clone(),
                generation,
            })
        }
        (Call::Kill { .. }, None) => {
            let generation = stored
                .and_then(|s| s.generation.clone())
                .ok_or((ToolFailureReasonV3::ProcessUnobservable, "NO_GENERATION"))?;
            Ok(Operation::ProcessKill {
                process_id: process.clone(),
                generation,
            })
        }
        _ => Err((ToolFailureReasonV3::BrokerExecutionError, "MISMATCH")),
    }
}

// ---------------------------------------------------------------------------
// Steps 5 and 6: the outcome.
// ---------------------------------------------------------------------------

/// How an invocation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ending {
    /// Performed; the output and what the process row becomes.
    Completed(Box<ProcessOutput>),
    /// Provably nothing was done.
    Failed(ToolFailureReasonV3),
    /// An effect may have happened, and nothing proves what.
    Unknown,
}

/// Why a delivery is not a result for this invocation.
type Malformed = &'static str;

fn completed(
    tool: CoreTool,
    process: &ProcessId,
    stream_limit: Option<u32>,
    delivery: BrokerDelivery,
) -> Result<ProcessOutput, Malformed> {
    Ok(match (tool, delivery) {
        (CoreTool::ProcessExec, BrokerDelivery::ProcessStarted(started)) => {
            launched(process, &started)?
        }
        (CoreTool::ProcessStatus, BrokerDelivery::ProcessStatus(status)) => {
            observed(process, stream_limit, status)?
        }
        (CoreTool::ProcessKill, BrokerDelivery::ProcessKilled(outcome)) => ProcessOutput::Killed {
            process_id: process.clone(),
            outcome,
        },
        _ => return Err("the broker answered another operation"),
    })
}

fn launched(
    process: &ProcessId,
    started: &ProcessStartDelivery,
) -> Result<ProcessOutput, Malformed> {
    let consistent = match started.state {
        ProcessState::Running => started.exit_code.is_none() && started.signal.is_none(),
        ProcessState::Exited => started.exit_code.is_some() && started.signal.is_none(),
        ProcessState::Signaled => started.exit_code.is_none() && started.signal.is_some(),
        ProcessState::Unobservable => false,
    };
    if !consistent {
        return Err("a launch's state does not agree with itself");
    }
    Ok(ProcessOutput::Launched {
        process_id: process.clone(),
        state: started.state,
        exit_code: started.exit_code,
        signal: started.signal,
    })
}

fn observed(
    process: &ProcessId,
    stream_limit: Option<u32>,
    status: ProcessStatusDelivery,
) -> Result<ProcessOutput, Malformed> {
    let limit = stream_limit.map_or(0, |l| usize::try_from(l).unwrap_or(usize::MAX));
    for stream in [&status.stdout, &status.stderr] {
        if stream.content.len() > limit {
            return Err("the broker returned more output than the launch retains");
        }
        let kept = u64::try_from(stream.content.len()).unwrap_or(u64::MAX);
        if stream.observed < kept || stream.truncated != (stream.observed > kept) {
            return Err("a stream's counts do not agree with its content");
        }
    }
    let consistent = match status.state {
        ProcessState::Running => status.exit_code.is_none() && status.signal.is_none(),
        ProcessState::Exited => status.exit_code.is_some() && status.signal.is_none(),
        ProcessState::Signaled => status.exit_code.is_none() && status.signal.is_some(),
        ProcessState::Unobservable => false,
    } && (!status.timed_out || status.state == ProcessState::Signaled);
    if !consistent {
        return Err("a status does not agree with itself");
    }
    Ok(ProcessOutput::Observed {
        process_id: process.clone(),
        state: status.state,
        exit_code: status.exit_code,
        signal: status.signal,
        timed_out: status.timed_out,
        stdout: StreamSnapshot {
            content: status.stdout.content,
            observed: status.stdout.observed,
            truncated: status.stdout.truncated,
        },
        stderr: StreamSnapshot {
            content: status.stderr.content,
            observed: status.stderr.observed,
            truncated: status.stderr.truncated,
        },
    })
}

/// What a status answers when the broker no longer holds the process.
fn unobservable(process: &ProcessId) -> ProcessOutput {
    let empty = || StreamSnapshot {
        content: Vec::new(),
        observed: 0,
        truncated: false,
    };
    ProcessOutput::Observed {
        process_id: process.clone(),
        state: ProcessState::Unobservable,
        exit_code: None,
        signal: None,
        timed_out: false,
        stdout: empty(),
        stderr: empty(),
    }
}

/// Classify the broker's answer. A launch or a kill is `FAILED` only when the
/// broker provably did nothing — it was told nothing, or it said it refused —
/// and `UNKNOWN` otherwise. A status has no effect: any trouble is a failure,
/// and a broker that no longer holds the process (restarted, or evicted it)
/// answers `UNOBSERVABLE`, which is an observation.
pub(super) fn classify(
    tool: CoreTool,
    process: &ProcessId,
    stream_limit: Option<u32>,
    result: Result<BrokerDelivery, BrokerError>,
) -> (Ending, Option<(BrokerFailure, bool)>) {
    match result {
        Ok(delivery) => match completed(tool, process, stream_limit, delivery) {
            Ok(output) => (Ending::Completed(Box::new(output)), None),
            Err(why) => {
                let detail = Some((BrokerFailure::Protocol(why), true));
                if has_effect(tool) {
                    (Ending::Unknown, detail)
                } else {
                    (
                        Ending::Failed(ToolFailureReasonV3::BrokerProtocolError),
                        detail,
                    )
                }
            }
        },
        Err(error) => {
            let detail = Some((error.failure, error.sent));
            let gone = matches!(
                error.failure,
                BrokerFailure::Refused(
                    BrokerRefusal::StaleGeneration | BrokerRefusal::UnknownProcess
                )
            );
            if tool == CoreTool::ProcessStatus && gone {
                (Ending::Completed(Box::new(unobservable(process))), detail)
            } else if has_effect(tool) && !error.provably_without_effect() {
                (Ending::Unknown, detail)
            } else {
                (Ending::Failed(failure_reason(error.failure)), detail)
            }
        }
    }
}

/// The stored class of a completed output, and its retained output bytes.
fn completion(output: &ProcessOutput) -> (&'static str, u64) {
    match output {
        ProcessOutput::Launched { .. } => ("LAUNCHED", 0),
        ProcessOutput::Observed { stdout, stderr, .. } => (
            "OBSERVED",
            u64::try_from(stdout.content.len().saturating_add(stderr.content.len()))
                .unwrap_or(u64::MAX),
        ),
        ProcessOutput::Killed { outcome, .. } => (outcome.as_str(), 0),
    }
}

/// End an open invocation: exactly one row, from `INTENT`.
fn end(
    work: &mut Work<'_>,
    invocation: &InvocationId,
    ending: &Ending,
) -> Result<(), AuthorityError> {
    let now = to_sql(work.now)?;
    let ended = match ending {
        Ending::Completed(output) => {
            let (class, bytes) = completion(output);
            work.db(work.tx.execute(
                "UPDATE process_invocation SET state = 'COMPLETED', completion = ?2, \
                 output_bytes = ?3, ended_ms = ?4 WHERE invocation_id = ?1 AND state = 'INTENT'",
                rusqlite::params![invocation.as_str(), class, to_sql(bytes)?, now],
            ))?
        }
        Ending::Failed(reason) => work.db(work.tx.execute(
            "UPDATE process_invocation SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation.as_str(), reason.as_str(), now],
        ))?,
        Ending::Unknown => work.db(work.tx.execute(
            "UPDATE process_invocation SET state = 'UNKNOWN', ended_ms = ?2 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation.as_str(), now],
        ))?,
    };
    if ended == 1 {
        Ok(())
    } else {
        Err(AuthorityError::Invariant(
            "an outcome names no open invocation",
        ))
    }
}

/// Move a process row to what an outcome proved. Never backwards (the
/// triggers are the second statement of that).
fn settle_process(
    work: &mut Work<'_>,
    tool: CoreTool,
    process: &ProcessId,
    ending: &Ending,
    generation: Option<&BrokerGeneration>,
) -> Result<(), AuthorityError> {
    let now = to_sql(work.now)?;
    let state = |s: ProcessState| match s {
        ProcessState::Running => "RUNNING",
        ProcessState::Exited => "EXITED",
        ProcessState::Signaled => "SIGNALED",
        ProcessState::Unobservable => "UNOBSERVABLE",
    };
    match (tool, ending) {
        (CoreTool::ProcessExec, Ending::Completed(output)) => {
            let ProcessOutput::Launched {
                state: s,
                exit_code,
                signal,
                ..
            } = output.as_ref()
            else {
                return Err(AuthorityError::Invariant(
                    "a launch completed as something else",
                ));
            };
            let generation =
                generation.ok_or(AuthorityError::Invariant("a launch without a generation"))?;
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = ?2, broker_generation = ?3, exit_code = ?4, \
                 signal = ?5, updated_ms = ?6 WHERE process_id = ?1 AND state = 'LAUNCHING'",
                rusqlite::params![
                    process.as_str(),
                    state(*s),
                    generation.as_str(),
                    exit_code.map(i64::from),
                    signal.map(i64::from),
                    now
                ],
            ))?;
        }
        (CoreTool::ProcessExec, Ending::Failed(_)) => {
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = 'FAILED', updated_ms = ?2 \
                 WHERE process_id = ?1 AND state = 'LAUNCHING'",
                rusqlite::params![process.as_str(), now],
            ))?;
        }
        (CoreTool::ProcessExec, Ending::Unknown) => {
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = 'UNKNOWN', updated_ms = ?2 \
                 WHERE process_id = ?1 AND state = 'LAUNCHING'",
                rusqlite::params![process.as_str(), now],
            ))?;
        }
        (CoreTool::ProcessStatus, Ending::Completed(output)) => {
            let ProcessOutput::Observed {
                state: s,
                exit_code,
                signal,
                timed_out,
                ..
            } = output.as_ref()
            else {
                return Err(AuthorityError::Invariant(
                    "a status completed as something else",
                ));
            };
            // Only a running process's row moves; an ended one is final.
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = ?2, exit_code = ?3, signal = ?4, \
                 timed_out = ?5, updated_ms = ?6 WHERE process_id = ?1 AND state = 'RUNNING'",
                rusqlite::params![
                    process.as_str(),
                    state(*s),
                    exit_code.map(i64::from),
                    signal.map(i64::from),
                    i64::from(*timed_out),
                    now
                ],
            ))?;
        }
        (CoreTool::ProcessKill, Ending::Failed(ToolFailureReasonV3::ProcessUnobservable)) => {
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = 'UNOBSERVABLE', updated_ms = ?2 \
                 WHERE process_id = ?1 AND state = 'RUNNING'",
                rusqlite::params![process.as_str(), now],
            ))?;
        }
        _ => {}
    }
    Ok(())
}

/// The fields that say what the broker did wrong.
fn broker_fields(failure: BrokerFailure, sent: bool) -> Fields {
    let fields = Fields::new()
        .text("broker_failure", failure.class())
        .flag("authorisation_sent", sent);
    match failure {
        BrokerFailure::Refused(why) => fields.text("broker_refusal", why.as_str()),
        BrokerFailure::Indeterminate(why) => fields.text("indeterminate", why.as_str()),
        BrokerFailure::Protocol(why) => fields.text("protocol", why),
        BrokerFailure::Unreachable(why) => fields.text("unreachable", why.as_str()),
        BrokerFailure::PeerRefused { observed_uid } => {
            fields.int("observed_uid", u64::from(observed_uid))
        }
        BrokerFailure::NotConfigured => fields,
    }
}

/// Step 4 failed: nothing was sent, nothing launched.
pub(super) fn record_handoff_failure(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    process: &ProcessId,
    (reason, detail): (ToolFailureReasonV3, &'static str),
) -> Result<ToolFailureReasonV3, AuthorityError> {
    let ending = Ending::Failed(reason);
    end(work, invocation, &ending)?;
    settle_process(work, CoreTool::ProcessExec, process, &ending, None)?;
    work.audit(
        AuditEvent::ToolFailed,
        Fields::new()
            .text("run_id", run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("tool", CoreTool::ProcessExec.as_str())
            .text("process_id", process.as_str())
            .text("failure", reason.as_str())
            .flag("effect_possible", false)
            .text("open_failure", detail),
    )?;
    Ok(reason)
}

/// Step 6: the outcome, the process row, and — for a status with output —
/// the taint, recorded before the runtime is answered.
pub(super) fn record_outcome(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    (tool, process): (CoreTool, &ProcessId),
    (ending, detail): (&Ending, Option<(BrokerFailure, bool)>),
    generation: Option<&BrokerGeneration>,
) -> Result<(), AuthorityError> {
    end(work, invocation, ending)?;
    settle_process(work, tool, process, ending, generation)?;
    let head = Fields::new()
        .text("run_id", run.as_str())
        .text("invocation_id", invocation.as_str())
        .text("tool", tool.as_str())
        .text("process_id", process.as_str());
    match ending {
        Ending::Completed(output) => {
            let mut fields = head;
            match output.as_ref() {
                ProcessOutput::Launched {
                    state,
                    exit_code,
                    signal,
                    ..
                } => {
                    fields.extend(
                        Fields::new()
                            .text("state", state.as_str())
                            .maybe_int("exit_code", exit_code.map(u64::from))
                            .maybe_int("signal", signal.map(u64::from))
                            .maybe_text(
                                "broker_generation",
                                generation.map(|g| g.as_str().to_owned()),
                            ),
                    );
                }
                ProcessOutput::Observed {
                    state,
                    exit_code,
                    signal,
                    timed_out,
                    stdout,
                    stderr,
                    ..
                } => {
                    // Counts, never content: output does not enter the audit
                    // record (ADR-0045 §13).
                    fields.extend(
                        Fields::new()
                            .text("state", state.as_str())
                            .maybe_int("exit_code", exit_code.map(u64::from))
                            .maybe_int("signal", signal.map(u64::from))
                            .flag("timed_out", *timed_out)
                            .int(
                                "stdout_bytes",
                                u64::try_from(stdout.content.len()).unwrap_or(u64::MAX),
                            )
                            .int("stdout_observed", stdout.observed)
                            .int(
                                "stderr_bytes",
                                u64::try_from(stderr.content.len()).unwrap_or(u64::MAX),
                            )
                            .int("stderr_observed", stderr.observed),
                    );
                    if !stdout.content.is_empty() || !stderr.content.is_empty() {
                        // A host process's output is content the operator's
                        // machine produced: LOCAL_UNVERIFIED, never lower.
                        // Raised before it can reach cognition.
                        let taint = query::raise_taint(
                            work,
                            run,
                            TaintLevel::LocalUnverified,
                            TaintCause::ToolResult,
                        )?;
                        fields.extend(Fields::new().text("taint", taint.as_str()));
                    }
                }
                ProcessOutput::Killed { outcome, .. } => {
                    fields.extend(Fields::new().text("kill_outcome", outcome.as_str()));
                }
            }
            if let Some((failure, sent)) = detail {
                fields.extend(broker_fields(failure, sent));
            }
            work.audit(AuditEvent::ToolCompleted, fields)
        }
        Ending::Failed(reason) => {
            let mut fields = head
                .text("failure", reason.as_str())
                .flag("effect_possible", false);
            if let Some((failure, sent)) = detail {
                fields.extend(broker_fields(failure, sent));
            }
            work.audit(AuditEvent::ToolFailed, fields)
        }
        Ending::Unknown => {
            let mut fields = head
                .text("retry_class", retry_class(tool).as_str())
                .text("cause", "broker");
            if let Some((failure, sent)) = detail {
                fields.extend(broker_fields(failure, sent));
            }
            work.audit(AuditEvent::ToolOutcomeUnknown, fields)
        }
    }
}

/// End every process invocation a previous incarnation left open. **Nothing
/// is performed**: an open launch or kill is `UNKNOWN` — the broker may have
/// acted — and a launch's process row with it; an open status is
/// `INTERRUPTED`. Never re-launched, never re-signalled. Runs in the start-up
/// transaction.
pub(super) fn reconcile_open(work: &mut Work<'_>) -> Result<(u64, u64), AuthorityError> {
    let open: Vec<(String, String, String, String, String, i64)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, run_id, tool, retry_class, process_id, incarnation \
             FROM process_invocation WHERE state = 'INTENT' ORDER BY intent_ms, invocation_id",
        ))?;
        let rows = work.db(statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        }))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    let mut interrupted = 0u64;
    let mut unknown = 0u64;
    for (invocation, run, tool, retry, process, incarnation) in &open {
        let effect = tool != CoreTool::ProcessStatus.as_str();
        let (state, event) = if effect {
            unknown = unknown.saturating_add(1);
            ("UNKNOWN", AuditEvent::ToolOutcomeUnknown)
        } else {
            interrupted = interrupted.saturating_add(1);
            ("INTERRUPTED", AuditEvent::ToolInterrupted)
        };
        let ended = work.db(work.tx.execute(
            "UPDATE process_invocation SET state = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation, state, to_sql(work.now)?],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant(
                "an open invocation could not be ended",
            ));
        }
        if tool == CoreTool::ProcessExec.as_str() {
            work.db(work.tx.execute(
                "UPDATE tool_process SET state = 'UNKNOWN', updated_ms = ?2 \
                 WHERE process_id = ?1 AND state = 'LAUNCHING'",
                rusqlite::params![process, to_sql(work.now)?],
            ))?;
        }
        let mut fields = Fields::new()
            .text("invocation_id", invocation.clone())
            .text("run_id", run.clone())
            .text("process_id", process.clone())
            .int(
                "intent_incarnation",
                u64::try_from(*incarnation).unwrap_or(0),
            );
        if effect {
            fields.extend(
                Fields::new()
                    .text("tool", tool.clone())
                    .text("retry_class", retry.clone())
                    .text("cause", "restart"),
            );
        }
        work.audit(event, fields)?;
    }
    Ok((interrupted, unknown))
}

// Real executables, resolved and hashed: the resolver exists on Linux only.
#[cfg(all(test, target_os = "linux"))]
mod tests;
