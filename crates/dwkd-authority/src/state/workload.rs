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
//!
//! # A workload's credential (M5d.3, ADR-0052 §7)
//!
//! A public launch that names a credential handle is decided twice, by both
//! gates each: `process.exec` on the image executable, and `secret.use:<handle>`
//! in the `SANDBOX` environment ([`SpawnGate`]). Either denial denies the
//! launch. Its use's intent (`super::secret_use::spawn`) is recorded in the
//! workload's own intent transaction and linked to it (`workload_secret`), so
//! they are durable, ended and reconciled together.

use dwk_proto::brokerp::sandbox::{AssuranceLevel, ContainerRef, ImageId, Verdict};
use dwk_proto::brokerp::workload::{
    ImagePath, WorkloadEnding, WorkloadLaunch, WorkloadRunDone, WorkloadSeconds, WorkloadSpec,
};
use dwk_proto::brokerp::{ProcessArgs, StreamLimit};
use dwk_proto::limits::{MAX_PROCESS_ARG_BYTES, MAX_PROCESS_ARGV_BYTES};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::{ContentDigest, ProcessArg};
use rusqlite::OptionalExtension as _;

use crate::capability::{
    Action, ArgvAllowlist, ArgvToken, Capability, ConstraintSet, Namespace, Scope, Verb,
};
use crate::policy::{ArgvSafety, CanonicalAction, Effect, Environment, Obligation, TaintLevel};
use crate::resource::ExecutableIdentity;
use crate::resource::exec::argv::{self, ArgvClass};
use crate::resource::exec::hygiene::{self, Hygiene};
use crate::sandbox::{SandboxConfig, WorkloadBudget};
use crate::secret::metadata::InjectionMode;

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
use super::secret_use::spawn::{self, SpawnAsked, SpawnAuthorised, SpawnPrepared};

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
    pub(super) stream_limit: StreamLimit,
    pub(super) wall_clock: WorkloadSeconds,
    pub(super) key: String,
    /// The credential handle a public launch named (M5d.3): part of what its
    /// key is bound to. The in-process API names none.
    pub(super) credential: Option<String>,
}

/// The longest idempotency key, in bytes.
const MAX_KEY_BYTES: usize = 128;

/// What a run's grants were resolved against when it was admitted with an
/// execution environment configured (M5d.2, OD-9): the image, by content
/// digest, and the digest of the operator's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageBinding {
    pub(super) image: ImageId,
    pub(super) manifest_sha256: String,
}

impl ImageBinding {
    /// The binding `config` gives a run admitted now.
    pub(super) fn of(config: &SandboxConfig) -> Self {
        let executables = config.executables();
        let mut hash = DomainHash::new(digest::IMAGE_MANIFEST)
            .text(config.image().as_str())
            .int(u64::try_from(executables.len()).unwrap_or(u64::MAX));
        for (path, sha256) in executables {
            hash = hash.text(path.as_str()).text(sha256.as_str());
        }
        Self {
            image: config.image().clone(),
            manifest_sha256: hash.finish().to_hex(),
        }
    }
}

/// Why a declaration names no executable of the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManifestMiss {
    /// The manifest does not name the path.
    NotInImage,
    /// The declaration pins a digest the manifest does not.
    DigestMismatch,
}

/// What a concrete process declaration means for a run admitted with an
/// execution environment configured (OD-9): the executable the manifest
/// names at `path` in the image, with the SHA-256 it pins -- never the host
/// file at that path. A declaration that pins a digest means it only if the
/// manifest pins the same one.
///
/// # Errors
///
/// [`ManifestMiss`]: the declaration covers nothing.
pub(super) fn manifest_identity(
    config: &SandboxConfig,
    path: &str,
    pinned: Option<&str>,
) -> Result<ExecutableIdentity, ManifestMiss> {
    let (executable, sha256) = config.executable(path).ok_or(ManifestMiss::NotInImage)?;
    if pinned.is_some_and(|digest| digest != sha256.as_str()) {
        return Err(ManifestMiss::DigestMismatch);
    }
    crate::resource::exec::image_executable_identity(executable.as_str(), sha256.as_str())
        .map_err(|_| ManifestMiss::NotInImage)
}

/// Bind `run` to the image its grants were resolved against (OD-9). Once,
/// at admission.
pub(super) fn bind_run_image(
    work: &Work<'_>,
    run: &RunId,
    binding: &ImageBinding,
) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "INSERT INTO run_image (run_id, image, manifest_sha256, recorded_ms) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            run.as_str(),
            binding.image.as_str(),
            binding.manifest_sha256,
            to_sql(work.now)?
        ],
    ))?;
    Ok(())
}

/// The image `run` is bound to, if it was admitted with one.
fn run_image(work: &Work<'_>, run: &RunId) -> Result<Option<ImageBinding>, AuthorityError> {
    let row: Option<(String, String)> = work.db(work
        .tx
        .query_row(
            "SELECT image, manifest_sha256 FROM run_image WHERE run_id = ?1",
            [run.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    row.map(|(image, manifest_sha256)| {
        Ok(ImageBinding {
            image: ImageId::new(image).ok_or(AuthorityError::Invariant(
                "a stored image binding is malformed",
            ))?,
            manifest_sha256,
        })
    })
    .transpose()
}

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
    // Within the protocol's bounds as the broker will be told them.
    ProcessArgs::new(wire).ok_or("ARGV_TOO_LARGE")?;
    let stream_limit = StreamLimit::new(request.stream_limit).ok_or("STREAM_LIMIT_INVALID")?;
    let wall_clock =
        WorkloadSeconds::new(request.wall_clock_seconds).ok_or("WALL_CLOCK_INVALID")?;
    Ok(Checked {
        executable: executable.clone(),
        sha256: sha256.clone(),
        identity,
        args: request.args.clone(),
        stream_limit,
        wall_clock,
        key: key.clone(),
        credential: None,
    })
}

/// The arguments' digest: their count, then each, length-prefixed — the
/// process tools' domain, so a workload's and a launch's arguments digest
/// alike.
pub(super) fn argv_digest(args: &[String]) -> Sha256Hash {
    let mut hash =
        DomainHash::new(digest::PROCESS_ARGV).int(u64::try_from(args.len()).unwrap_or(u64::MAX));
    for arg in args {
        hash = hash.text(arg);
    }
    hash.finish()
}

/// What a key is bound to: the run, the executable, the arguments, the
/// bounds -- and the credential handle, when one is named (a request naming
/// none digests as it did before M5d.3).
fn request_digest(run: &RunId, checked: &Checked) -> Sha256Hash {
    let hash = DomainHash::new(digest::WORKLOAD_REQUEST)
        .text(run.as_str())
        .text(checked.executable.as_str())
        .text(checked.sha256.as_str())
        .bytes(argv_digest(&checked.args).as_bytes())
        .int(u64::from(checked.stream_limit.get()))
        .int(u64::from(checked.wall_clock.get()));
    match &checked.credential {
        Some(handle) => hash.text("credential").text(handle).finish(),
        None => hash.finish(),
    }
}

/// A launch's spawn injection, decided (M5d.3): `secret.use:<handle>` through
/// both gates for a `SANDBOX` action, keeping only `audit_level`, and the mode
/// the kernel chose from the operator's metadata.
#[derive(Debug, Clone)]
pub(super) struct SpawnGate {
    pub(super) handle: String,
    pub(super) mode: InjectionMode,
    pub(super) record: DecisionRecord,
    pub(super) obligations_enforced: bool,
}

impl SpawnGate {
    /// Both gates, and every obligation kept.
    pub(super) fn permits(&self) -> bool {
        self.record.capability_satisfied()
            && self.record.policy_satisfied()
            && self.obligations_enforced
    }

    /// Why it was decided as it was, in the process tools' order.
    pub(super) fn reason(&self) -> &'static str {
        decision_reason(&self.record, self.obligations_enforced, self.permits())
    }
}

/// Why `record` was decided as it was, in the process tools' order: an
/// unevaluable input, policy, the capability, the obligations, an approval.
fn decision_reason(record: &DecisionRecord, enforced: bool, permits: bool) -> &'static str {
    let policy = record.policy();
    if permits {
        return "ALLOWED_BY_RULE";
    }
    if policy.unevaluable().is_some() {
        return "UNRESOLVED_POLICY_INPUT";
    }
    match policy.effect() {
        Effect::Deny if policy.rule_id().is_default() => "DEFAULT_DENY",
        Effect::Deny => "DENIED_BY_RULE",
        _ if !record.capability_satisfied() => "NO_CAPABILITY",
        Effect::Allow if !enforced => "OBLIGATION_UNENFORCEABLE",
        // REQUIRE_APPROVAL: no approval exists before M6.
        _ => "APPROVAL_REQUIRED",
    }
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
    /// How the broker starts it: through the trusted launcher when
    /// `workspace_exec_hygiene` is kept.
    pub(super) launch: WorkloadLaunch,
    /// The arguments the kept obligation puts before the invocation's own.
    pub(super) prefix: &'static [&'static str],
    /// The spawn injection, when the launch names a credential (M5d.3).
    pub(super) injection: Option<SpawnGate>,
}

impl WorkloadPlan {
    /// The arguments the broker is told: the obligation's, then the
    /// invocation's own.
    pub(super) fn executed(&self, checked: &Checked) -> Vec<String> {
        self.prefix
            .iter()
            .map(|a| (*a).to_owned())
            .chain(checked.args.iter().cloned())
            .collect()
    }
}

impl WorkloadPlan {
    /// The launch's own action: both gates, and every obligation enforced.
    pub(super) fn workload_permits(&self) -> bool {
        self.record.capability_satisfied()
            && self.record.policy_satisfied()
            && self.obligations_enforced
    }

    /// The whole plan: the launch's action and, when it names a credential,
    /// its spawn injection. The only condition under which anything runs.
    pub(super) fn permits(&self) -> bool {
        self.workload_permits() && self.injection.as_ref().is_none_or(SpawnGate::permits)
    }

    /// Why the launch's own action was decided as it was, in the process
    /// tools' order: an unevaluable input, policy, the capability, the
    /// obligations, an approval.
    pub(super) fn reason(&self) -> &'static str {
        decision_reason(
            &self.record,
            self.obligations_enforced,
            self.workload_permits(),
        )
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

/// What keeping a plan's obligations needs of its workload.
struct Kept {
    enforced: bool,
    stream_limit: u32,
    launch: WorkloadLaunch,
    prefix: &'static [&'static str],
}

/// Whether the authority keeps every obligation, for a workload in an
/// environment, and what keeping them needs (ADR-0052 §§5a, 10):
///
/// | obligation | a workload |
/// |---|---|
/// | `max_output_bytes=N` | each stream keeps its first `N / 2` bytes (`N >= 2`) |
/// | `audit_level=full` | the intent record carries the full argv |
/// | `workspace_exec_hygiene` | kept by the trusted launcher and the tool's arguments, unless the invocation's own arguments undo it or the tool has no real-tool evidence (`resource::exec::hygiene`): then denied |
/// | anything else | **not enforceable**: denied |
fn obligations(record: &DecisionRecord, checked: &Checked) -> Kept {
    let mut kept = Kept {
        enforced: true,
        stream_limit: checked.stream_limit.get(),
        launch: WorkloadLaunch::Direct,
        prefix: &[],
    };
    let (mut stream_limit, mut enforced) = (kept.stream_limit, true);
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
            Obligation::WorkspaceExecHygiene => {
                let args: Vec<&str> = checked.args.iter().map(String::as_str).collect();
                match hygiene::hygiene(&checked.identity, &args) {
                    Hygiene::Kept { prefix } => {
                        kept.launch = WorkloadLaunch::Hygiene;
                        kept.prefix = prefix;
                        true
                    }
                    Hygiene::Unenforceable(_) => false,
                }
            }
            _ => false,
        };
        enforced &= ok;
    }
    kept.enforced = enforced;
    kept.stream_limit = stream_limit;
    kept
}

/// Both gates for a **sandbox** action -- and, for a launch that names a
/// credential, both gates again for `secret.use:<handle>` in the `SANDBOX`
/// environment. Pure: reads what the caller loaded.
fn decide_plan(
    checked: &Checked,
    admission: &super::admission::Admission,
    (context, active): (&crate::policy::PolicyContext, &ActiveAuthority),
    secret: Option<&SpawnPrepared>,
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
    let kept = obligations(&record, checked);
    let injection = secret
        .map(|prepared| -> Result<SpawnGate, AuthorityError> {
            let required = super::secret_use::required(&prepared.handle)?;
            let record = query::decide(
                &CanonicalAction::new(required, Environment::Sandbox),
                admission,
                context,
                active,
            );
            Ok(SpawnGate {
                handle: prepared.handle.as_str().to_owned(),
                mode: prepared.mode,
                obligations_enforced: super::secret_use::obligations_enforced(&record),
                record,
            })
        })
        .transpose()?;
    Ok(WorkloadPlan {
        action,
        record,
        class,
        obligations_enforced: kept.enforced,
        stream_limit: kept.stream_limit,
        launch: kept.launch,
        prefix: kept.prefix,
        injection,
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
            u64::try_from(plan.executed(checked).len()).unwrap_or(u64::MAX),
        )
        .text("argv_sha256", argv_digest(&plan.executed(checked)).to_hex())
        // The full canonical command (SANDBOX.md §4): argv is an array,
        // recorded as one -- what ran, the obligation's arguments first.
        // Output is never recorded.
        .list(
            "argv",
            std::iter::once(checked.executable.as_str().to_owned())
                .chain(plan.executed(checked))
                .map(Field::Text)
                .collect(),
        )
        .text("launch", plan.launch.as_str())
        .list(
            "hygiene_args",
            plan.prefix
                .iter()
                .map(|a| Field::Text((*a).to_owned()))
                .collect(),
        )
        .int("stream_limit", u64::from(plan.stream_limit))
        .int("wall_clock_s", u64::from(checked.wall_clock.get()))
        .text("reason", plan.reason());
    fields.extend(class);
    // The spawn injection's own decision (M5d.3): the handle, the mode, both
    // gates. Never the value, its length, or the variable.
    if let Some(gate) = &plan.injection {
        let policy = gate.record.policy();
        fields.extend(
            Fields::new()
                .text("credential_handle", gate.handle.as_str())
                .text("injection_mode", gate.mode.as_str())
                .text(
                    "injection_required_capability",
                    gate.record.required().to_canonical_string(),
                )
                .flag(
                    "injection_capability_satisfied",
                    gate.record.capability_satisfied(),
                )
                .maybe_text(
                    "injection_covering_cap_id",
                    gate.record.covering_grant().map(|c| c.as_str().to_owned()),
                )
                .text("injection_policy_effect", policy.effect().as_str())
                .flag("injection_policy_satisfied", gate.record.policy_satisfied())
                .text("injection_rule_id", policy.rule_id().as_str())
                .text("injection_reason", gate.reason())
                .text(
                    "injection_effect",
                    if gate.permits() { "ALLOW" } else { "DENY" },
                ),
        );
    }
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

/// One workload's record, by its invocation: static text, the id bound.
const RECORD_BY_INVOCATION: &str = "SELECT invocation_id, run_id, environment_id, state, \
                                    failure, ending, exit_code, signal, residue FROM workload \
                                    WHERE invocation_id = ?1";

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
        .query_row(RECORD_BY_INVOCATION, [invocation.as_str()], read_row)
        .optional())?;
    row.map(record_of).transpose()
}

/// The environment a workload is decided in: the run's live one, `READY`.
#[derive(Debug, Clone)]
pub(super) struct ReadyEnvironment {
    pub(super) environment: EnvironmentId,
    pub(super) container: ContainerRef,
    /// The image it was prepared from.
    pub(super) image: String,
    /// Its measured, effective level.
    pub(super) level: AssuranceLevel,
}

/// What starting a workload decided.
#[derive(Debug)]
pub(super) enum Begun {
    /// Refused before anything was recorded; audited.
    Refused(&'static str),
    /// A gate denied it; audited. The plan says how.
    Denied(Box<Decided>),
    /// Its key is bound to a workload already: that one's record.
    Replayed(Box<WorkloadRecord>),
    /// Permitted, and its run has no live environment: the public route
    /// prepares one and asks again. Nothing was recorded.
    NeedsEnvironment,
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
    /// The plan both gates allowed: what the answer states.
    pub(super) plan: WorkloadPlan,
    /// Its credential's use, when it names one (M5d.3): durable with it.
    pub(super) secret: Option<SpawnAuthorised>,
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
    type Row = (String, String, Option<String>, Option<String>, String);
    let row: Option<Row> = work.db(work
        .tx
        .query_row(
            "SELECT environment_id, state, container, effective, image FROM environment \
             WHERE run_id = ?1 AND state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')",
            [run.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional())?;
    let Some((environment, state, container, effective, image)) = row else {
        return Ok(Err("NO_ENVIRONMENT"));
    };
    let level = match readiness(&state, effective.as_deref())? {
        Ok(level) => level,
        Err(reason) => return Ok(Err(reason)),
    };
    let malformed = AuthorityError::Invariant("a ready environment is malformed");
    Ok(Ok(ReadyEnvironment {
        environment: EnvironmentId::parse(&environment).ok_or_else(|| malformed.clone())?,
        container: container.and_then(ContainerRef::new).ok_or(malformed)?,
        image,
        level,
    }))
}

/// Whether a live environment in `state`, measured at `effective`, may run
/// a workload — `READY`, at a level [`workload_may_run_at`] accepts — or
/// why not. A `READY` environment without a known level is malformed.
fn readiness(
    state: &str,
    effective: Option<&str>,
) -> Result<Result<AssuranceLevel, &'static str>, AuthorityError> {
    if state != "READY" {
        return Ok(Err("ENVIRONMENT_NOT_READY"));
    }
    let level = effective
        .and_then(|text| {
            AssuranceLevel::ALL
                .iter()
                .copied()
                .find(|level| level.as_str() == text)
        })
        .ok_or(AuthorityError::Invariant(
            "a ready environment is malformed",
        ))?;
    if !workload_may_run_at(level) {
        return Ok(Err("ASSURANCE_INSUFFICIENT"));
    }
    Ok(Ok(level))
}

/// Whether a workload may run in an environment measured at `level`: the
/// container's isolation, measured, and never less.
const fn workload_may_run_at(level: AssuranceLevel) -> bool {
    level.rank() >= AssuranceLevel::ContainerIsolation.rank()
}

/// Where a workload's idempotency key is bound.
#[derive(Debug, Clone, Copy)]
pub(super) enum Binding<'a> {
    /// The in-process API's (M5d.1): once per run, a repeat answered from
    /// the record.
    Run,
    /// The public route's (M5d.2): the session's one namespace, shared with
    /// every tool -- the caller's subject, the session, the envelope's key.
    Session {
        /// The caller's subject, as stored.
        subject: &'a str,
        /// The session.
        session: &'a SessionId,
        /// The tool messages' version it was asked at: 5, or 6 (M5d.3).
        version: u16,
    },
}

/// The workload as the broker is told it: the checked request, with the
/// per-stream bound its plan left.
///
/// # Errors
///
/// [`AuthorityError::Invariant`] for a decided bound out of range: a bug.
pub(super) fn spec(checked: &Checked, intent: &Intent) -> Result<WorkloadSpec, AuthorityError> {
    let stream_limit = StreamLimit::new(intent.stream_limit).ok_or(AuthorityError::Invariant(
        "a decided stream bound is out of range",
    ))?;
    let mut args = Vec::with_capacity(intent.plan.prefix.len() + checked.args.len());
    for arg in intent.plan.executed(checked) {
        args.push(ProcessArg::new(arg).ok_or(AuthorityError::Invariant(
            "a checked argument is not an argument",
        ))?);
    }
    Ok(WorkloadSpec {
        executable: checked.executable.clone(),
        executable_sha256: checked.sha256.clone(),
        args: ProcessArgs::new(args)
            .ok_or(AuthorityError::Invariant("a decided argv is out of bounds"))?,
        stream_limit,
        wall_clock: checked.wall_clock,
        launch: intent.plan.launch,
    })
}

/// What both gates decided for a workload, in the environment the authority
/// chose for it.
#[derive(Debug, Clone)]
pub(super) struct Decided {
    pub(super) binding: RootBinding,
    /// The run's `READY` environment -- absent only from a denial, or from a
    /// preview of a run whose environment the public route would prepare.
    pub(super) environment: Option<ReadyEnvironment>,
    pub(super) plan: WorkloadPlan,
}

/// The most environments one run may have had, live or ended: the public
/// route prepares one when a run has none (M5d.2), and a run whose
/// environments keep failing or being destroyed runs no more of them.
pub(super) const MAX_ENVIRONMENTS_PER_RUN: i64 = 8;

/// At most this many environments are live at once, across every run
/// (M5d.2, ADR-0052 §2a): the broker supervises at most as many workloads,
/// one per environment. A launch that would need another is refused.
pub(super) const MAX_LIVE_ENVIRONMENTS: i64 = 16;

/// How many environments are live -- preparing, ready, being destroyed or
/// of an uncertain end -- across every run.
pub(super) fn live_environments(work: &Work<'_>) -> Result<i64, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT count(*) FROM environment \
         WHERE state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')",
        [],
        |row| row.get(0),
    ))
}

/// The oldest environment that can never run a workload again, if one is
/// live: `READY` in a run that is no longer `ACTIVE`, or `UNKNOWN` or
/// `DESTROYING` in any run -- never one a workload is `LAUNCHING` in. Its
/// destruction is its only end; until M5d.6 a run's release does not
/// perform it, so the authority does before it prepares another.
pub(super) fn reclaimable(work: &Work<'_>) -> Result<Option<EnvironmentId>, AuthorityError> {
    let found: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT e.environment_id FROM environment e JOIN run r ON r.run_id = e.run_id \
             WHERE (e.state IN ('UNKNOWN', 'DESTROYING') \
                    OR (e.state = 'READY' AND r.state <> 'ACTIVE')) \
             AND NOT EXISTS (SELECT 1 FROM workload w \
                             WHERE w.environment_id = e.environment_id AND w.state = 'LAUNCHING') \
             ORDER BY e.intent_ms, e.environment_id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional())?;
    found
        .map(|id| {
            EnvironmentId::parse(&id).ok_or(AuthorityError::Invariant(
                "a stored environment id is malformed",
            ))
        })
        .transpose()
}

/// What the public route may do when a permitted workload's run has no live
/// environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Missing {
    /// Refuse it (`NO_ENVIRONMENT`): the in-process API, and a preview.
    Refuse,
    /// Say so ([`Begun::NeedsEnvironment`]): the public route prepares one,
    /// within [`MAX_ENVIRONMENTS_PER_RUN`], and asks again.
    Prepare,
}

/// The decision a workload's invocation and its preview share: **both gates
/// first**, for a sandbox action -- a denial needs, prepares and reveals no
/// environment -- then the run's `READY` environment at a level a workload
/// needs, of the image the run was admitted against (OD-9), idle
/// (`busy_matters`), and within the budget. Nothing is recorded but what the
/// caller audits.
fn decide(
    work: &Work<'_>,
    run: &RunId,
    (checked, secret): (&Checked, Option<&SpawnPrepared>),
    (budget, active, image): (WorkloadBudget, &ActiveAuthority, &ImageBinding),
    (binding, busy_matters): (RootBinding, bool),
) -> Result<Result<Decided, &'static str>, AuthorityError> {
    let admission = super::admission::load(work, run.as_str())?;
    let context = query::policy_context(work, run.as_str(), active)?;
    let plan = decide_plan(checked, &admission, (&context, active), secret)?;
    let found = ready_environment(work, run)?;
    if !plan.permits() {
        return Ok(Ok(Decided {
            binding,
            environment: found.ok(),
            plan,
        }));
    }
    let environment = match found {
        Ok(environment) => environment,
        Err(reason) => return Ok(Err(reason)),
    };
    // OD-9: a run whose grants were resolved against an image runs only in
    // an environment of that image, under that manifest.
    if let Some(bound) = run_image(work, run)?
        && (bound != *image || bound.image.as_str() != environment.image)
    {
        return Ok(Err("IMAGE_CHANGED"));
    }
    if busy_matters {
        let busy: Option<i64> = work.db(work
            .tx
            .query_row(
                "SELECT 1 FROM workload WHERE environment_id = ?1 AND state = 'LAUNCHING'",
                [environment.environment.as_str()],
                |row| row.get(0),
            )
            .optional())?;
        if busy.is_some() {
            return Ok(Err("ENVIRONMENT_BUSY"));
        }
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
        return Ok(Err("BUDGET_EXHAUSTED"));
    }
    Ok(Ok(Decided {
        binding,
        environment: Some(environment),
        plan,
    }))
}

/// How many environments `run` has had, live or ended.
fn environments(work: &Work<'_>, run: &RunId) -> Result<i64, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT count(*) FROM environment WHERE run_id = ?1",
        [run.as_str()],
        |row| row.get(0),
    ))
}

/// Who asked, for the audit: the public route's caller, or nothing more
/// than the run for the in-process API.
fn caller_fields(binding_key: &Binding<'_>) -> Fields {
    match binding_key {
        Binding::Run => Fields::new(),
        Binding::Session {
            subject,
            session,
            version,
        } => Fields::new()
            .text("subject", *subject)
            .text("session_id", session.as_str())
            .int("protocol_version", u64::from(*version)),
    }
}

/// What a workload's preview decided: refused, or the plan an invocation
/// would decide on. Nothing is recorded but the audit.
#[derive(Debug)]
pub(super) enum Previewed {
    /// Refused before any gate; audited.
    Refused(&'static str),
    /// The plan.
    Decided(Box<Decided>),
}

/// A workload's preview (M5d.2): every check an invocation makes but the
/// key and whether the environment is idle, and both gates. Records the plan
/// it decided on, and nothing else.
pub(super) fn preview(
    work: &mut Work<'_>,
    run: &RunId,
    (checked, secret): (&Checked, Option<&SpawnPrepared>),
    (budget, active, image): (WorkloadBudget, &ActiveAuthority, &ImageBinding),
    binding_key: &Binding<'_>,
) -> Result<Previewed, AuthorityError> {
    let executable = checked.executable.as_str();
    let binding = match resolution::run_root(work, run.as_str())? {
        Ok(binding) => binding,
        Err(refused) => {
            refuse(work, run, executable, resolution_class(&refused))?;
            return Ok(Previewed::Refused(resolution_class(&refused)));
        }
    };
    let decided = match decide(
        work,
        run,
        (checked, secret),
        (budget, active, image),
        (binding.clone(), false),
    )? {
        Ok(decided) => decided,
        // Nothing to run in yet: the plan an invocation would decide on, in
        // the environment it would prepare -- a preview prepares nothing.
        Err("NO_ENVIRONMENT") => {
            let admission = super::admission::load(work, run.as_str())?;
            let context = query::policy_context(work, run.as_str(), active)?;
            Decided {
                binding,
                environment: None,
                plan: decide_plan(checked, &admission, (&context, active), secret)?,
            }
        }
        Err(reason) => {
            refuse(work, run, executable, reason)?;
            return Ok(Previewed::Refused(reason));
        }
    };
    let mut fields = Fields::new()
        .text("operation", "CANONICAL_PREVIEW")
        .text("tool", "process.exec")
        .text("run_id", run.as_str())
        .maybe_text(
            "environment_id",
            decided
                .environment
                .as_ref()
                .map(|e| e.environment.as_str().to_owned()),
        );
    fields.extend(caller_fields(binding_key));
    fields.extend(plan_fields(active, checked, &decided.plan));
    work.audit(AuditEvent::ToolPreviewed, fields)?;
    Ok(Previewed::Decided(Box::new(decided)))
}

/// Step 2: decide the workload -- and its credential's use, when it names
/// one -- and record its intent.
pub(super) fn begin(
    work: &mut Work<'_>,
    run: &RunId,
    (checked, secret): (&Checked, Option<(&SpawnAsked<'_>, &SpawnPrepared)>),
    (budget, active, image): (WorkloadBudget, &ActiveAuthority, &ImageBinding),
    (binding_key, missing): (&Binding<'_>, Missing),
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
    let decided = match decide(
        work,
        run,
        (checked, secret.map(|(_, prepared)| prepared)),
        (budget, active, image),
        (binding, true),
    )? {
        Ok(decided) => decided,
        // Permitted, and nothing to run in: the public route prepares the
        // run's environment -- within its bound -- and asks again.
        Err("NO_ENVIRONMENT") if missing == Missing::Prepare => {
            if environments(work, run)? >= MAX_ENVIRONMENTS_PER_RUN {
                return refuse(work, run, executable, "ENVIRONMENT_BUDGET_EXHAUSTED");
            }
            return Ok(Begun::NeedsEnvironment);
        }
        Err(reason) => return refuse(work, run, executable, reason),
    };
    let Decided {
        binding,
        environment,
        plan,
    } = decided;
    let mut fields = Fields::new().text("run_id", run.as_str()).maybe_text(
        "environment_id",
        environment
            .as_ref()
            .map(|e| e.environment.as_str().to_owned()),
    );
    fields.extend(caller_fields(binding_key));
    fields.extend(plan_fields(active, checked, &plan));
    if !plan.permits() {
        // A denied use is the secret side's to record too, as an egress one is.
        if let (Some((asked, _)), Some(gate)) = (secret, &plan.injection) {
            spawn::refused_by_gates(work, asked, active, (&gate.record, gate.mode))?;
        }
        work.audit(AuditEvent::WorkloadDenied, fields)?;
        return Ok(Begun::Denied(Box::new(Decided {
            binding,
            environment,
            plan,
        })));
    }
    let Some(environment) = environment else {
        return Err(AuthorityError::Invariant(
            "a permitted workload was decided without its environment",
        ));
    };
    let invocation = record_intent(
        work,
        (run, checked, &digest),
        (&environment, &plan),
        binding_key,
    )?;
    fields.extend(
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("idempotency_key", checked.key.as_str())
            .text("request_digest", digest.to_hex())
            .text("container", environment.container.as_str()),
    );
    work.audit(AuditEvent::WorkloadIntentRecorded, fields)?;
    let secret = secret_intent(work, secret, (active, &plan), &invocation)?;
    Ok(Begun::Intent(Box::new(Intent {
        invocation,
        stream_limit: plan.stream_limit,
        environment,
        binding,
        plan,
        secret,
    })))
}

/// A workload's credential's intent (M5d.3), in the workload's own
/// transaction, linked to it.
fn secret_intent(
    work: &mut Work<'_>,
    secret: Option<(&SpawnAsked<'_>, &SpawnPrepared)>,
    (active, plan): (&ActiveAuthority, &WorkloadPlan),
    invocation: &InvocationId,
) -> Result<Option<SpawnAuthorised>, AuthorityError> {
    match (secret, &plan.injection) {
        (Some((asked, prepared)), Some(gate)) => Ok(Some(spawn::record_intent(
            work,
            (asked, prepared.clone()),
            (active, &gate.record),
            invocation,
        )?)),
        (None, None) => Ok(None),
        _ => Err(AuthorityError::Invariant(
            "a credential was prepared without its decision, or decided without preparing",
        )),
    }
}

/// The intent's rows: the workload, `LAUNCHING`, and -- for the public
/// route -- its key in the namespace every tool shares, in the same
/// transaction, so a crash leaves both or neither.
fn record_intent(
    work: &mut Work<'_>,
    (run, checked, digest): (&RunId, &Checked, &Sha256Hash),
    (environment, plan): (&ReadyEnvironment, &WorkloadPlan),
    binding_key: &Binding<'_>,
) -> Result<InvocationId, AuthorityError> {
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
            i64::try_from(plan.executed(checked).len()).unwrap_or(i64::MAX),
            argv_digest(&plan.executed(checked)).to_hex(),
            i64::from(plan.stream_limit),
            i64::from(checked.wall_clock.get()),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    // The public route's key, in the namespace every tool shares: bound with
    // the intent, in the same transaction, so a crash leaves both or neither.
    if let Binding::Session {
        subject, session, ..
    } = binding_key
    {
        work.db(work.tx.execute(
            "INSERT INTO workload_idempotency (subject, session_id, idempotency_key, \
             request_digest, invocation_id, recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                subject,
                session.as_str(),
                checked.key,
                digest.to_hex(),
                invocation.as_str(),
                to_sql(work.now)?
            ],
        ))?;
    }
    Ok(invocation)
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

/// Why a workload's ending takes its environment down, if it does: a
/// completion whose residue `reap` did not prove clean, every uncertain
/// ending, and a refusal that found the environment not what was recorded.
/// Only a clean completion, or a refusal of something else, keeps it.
fn destroy_reason(ending: &Ending) -> Option<&'static str> {
    match ending {
        Ending::Completed(done) => (done.residue != Verdict::Pass).then_some("WORKLOAD_RESIDUE"),
        Ending::Unknown { .. } => Some("WORKLOAD_UNKNOWN"),
        Ending::Failed { reason } => environment_drifted(reason).then_some("DRIFTED"),
    }
}

/// Whether a refusal says the environment is not what was recorded: it is
/// then destroyed, as a drifted measurement is. Since M5d.4 that includes a
/// workspace no longer the one it was measured with -- replaced, or no
/// longer the contract's on the authority's side -- and one the broker,
/// reading it again before the workload, found changed (`NOT_CLEAN`).
const fn environment_drifted(reason: &str) -> bool {
    matches!(
        reason.as_bytes(),
        b"ENVIRONMENT_NOT_CLEAN"
            | b"ENVIRONMENT_NOT_FOUND"
            | b"FOREIGN_ENVIRONMENT"
            | b"WORKSPACE_CHANGED"
            | b"WORKSPACE_OWNER"
            | b"WORKSPACE_GROUP"
            | b"WORKSPACE_MODE"
            | b"WORKSPACE_GROUP_MEMBERSHIP"
            | b"WORKSPACE_UNBOUNDED"
            | b"WORKSPACE_QUOTA_MISMATCH"
            | b"WORKSPACE_FILESYSTEM_SHARED"
            | b"WORKSPACE_UNOBSERVABLE"
            | b"WORKSPACE_UNVERIFIED"
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
            (destroy_reason(ending), WorkloadState::Completed)
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
            (destroy_reason(ending), WorkloadState::Unknown)
        }
        Ending::Failed { reason } => {
            work.db(work.tx.execute(
                "UPDATE workload SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
                 WHERE invocation_id = ?1",
                rusqlite::params![invocation, reason, now],
            ))?;
            fields = fields.text("reason", *reason);
            (destroy_reason(ending), WorkloadState::Failed)
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
        // A credential-bearing workload's: how many whole occurrences of its
        // value the broker replaced as it drained the output. A count only.
        .maybe_int(
            "broker_redactions",
            done.redactions.map(|count| u64::from(count.get())),
        )
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
    use super::{
        Ending, WorkloadRequest, WorkloadState, check, destroy_reason, readiness,
        workload_may_run_at,
    };
    use crate::sandbox::{SandboxConfig, WorkloadBudget, WorkspaceSetting};
    use dwk_proto::brokerp::sandbox::{AssuranceLevel, Milliseconds, NetworkTopology, Verdict};
    use dwk_proto::brokerp::workload::{ProcessCount, WorkloadEnding, WorkloadRunDone};

    fn config() -> SandboxConfig {
        let Ok(config) = SandboxConfig::new(
            "/usr/bin/docker",
            "/var/run/docker.sock",
            &format!("sha256:{}", "a".repeat(64)),
            &"b".repeat(64),
            NetworkTopology::NoNetwork,
            WorkspaceSetting::UnverifiedEvidence,
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
    fn a_workload_runs_only_at_container_isolation_or_above() {
        for level in AssuranceLevel::ALL {
            assert_eq!(
                workload_may_run_at(*level),
                matches!(
                    level,
                    AssuranceLevel::ContainerIsolation | AssuranceLevel::VmIsolation
                ),
                "{level:?}"
            );
        }
    }

    #[test]
    fn only_a_ready_environment_at_container_isolation_runs_a_workload() {
        let container = Some("CONTAINER_ISOLATION");
        assert_eq!(
            readiness("READY", container).ok(),
            Some(Ok(AssuranceLevel::ContainerIsolation))
        );
        assert_eq!(
            readiness("READY", Some("VM_ISOLATION")).ok(),
            Some(Ok(AssuranceLevel::VmIsolation))
        );
        // Every other live state, whatever it was measured at.
        for state in ["PREPARING", "DESTROYING", "UNKNOWN"] {
            for effective in [container, None] {
                assert_eq!(
                    readiness(state, effective).ok(),
                    Some(Err("ENVIRONMENT_NOT_READY")),
                    "{state} {effective:?}"
                );
            }
        }
        for lower in ["NONE", "PROCESS_ISOLATION"] {
            assert_eq!(
                readiness("READY", Some(lower)).ok(),
                Some(Err("ASSURANCE_INSUFFICIENT")),
                "{lower}"
            );
        }
        // READY with no level, or one nobody spells: malformed, never run.
        for effective in [None, Some("CONTAINER"), Some("container_isolation")] {
            assert!(readiness("READY", effective).is_err(), "{effective:?}");
        }
    }

    #[test]
    fn only_a_clean_completion_or_an_unrelated_refusal_keeps_the_environment() {
        let empty = || dwk_proto::brokerp::ProcessStreamSnapshot {
            content: dwk_proto::wire::scalar::StreamContent::from_bytes(&[])
                .unwrap_or_else(|| unreachable!("no bytes")),
            observed: dwk_proto::wire::scalar::ByteCount::new(0)
                .unwrap_or_else(|| unreachable!("zero bytes")),
            truncated: false,
        };
        let completed = |residue| {
            let Some(none) = ProcessCount::new(0) else {
                unreachable!("zero processes")
            };
            Ending::Completed(Box::new(WorkloadRunDone {
                ending: WorkloadEnding::Exited,
                exit_code: dwk_proto::wire::scalar::ExitCode::new(0),
                signal: None,
                stdout: empty(),
                stderr: empty(),
                elapsed_ms: Milliseconds::new(5).unwrap_or_else(|| unreachable!("5 ms")),
                residue,
                ended_processes: none,
                remaining_processes: none,
                redactions: None,
            }))
        };
        assert_eq!(destroy_reason(&completed(Verdict::Pass)), None);
        for residue in [Verdict::Fail, Verdict::Unobservable] {
            assert_eq!(
                destroy_reason(&completed(residue)),
                Some("WORKLOAD_RESIDUE"),
                "{residue:?}"
            );
        }
        for reason in ["WORKLOAD_UNCONFIRMED", "BROKER_UNAVAILABLE", "INTERRUPTED"] {
            assert_eq!(
                destroy_reason(&Ending::Unknown { reason, done: None }),
                Some("WORKLOAD_UNKNOWN"),
                "{reason}"
            );
        }
        for reason in [
            "ENVIRONMENT_NOT_CLEAN",
            "ENVIRONMENT_NOT_FOUND",
            "FOREIGN_ENVIRONMENT",
            // M5d.4: a workspace that changed under a READY environment --
            // replaced, or no longer the contract's on the authority's side,
            // or not one this broker builds -- takes the environment down
            // before anything more runs in it.
            "WORKSPACE_CHANGED",
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
                destroy_reason(&Ending::Failed { reason }),
                Some("DRIFTED"),
                "{reason}"
            );
        }
        for reason in [
            "DIGEST_MISMATCH",
            "BROKER_UNAVAILABLE",
            "WORKSPACE_PATH",
            "BUDGET_EXHAUSTED",
        ] {
            assert_eq!(destroy_reason(&Ending::Failed { reason }), None, "{reason}");
        }
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
