//! `ToolInvoke` and `CanonicalPreview`: a canonical plan, every gate of every
//! action, and — for an invocation whose whole plan is allowed — one brokered
//! operation (M4b, [ADR-0043]; the eight filesystem tools, M4c, [ADR-0044]).
//!
//! # The order, and why each step is where it is
//!
//! ```text
//! 1  (transaction)  locate: the fence, the run, the idempotency key, the
//!                   call's type and paths' syntax, the run's root binding; a
//!                   refusal is recorded here
//! 2  (none)         resolution beneath the pinned root: every target, existing
//!                   or vacant, O_PATH descriptors only -- the canonical paths
//!                   are the ones the FILESYSTEM supplies, never the spelling;
//!                   a refusal is recorded in its own transaction
//! 3  (transaction)  decide: the fence, the run and the key again; the complete
//!                   canonical plan from the resolved paths; both gates of
//!                   every action. A preview records its plan and stops. A
//!                   denial is recorded and stops. An allowed invocation mints
//!                   its id, binds its key and records the INTENT; COMMIT, and
//!                   the audit record is fsynced before this returns
//! 4  (none)         only now are the effect-capable descriptors made: the
//!                   file opened for reading, the directory opened for
//!                   listing, the parent directories whose names change --
//!                   each proved to be the object checked, a vacant name
//!                   re-proved vacant; a failure ends the invocation FAILED
//! 5  (none)         the broker channel: one authorisation, exactly the
//!                   operation's descriptors
//! 6  (transaction)  the outcome -- COMPLETED, FAILED, or UNKNOWN when an
//!                   effect may have happened and nothing proves it -- and,
//!                   for a read-family result, the taint; COMMIT, fsync --
//!                   only then is the runtime answered
//! ```
//!
//! **No effect-capable descriptor exists before the intent is durable**: step
//! 2 holds only `O_PATH` handles, and step 4 is the first open for reading.
//! No SQLite transaction is open across resolution, the handoff or the broker.
//!
//! Preview and invocation share steps 1-3 and the one plan builder
//! (`state::plan`), so a preview names exactly the plan an invocation would
//! decide on. A preview mints nothing, binds no key, records no intent, opens
//! nothing for an effect and never contacts the broker.
//!
//! # An effect whose outcome is not proved is UNKNOWN, and is never repeated
//!
//! Once the authorisation has left for the broker, a missing or malformed
//! answer does not prove that nothing happened. For a tool without effect
//! that is only a failed read. For `fs.write`, `fs.patch`, `fs.move` and
//! `fs.delete` it is recorded `UNKNOWN` — never `FAILED`, which would claim
//! nothing changed, and never retried by the authority. The same holds for an
//! intent a previous incarnation left open ([`reconcile_open`]): start-up
//! records it `INTERRUPTED` (no effect possible) or `UNKNOWN` (an effect
//! possible), and performs nothing. What may be retried is the runtime's
//! decision, by the retry class persisted with the invocation, under a new
//! idempotency key.
//!
//! **What resolving first costs.** Resolution precedes the gates, so the
//! answer to a path the run may not touch still says whether it resolved: a
//! refusal (`NOT_FOUND`, `SYMLINK`, …) or a denial. The class of a workspace
//! path is visible to the runtime; its content never is.
//!
//! [ADR-0043]: ../../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md
//! [ADR-0044]: ../../../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md

use dwk_proto::dwkp::fsops::{
    ContentRevision, FsDeleteResult, FsListEntry, FsListResult, FsMoveResult, FsPatchResult,
    FsSearchResult, FsStatResult, FsWriteResult, ToolCall, ToolOutput,
};
use dwk_proto::dwkp::messages::{FsReadCall, FsReadResult};
use dwk_proto::json;
use dwk_proto::wire::WireType as _;
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::list::BoundedList;
use dwk_proto::wire::scalar::{
    ByteCount, ContentDigest, EntryCount, EntryName, Epoch, FsFailureReason, FsRefusalReason,
    FsTool, HexContent, IdempotencyKey, LinkCount, ObjectState, PatchOutcome, StatKind,
    ToolOperation,
};
use rusqlite::OptionalExtension as _;
use sha2::{Digest as _, Sha256};

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, FsReadDelivery, ListDelivery, Operation,
    RawListEntry, SearchDelivery, StatDelivery,
};
use crate::capability::DeclaredPath;
use crate::policy::TaintLevel;
use crate::resource::fs::{
    Access, Expect, PathError, PinnedRoot, ResolveError, ResolvedResource, RootError, Target,
    VacantResource,
};

use super::Work;
use super::admission;
use super::audit::{AuditEvent, Field, Fields};
use super::config::RootBinding;
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::plan::{self, Call, PlannedAction, ToolPlan, ToolVersion};
use super::policy_state::ActiveAuthority;
use super::query::{self, TaintCause};
use super::resolution::{self, ResolutionRefused};
use super::staging;

/// A tool request, as the state layer takes it: the call, the version it
/// arrived in, and — for a version-2 invocation — its idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequest {
    version: ToolVersion,
    call: ToolCall,
    key: Option<IdempotencyKey>,
}

impl ToolRequest {
    /// A version-1 `fs.read` (M4b).
    #[must_use]
    pub fn v1(call: &FsReadCall) -> Self {
        Self {
            version: ToolVersion::V1,
            call: ToolCall {
                fs_read: Some(call.clone()),
                fs_list: None,
                fs_search: None,
                fs_stat: None,
                fs_write: None,
                fs_patch: None,
                fs_move: None,
                fs_delete: None,
            },
            key: None,
        }
    }

    /// A version-2 call. An invocation needs `key`; a preview has none.
    #[must_use]
    pub const fn v2(call: ToolCall, key: Option<IdempotencyKey>) -> Self {
        Self {
            version: ToolVersion::V2,
            call,
            key,
        }
    }

    /// The version it arrived in.
    #[must_use]
    pub const fn version(&self) -> ToolVersion {
        self.version
    }

    /// The call.
    #[must_use]
    pub const fn call(&self) -> &ToolCall {
        &self.call
    }

    /// The idempotency key.
    #[must_use]
    pub const fn key(&self) -> Option<&IdempotencyKey> {
        self.key.as_ref()
    }
}

/// How a tool operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolReply {
    /// An invocation whose whole plan was allowed, performed on the checked
    /// objects, and recorded.
    Done {
        /// The authority's id for it.
        invocation: InvocationId,
        /// The plan.
        plan: ToolPlan,
        /// The tool's output.
        output: Box<ToolOutput>,
    },
    /// Every target resolved; at least one action was refused. Nothing was
    /// opened for an effect or sent.
    Denied(ToolPlan),
    /// A preview: every target resolved, and the plan an invocation would
    /// decide on. Nothing was opened for an effect.
    Previewed(ToolPlan),
    /// Refused before any effect was authorised.
    Refused(ToolOperation, FsRefusalReason),
    /// An authorised invocation produced no result — `OUTCOME_UNKNOWN` when an
    /// effect may have happened.
    Failed {
        /// The authority's id for it.
        invocation: InvocationId,
        /// Why.
        reason: FsFailureReason,
    },
}

/// Who asks, about what: the envelope of one tool operation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked<'a> {
    pub(super) caller: &'a CallerContext,
    pub(super) operation: ToolOperation,
    pub(super) session: &'a SessionId,
    pub(super) run: &'a RunId,
    pub(super) epoch: Epoch,
    pub(super) request: &'a ToolRequest,
}

impl Asked<'_> {
    /// The key an invocation binds, if this is an invocation that carries one.
    fn binding_key(&self) -> Option<&IdempotencyKey> {
        match self.operation {
            ToolOperation::ToolInvoke => self.request.key(),
            ToolOperation::CanonicalPreview => None,
        }
    }
}

/// What step 1 found.
#[derive(Debug)]
pub(super) enum Located {
    /// Refused, and recorded.
    Refused(FsRefusalReason),
    /// Where the call's paths are to be resolved.
    At {
        /// The call, typed.
        call: Call,
        /// The run's root binding.
        binding: RootBinding,
    },
}

/// What step 2 found: the call's targets, resolved.
#[derive(Debug)]
pub(super) enum Targets {
    /// One existing object.
    One(ResolvedResource),
    /// A write's target: an existing file or a vacant name.
    Write(Target),
    /// A move's source file and vacant destination.
    Move {
        /// The source.
        source: ResolvedResource,
        /// The destination.
        destination: VacantResource,
    },
}

impl Targets {
    /// The canonical paths the plan is built from.
    fn resolved(&self) -> plan::Resolved {
        match self {
            Self::One(resolved) | Self::Write(Target::Existing(resolved)) => plan::Resolved::One {
                canonical: resolved.canonical_path().clone(),
                object: ObjectState::Existing,
            },
            Self::Write(Target::Vacant(vacant)) => plan::Resolved::One {
                canonical: vacant.canonical_path().clone(),
                object: ObjectState::Vacant,
            },
            Self::Move {
                source,
                destination,
            } => plan::Resolved::Pair {
                source: source.canonical_path().clone(),
                destination: destination.canonical_path().clone(),
            },
        }
    }
}

/// What step 3 decided, all of it recorded before it returns.
#[derive(Debug)]
pub(super) enum Decided {
    /// Refused (the fence, the run or the key changed since step 1), and
    /// recorded.
    Refused(FsRefusalReason),
    /// At least one action of an invocation's plan was refused.
    Denied(ToolPlan),
    /// A preview's answer.
    Previewed(ToolPlan),
    /// An invocation whose whole plan was allowed, its intent durable.
    Authorised {
        /// The plan.
        plan: ToolPlan,
        /// The authority's id for the invocation.
        invocation: InvocationId,
    },
}

// ---------------------------------------------------------------------------
// Reason vocabularies.
// ---------------------------------------------------------------------------

/// A refusal for a spelling the grammar does not accept.
pub(super) const fn path_refusal(error: PathError) -> FsRefusalReason {
    match error {
        PathError::OutsideWorkspace => FsRefusalReason::PathOutsideWorkspace,
        PathError::Traversal { .. } => FsRefusalReason::PathTraversal,
        PathError::EmptyComponent { .. }
        | PathError::Separator { .. }
        | PathError::UnsupportedCharacter { .. }
        | PathError::NotNormalized { .. }
        | PathError::NameTooLong { .. }
        | PathError::TooDeep => FsRefusalReason::PathNotCanonical,
    }
}

/// A refusal for a path that did not resolve.
pub(super) const fn resolve_refusal(error: ResolveError) -> FsRefusalReason {
    match error {
        ResolveError::Path(path) => path_refusal(path),
        ResolveError::NotFound { .. } => FsRefusalReason::NotFound,
        ResolveError::NotADirectory { .. } => FsRefusalReason::NotADirectory,
        ResolveError::Symlink { .. } => FsRefusalReason::Symlink,
        ResolveError::MagicLink { .. } => FsRefusalReason::MagicLink,
        ResolveError::MountCrossing { .. } => FsRefusalReason::MountCrossing,
        ResolveError::NameMismatch { .. } => FsRefusalReason::NameMismatch,
        ResolveError::NormalizationAmbiguity { .. } => FsRefusalReason::NormalizationAmbiguity,
        ResolveError::SpecialFile { .. } => FsRefusalReason::SpecialFile,
        ResolveError::WrongKind { .. } => FsRefusalReason::WrongKind,
        ResolveError::HardlinkAliased { .. } => FsRefusalReason::MultiplyLinked,
        ResolveError::Race { .. } => FsRefusalReason::Race,
        ResolveError::PermissionDenied { .. } => FsRefusalReason::PermissionDenied,
        ResolveError::DirectoryTooLarge { .. } => FsRefusalReason::DirectoryTooLarge,
        ResolveError::Unsupported => FsRefusalReason::UnsupportedPlatform,
        ResolveError::Io { .. } => FsRefusalReason::IoError,
    }
}

/// A refusal for a root that could not be pinned.
pub(super) const fn root_refusal(error: RootError) -> FsRefusalReason {
    match error {
        RootError::Replaced => FsRefusalReason::RootReplaced,
        RootError::Unsupported => FsRefusalReason::UnsupportedPlatform,
        RootError::NotAbsolute
        | RootError::TooLong
        | RootError::Nul
        | RootError::Missing
        | RootError::NotADirectory
        | RootError::Symlink
        | RootError::UnsupportedFilesystem
        | RootError::PermissionDenied
        | RootError::Io(_) => FsRefusalReason::RootUnavailable,
    }
}

/// The wire class of a broker failure that provably changed nothing — the
/// authorisation never left, or the broker refused — or of any failure of a
/// tool without effect.
pub(super) const fn failure_reason(failure: BrokerFailure) -> FsFailureReason {
    use dwk_proto::brokerp::BrokerRefusal;
    match failure {
        BrokerFailure::NotConfigured
        | BrokerFailure::Unreachable(_)
        | BrokerFailure::PeerRefused { .. } => FsFailureReason::BrokerUnavailable,
        BrokerFailure::Protocol(_) => FsFailureReason::BrokerProtocolError,
        BrokerFailure::Refused(refusal) => match refusal {
            BrokerRefusal::ObjectChanged => FsFailureReason::ObjectChanged,
            BrokerRefusal::TargetOccupied => FsFailureReason::TargetOccupied,
            BrokerRefusal::Conflict => FsFailureReason::Conflict,
            BrokerRefusal::DirectoryNotEmpty => FsFailureReason::DirectoryNotEmpty,
            BrokerRefusal::WriteDenied => FsFailureReason::WriteDenied,
            BrokerRefusal::AttributesNotPreserved => FsFailureReason::AttributesNotPreserved,
            BrokerRefusal::SharedDirectory => FsFailureReason::SharedDirectory,
            BrokerRefusal::ChannelMismatch
            | BrokerRefusal::DescriptorCount
            | BrokerRefusal::DescriptorNotRegular
            | BrokerRefusal::DescriptorNotDirectory
            | BrokerRefusal::DescriptorNotReadable
            | BrokerRefusal::DescriptorNotPath
            | BrokerRefusal::IdentityMismatch
            | BrokerRefusal::ReadFailed
            | BrokerRefusal::Unsupported
            | BrokerRefusal::DirectoryTooLarge
            | BrokerRefusal::IoError => FsFailureReason::BrokerExecutionError,
        },
        BrokerFailure::Indeterminate(_) => FsFailureReason::BrokerExecutionError,
    }
}

/// The wire class of a failure to make the effect-capable descriptors after
/// the intent was recorded: another object is there now, a vacant name is
/// occupied, or the object cannot be opened.
pub(super) const fn handoff_failure(error: ResolveError, vacant: bool) -> FsFailureReason {
    match error {
        ResolveError::PermissionDenied { .. }
        | ResolveError::Io { .. }
        | ResolveError::Unsupported => FsFailureReason::ObjectUnreadable,
        ResolveError::Race { .. } if vacant => FsFailureReason::TargetOccupied,
        _ => FsFailureReason::ObjectChanged,
    }
}

// ---------------------------------------------------------------------------
// Steps 1 and 3.
// ---------------------------------------------------------------------------

/// Which tool a wire call names, before it is typed: for the records of a
/// refusal that comes first.
fn tool_named(call: &ToolCall) -> FsTool {
    if call.fs_list.is_some() {
        FsTool::FsList
    } else if call.fs_search.is_some() {
        FsTool::FsSearch
    } else if call.fs_stat.is_some() {
        FsTool::FsStat
    } else if call.fs_write.is_some() {
        FsTool::FsWrite
    } else if call.fs_patch.is_some() {
        FsTool::FsPatch
    } else if call.fs_move.is_some() {
        FsTool::FsMove
    } else if call.fs_delete.is_some() {
        FsTool::FsDelete
    } else {
        FsTool::FsRead
    }
}

/// Whether the caller holds `run`: active, theirs, this session's and fenced
/// to `epoch`. Also its activation must be the one in force.
fn run_is_live(
    work: &Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<bool, AuthorityError> {
    let activation: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT activation_id FROM run WHERE run_id = ?1 AND session_id = ?2 \
                 AND subject = ?3 AND epoch = ?4 AND state = 'ACTIVE'",
            rusqlite::params![
                asked.run.as_str(),
                asked.session.as_str(),
                asked.caller.subject().storage_key(),
                to_sql(asked.epoch.get())?
            ],
            |row| row.get(0),
        )
        .optional())?;
    match activation {
        None => Ok(false),
        Some(id) if id == active.activation_id => Ok(true),
        Some(_) => Err(AuthorityError::Invariant(
            "a live run belongs to an activation that is not in force",
        )),
    }
}

/// Whether an invocation's key is already bound, in this caller's session.
fn key_bound(
    work: &Work<'_>,
    asked: &Asked<'_>,
    key: &IdempotencyKey,
) -> Result<bool, AuthorityError> {
    let found: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT invocation_id FROM tool_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3",
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

/// The fence, the run and — for an invocation — the key: what steps 1 and 3
/// both check, because step 2 runs outside any transaction.
fn standing(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<Option<FsRefusalReason>, AuthorityError> {
    if !lease::fence(work, asked.caller, asked.session, asked.epoch)? {
        return Ok(Some(FsRefusalReason::StaleEpoch));
    }
    if !run_is_live(work, asked, active)? {
        return Ok(Some(FsRefusalReason::UnknownRun));
    }
    if asked.operation == ToolOperation::ToolInvoke && asked.request.version() == ToolVersion::V2 {
        let Some(key) = asked.request.key() else {
            return Err(AuthorityError::Invariant(
                "a version-2 invocation arrived without an idempotency key",
            ));
        };
        if key_bound(work, asked, key)? {
            return Ok(Some(FsRefusalReason::IdempotencyKeyReused));
        }
    }
    Ok(None)
}

/// Who asked, about what: the fields every tool record starts with.
fn base_fields(asked: &Asked<'_>, tool: FsTool) -> Fields {
    let fields = Fields::new()
        .text("operation", asked.operation.as_str())
        .text("tool", tool.as_str())
        .int(
            "protocol_version",
            match asked.request.version() {
                ToolVersion::V1 => 1,
                ToolVersion::V2 => 2,
            },
        )
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get());
    match asked.binding_key() {
        Some(key) => fields.text("idempotency_key", key.as_str()),
        None => fields,
    }
}

/// One action's fields: the canonical action and both gates.
fn action_fields(planned: &PlannedAction) -> Vec<(&'static str, Field)> {
    let record = planned.record();
    let policy = record.policy();
    let mut fields = vec![
        ("role", Field::Text(planned.role().as_str().to_owned())),
        ("verb", Field::Text(planned.verb().as_str().to_owned())),
        (
            "canonical_path",
            Field::Text(planned.canonical_path().to_string()),
        ),
        ("object", Field::Text(planned.object().as_str().to_owned())),
        ("byte_count", Field::Int(planned.byte_count())),
        (
            "required_capability",
            Field::Text(record.required().to_canonical_string()),
        ),
        (
            "capability_satisfied",
            Field::Flag(record.capability_satisfied()),
        ),
    ];
    if let Some(grant) = record.covering_grant() {
        fields.push(("covering_cap_id", Field::Text(grant.as_str().to_owned())));
    }
    fields.extend([
        (
            "policy_effect",
            Field::Text(policy.effect().as_str().to_owned()),
        ),
        ("policy_satisfied", Field::Flag(planned.policy_satisfied())),
        ("rule_id", Field::Text(policy.rule_id().as_str().to_owned())),
        ("rule_source", Field::Text(policy.rule_source().to_string())),
        ("reason", Field::Text(planned.reason().as_str().to_owned())),
        (
            "obligations",
            Field::List(
                policy
                    .obligations()
                    .as_slice()
                    .iter()
                    .map(|o| Field::Text(o.to_string()))
                    .collect(),
            ),
        ),
    ]);
    if let Some(unevaluable) = policy.unevaluable() {
        fields.push(("unevaluable", Field::Text(unevaluable.to_string())));
    }
    fields.push((
        "effect",
        Field::Text(if planned.permits() { "ALLOW" } else { "DENY" }.to_owned()),
    ));
    fields
}

/// The plan's fields: every action, and — so that a one-action plan's record
/// reads as M4b's did — the first action's flat.
fn plan_fields(active: &ActiveAuthority, plan: &ToolPlan) -> Fields {
    let mut fields = Fields::new()
        .text("policy_revision", active.revision.to_hex())
        .text("retry_class", plan.retry_class().as_str())
        .text("environment", "host");
    if let Some(primary) = plan.primary() {
        let record = primary.record();
        let policy = record.policy();
        fields.extend(
            Fields::new()
                .text("canonical_path", primary.canonical_path().to_string())
                .int("byte_count", primary.byte_count())
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
                .flag("policy_satisfied", primary.policy_satisfied())
                .text("rule_id", policy.rule_id().as_str())
                .text("rule_source", policy.rule_source().to_string())
                .text("reason", primary.reason().as_str())
                .maybe_text("unevaluable", policy.unevaluable().map(|u| u.to_string())),
        );
    }
    fields
        .list(
            "actions",
            plan.actions()
                .iter()
                .map(|planned| Field::Object(action_fields(planned)))
                .collect(),
        )
        .text("effect", if plan.permits() { "ALLOW" } else { "DENY" })
}

/// Record a refusal and return it.
pub(super) fn refuse(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: FsRefusalReason,
) -> Result<FsRefusalReason, AuthorityError> {
    let tool = tool_named(asked.request.call());
    work.audit(
        AuditEvent::ToolRefused,
        base_fields(asked, tool).text("refusal", reason.as_str()),
    )?;
    Ok(reason)
}

/// Step 1: the fence, the run, the key, the call's type and paths, and the
/// run's root binding. A refusal is recorded here and is final.
pub(super) fn locate(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<Located, AuthorityError> {
    if let Some(reason) = standing(work, asked, active)? {
        return refuse(work, asked, reason).map(Located::Refused);
    }
    let call = match Call::from_wire(asked.request.call()) {
        Ok(call) => call,
        Err(reason) => return refuse(work, asked, reason).map(Located::Refused),
    };
    match resolution::run_root(work, asked.run.as_str())? {
        Ok(binding) => Ok(Located::At { call, binding }),
        Err(ResolutionRefused::NoWorkspace | ResolutionRefused::NoWorkspaceRoot) => {
            refuse(work, asked, FsRefusalReason::WorkspaceUnbound).map(Located::Refused)
        }
        Err(_) => Err(AuthorityError::Invariant(
            "a live run's root binding could not be read",
        )),
    }
}

/// Step 2: pin the run's root and resolve every target of `call` beneath it,
/// with the kind and the access each tool needs. `O_PATH` descriptors only;
/// nothing is opened for reading or writing here. Call with no transaction
/// open.
///
/// | call | target | access, kind |
/// |---|---|---|
/// | read, search | existing | observe, regular file |
/// | stat | existing | observe, file or directory |
/// | list | existing | observe, directory |
/// | write | existing or vacant | modify, regular file |
/// | patch | existing | modify, regular file |
/// | move | source existing; destination vacant | observe, regular file; any |
/// | delete | existing, not the workspace root | observe, file or directory |
///
/// `modify` refuses a multiply-linked file (`MULTIPLY_LINKED`): a write or
/// patch changes a file's content, which every other name would see. A move
/// or delete changes one name only, so a hard-linked file may be moved or
/// deleted; its other names are untouched (ADR-0044 §5).
///
/// # Errors
///
/// The refusal, by class.
pub(super) fn resolve_targets(
    binding: &RootBinding,
    call: &Call,
) -> Result<Targets, FsRefusalReason> {
    let root =
        PinnedRoot::reopen(&binding.host_path, &binding.fingerprint).map_err(root_refusal)?;
    let resolve = |path: &DeclaredPath, access, expect| {
        root.resolve(path, access, expect).map_err(resolve_refusal)
    };
    Ok(match call {
        Call::Read { path, .. } | Call::Search { path, .. } => {
            Targets::One(resolve(path, Access::Observe, Expect::RegularFile)?)
        }
        Call::Stat { path } => Targets::One(resolve(path, Access::Observe, Expect::Any)?),
        Call::List { path, .. } => Targets::One(resolve(path, Access::Observe, Expect::Directory)?),
        Call::Write { path, .. } => Targets::Write(
            root.resolve_target(path, Access::Modify, Expect::RegularFile)
                .map_err(resolve_refusal)?,
        ),
        Call::Patch { path, .. } => {
            Targets::One(resolve(path, Access::Modify, Expect::RegularFile)?)
        }
        Call::Move {
            source,
            destination,
        } => {
            let source = resolve(source, Access::Observe, Expect::RegularFile)?;
            match root
                .resolve_target(destination, Access::Observe, Expect::Any)
                .map_err(resolve_refusal)?
            {
                Target::Existing(_) => return Err(FsRefusalReason::DestinationExists),
                Target::Vacant(destination) => Targets::Move {
                    source,
                    destination,
                },
            }
        }
        Call::Delete { path } => {
            let resolved = resolve(path, Access::Observe, Expect::Any)?;
            if resolved.is_workspace_root() {
                return Err(FsRefusalReason::WorkspaceRoot);
            }
            Targets::One(resolved)
        }
    })
}

/// The digest a key is bound to: the run and the canonical call. What M9's
/// status query will compare a retry against.
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

/// Step 3: the fence, the run and the key again (step 2 ran outside any
/// transaction), the plan from the paths the resolver derived, every gate of
/// every action — and for an invocation whose whole plan is allowed, the
/// durable intent. Everything decided here is recorded before it returns.
pub(super) fn decide(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    call: &Call,
    targets: &Targets,
    active: &ActiveAuthority,
) -> Result<Decided, AuthorityError> {
    if let Some(reason) = standing(work, asked, active)? {
        return refuse(work, asked, reason).map(Decided::Refused);
    }
    let admission = admission::load(work, asked.run.as_str())?;
    let context = query::policy_context(work, asked.run.as_str(), active)?;
    // The canonical paths are the resolver's: the filesystem supplied them.
    let plan = plan::decide(call, &targets.resolved(), &admission, &context, active)?;
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
    // Where the one staging directory this invocation may make will be:
    // recorded with the intent, so that none is ever untracked.
    let staged = match staging::staged(call, targets) {
        Ok(staged) => staged,
        Err(reason) => return refuse(work, asked, reason).map(Decided::Refused),
    };
    // The durable intent: everything the broker will be told, before any
    // descriptor that could perform it exists.
    let invocation = work.invocation_id()?;
    let intent = Intent::of(&plan, targets)?;
    work.db(work.tx.execute(
        "INSERT INTO tool_invocation (invocation_id, run_id, tool, retry_class, canonical_path, \
         object_state, object_device, object_inode, destination_path, destination_device, \
         destination_inode, byte_count, incarnation, state, failure, completion, content_bytes, \
         intent_ms, ended_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
         'INTENT', NULL, NULL, NULL, ?14, NULL)",
        rusqlite::params![
            invocation.as_str(),
            asked.run.as_str(),
            plan.tool().as_str(),
            plan.retry_class().as_str(),
            intent.canonical,
            intent.object.as_str(),
            intent.device,
            intent.inode,
            intent.destination.as_ref().map(|d| d.0.clone()),
            intent.destination.as_ref().map(|d| d.1.clone()),
            intent.destination.as_ref().map(|d| d.2.clone()),
            to_sql(intent.byte_count)?,
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    if let Some(key) = asked.binding_key() {
        let digest = request_digest(asked)?;
        work.db(work.tx.execute(
            "INSERT INTO tool_idempotency (subject, session_id, idempotency_key, request_digest, \
             invocation_id, recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
    if let Some(staged) = &staged {
        fields.extend(staging::record(work, &invocation, staged)?);
    }
    fields.extend(
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("object_state", intent.object.as_str())
            .text("object_device", intent.device.clone())
            .text("object_inode", intent.inode.clone())
            .maybe_text(
                "destination_path",
                intent.destination.as_ref().map(|d| d.0.clone()),
            )
            .maybe_text(
                "destination_parent_device",
                intent.destination.as_ref().map(|d| d.1.clone()),
            )
            .maybe_text(
                "destination_parent_inode",
                intent.destination.as_ref().map(|d| d.2.clone()),
            )
            .text("root_device", intent.root.device().to_string())
            .text("root_inode", intent.root.inode().to_string())
            .text("assurance", intent.assurance),
    );
    work.audit(AuditEvent::ToolIntentRecorded, fields)?;
    Ok(Decided::Authorised { plan, invocation })
}

/// What an intent row records about a plan's targets.
struct Intent {
    canonical: String,
    object: ObjectState,
    /// The object's identity, or a vacant target's parent's.
    device: String,
    inode: String,
    /// A move's destination: its canonical path and its parent's identity.
    destination: Option<(String, String, String)>,
    byte_count: u64,
    root: crate::resource::FileIdentity,
    assurance: &'static str,
}

impl Intent {
    fn of(plan: &ToolPlan, targets: &Targets) -> Result<Self, AuthorityError> {
        let primary = plan
            .primary()
            .ok_or(AuthorityError::Invariant("an allowed plan has no action"))?;
        // The content bound the invocation row keeps: the action that moves
        // the most content through the broker.
        let byte_count = plan
            .actions()
            .iter()
            .map(PlannedAction::byte_count)
            .max()
            .unwrap_or(0);
        let existing = |resolved: &ResolvedResource| Self {
            canonical: resolved.canonical_path().to_string(),
            object: ObjectState::Existing,
            device: resolved.identity().device().to_string(),
            inode: resolved.identity().inode().to_string(),
            destination: None,
            byte_count,
            root: resolved.root_identity(),
            assurance: resolved.assurance().as_str(),
        };
        let intent = match targets {
            Targets::One(resolved) | Targets::Write(Target::Existing(resolved)) => {
                existing(resolved)
            }
            Targets::Write(Target::Vacant(vacant)) => Self {
                canonical: vacant.canonical_path().to_string(),
                object: ObjectState::Vacant,
                device: vacant.parent_identity().device().to_string(),
                inode: vacant.parent_identity().inode().to_string(),
                destination: None,
                byte_count,
                root: vacant.root_identity(),
                assurance: vacant.assurance().as_str(),
            },
            Targets::Move {
                source,
                destination,
            } => Self {
                destination: Some((
                    destination.canonical_path().to_string(),
                    destination.parent_identity().device().to_string(),
                    destination.parent_identity().inode().to_string(),
                )),
                ..existing(source)
            },
        };
        if intent.canonical != primary.canonical_path().to_string() {
            return Err(AuthorityError::Invariant(
                "an intent's target is not its plan's",
            ));
        }
        Ok(intent)
    }
}

// ---------------------------------------------------------------------------
// Step 4: the handoff.
// ---------------------------------------------------------------------------

/// Step 4: make exactly the descriptors the operation needs, from the checked
/// targets, re-proving each — and nothing else. Consumes the targets: every
/// `O_PATH` descriptor not handed on closes here.
///
/// # Errors
///
/// The failure, when a target is no longer the object checked, a vacant name
/// is occupied, or an object cannot be opened.
pub(super) fn handoff(
    call: Call,
    targets: Targets,
) -> Result<Operation, (FsFailureReason, FsRefusalReason)> {
    let failed = |vacant: bool| {
        move |error: ResolveError| (handoff_failure(error, vacant), resolve_refusal(error))
    };
    let mismatch = || (FsFailureReason::ObjectChanged, FsRefusalReason::WrongKind);
    Ok(match (call, targets) {
        (Call::Read { max_bytes, .. }, Targets::One(resolved)) => Operation::Read {
            max_bytes,
            file: resolved.into_read_handoff().map_err(failed(false))?,
        },
        (
            Call::Search {
                needle,
                max_scan_bytes,
                max_matches,
                ..
            },
            Targets::One(resolved),
        ) => Operation::Search {
            needle,
            max_scan_bytes,
            max_matches,
            file: resolved.into_read_handoff().map_err(failed(false))?,
        },
        (Call::Stat { .. }, Targets::One(resolved)) => Operation::Stat {
            object: resolved.into_stat_handoff().map_err(failed(false))?,
        },
        (Call::List { max_entries, .. }, Targets::One(resolved)) => Operation::List {
            max_entries,
            directory: resolved.into_list_handoff().map_err(failed(false))?,
        },
        (Call::Write { content, .. }, Targets::Write(Target::Existing(resolved))) => {
            Operation::Write {
                parent: resolved.into_parent_handoff().map_err(failed(false))?,
                content,
            }
        }
        (Call::Write { content, .. }, Targets::Write(Target::Vacant(vacant))) => Operation::Write {
            parent: vacant.into_parent_handoff().map_err(failed(true))?,
            content,
        },
        (
            Call::Patch {
                base, post, edits, ..
            },
            Targets::One(resolved),
        ) => {
            let (parent, file) = resolved.into_patch_handoff().map_err(failed(false))?;
            Operation::Patch {
                parent,
                file,
                base,
                post,
                edits,
            }
        }
        (
            Call::Move { .. },
            Targets::Move {
                source,
                destination,
            },
        ) => {
            let source = source.into_parent_handoff().map_err(failed(false))?;
            let destination = destination.into_parent_handoff().map_err(failed(true))?;
            Operation::Move {
                source,
                destination,
            }
        }
        (Call::Delete { .. }, Targets::One(resolved)) => Operation::Delete {
            parent: resolved.into_parent_handoff().map_err(failed(false))?,
        },
        _ => return Err(mismatch()),
    })
}

/// Step 4 failed: the effect-capable descriptors could not be made after the
/// intent was recorded. The invocation ends here, `FAILED`: nothing was sent
/// to the broker, so nothing was done.
pub(super) fn record_handoff_failure(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    (reason, detail): (FsFailureReason, FsRefusalReason),
) -> Result<FsFailureReason, AuthorityError> {
    end(work, invocation, &Ending::Failed(reason))?;
    // Nothing was sent: no staging directory can exist.
    staging::clear(work, invocation)?;
    work.audit(
        AuditEvent::ToolFailed,
        Fields::new()
            .text("run_id", run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("failure", reason.as_str())
            .flag("effect_possible", false)
            .text("open_failure", detail.as_str()),
    )?;
    Ok(reason)
}

// ---------------------------------------------------------------------------
// Steps 5 and 6: the outcome.
// ---------------------------------------------------------------------------

/// How an invocation ended, as the store records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ending {
    /// The broker performed it and the authority accepted the result.
    Completed(Box<Completion>),
    /// It provably changed nothing.
    Failed(FsFailureReason),
    /// It may have changed something, and nothing proves what.
    Unknown,
}

/// A completed invocation: its output, and what the store and the audit
/// record keep about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Completion {
    /// What the runtime is answered with.
    pub(super) output: ToolOutput,
    /// The stored completion class.
    class: &'static str,
    /// The content bytes it moved.
    content_bytes: u64,
    /// The fields of its audit record: counts and digests, never content.
    fields: Fields,
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The plain SHA-256 of `bytes`, as a content digest.
fn content_digest(bytes: &[u8]) -> Result<ContentDigest, AuthorityError> {
    ContentDigest::new(hex(&Sha256::digest(bytes)))
        .ok_or(AuthorityError::Invariant("a digest is not a digest"))
}

/// Why a delivery is not a result for this invocation.
type Malformed = &'static str;

/// A count, as the audit record and the store keep it.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// An output with no member yet.
const fn no_output() -> ToolOutput {
    ToolOutput {
        fs_read: None,
        fs_list: None,
        fs_search: None,
        fs_stat: None,
        fs_write: None,
        fs_patch: None,
        fs_move: None,
        fs_delete: None,
    }
}

/// Turn what the broker delivered into the tool's output, checking it against
/// everything the plan was decided on. A delivery that does not fit is not a
/// result: never recorded as one, never tainting, never reaching the runtime.
fn complete(
    call: &Call,
    plan: &ToolPlan,
    delivery: BrokerDelivery,
) -> Result<Result<Completion, Malformed>, AuthorityError> {
    Ok(match (call, delivery) {
        (Call::Read { max_bytes, .. }, BrokerDelivery::Read(read)) => {
            completed_read(max_bytes.get(), &read)
        }
        (Call::List { max_entries, .. }, BrokerDelivery::List(list)) => {
            completed_list(usize::from(max_entries.get()), &list)
        }
        (
            Call::Search {
                needle,
                max_scan_bytes,
                max_matches,
                ..
            },
            BrokerDelivery::Search(found),
        ) => search_fits(&found, needle, max_scan_bytes.get(), max_matches.get())
            .and_then(|()| completed_search(&found)),
        (Call::Stat { .. }, BrokerDelivery::Stat(stat)) => completed_stat(&stat),
        (Call::Write { content, .. }, BrokerDelivery::Write { created, debris }) => {
            let creating = plan
                .actions()
                .iter()
                .any(|a| a.object() == ObjectState::Vacant);
            if created == creating {
                completed_write(content, created, debris)?
            } else {
                Err("the broker created where it was to replace, or the reverse")
            }
        }
        (Call::Patch { post, .. }, BrokerDelivery::Patch { outcome, debris }) => {
            Ok(completed_patch(post, outcome, debris))
        }
        (Call::Move { .. }, BrokerDelivery::Move) => Ok(Completion {
            output: ToolOutput {
                fs_move: Some(FsMoveResult {}),
                ..no_output()
            },
            class: "MOVED",
            content_bytes: 0,
            fields: Fields::new(),
        }),
        (Call::Delete { .. }, BrokerDelivery::Delete { debris }) => Ok(Completion {
            output: ToolOutput {
                fs_delete: Some(FsDeleteResult {}),
                ..no_output()
            },
            class: "DELETED",
            content_bytes: 0,
            fields: Fields::new().flag("debris", debris),
        }),
        _ => Err("the broker answered another operation"),
    })
}

fn completed_read(max_bytes: u32, read: &FsReadDelivery) -> Result<Completion, Malformed> {
    if read.content.len() > usize::try_from(max_bytes).unwrap_or(usize::MAX) {
        return Err("the broker returned more than was authorised");
    }
    let content =
        HexContent::from_bytes(&read.content).ok_or("a read result does not fit the wire")?;
    let digest = DomainHash::new(digest::TOOL_CONTENT)
        .bytes(&read.content)
        .finish();
    Ok(Completion {
        output: ToolOutput {
            fs_read: Some(FsReadResult {
                content,
                eof_observed: read.eof_observed,
            }),
            ..no_output()
        },
        class: "READ",
        content_bytes: count(read.content.len()),
        fields: Fields::new()
            .int("bytes_returned", count(read.content.len()))
            .flag("eof_observed", read.eof_observed)
            .text("content_sha256", digest.to_hex()),
    })
}

fn completed_list(max: usize, list: &ListDelivery) -> Result<Completion, Malformed> {
    let (entries, unaddressable) = listing(max, &list.entries)?;
    let (Some(entries), Some(unaddressable)) = (
        BoundedList::new(entries),
        EntryCount::new(u16::try_from(unaddressable).unwrap_or(u16::MAX)),
    ) else {
        return Err("a listing does not fit the wire");
    };
    Ok(Completion {
        output: ToolOutput {
            fs_list: Some(FsListResult {
                entries,
                unaddressable,
                complete: list.complete,
            }),
            ..no_output()
        },
        class: "LISTED",
        content_bytes: 0,
        fields: Fields::new()
            .int("entries_examined", count(list.entries.len()))
            .int("unaddressable", u64::from(unaddressable.get()))
            .flag("complete", list.complete),
    })
}

fn completed_search(found: &SearchDelivery) -> Result<Completion, Malformed> {
    let offsets: Option<Vec<ByteCount>> =
        found.offsets.iter().map(|o| ByteCount::new(*o)).collect();
    let (Some(offsets), Some(scanned)) = (
        offsets.and_then(BoundedList::new),
        ByteCount::new(found.scanned),
    ) else {
        return Err("a search result does not fit the wire");
    };
    Ok(Completion {
        output: ToolOutput {
            fs_search: Some(FsSearchResult {
                offsets,
                scanned,
                eof_observed: found.eof_observed,
                matches_truncated: found.matches_truncated,
            }),
            ..no_output()
        },
        class: "SEARCHED",
        content_bytes: found.scanned,
        fields: Fields::new()
            .int("matches", count(found.offsets.len()))
            .int("scanned", found.scanned)
            .flag("eof_observed", found.eof_observed)
            .flag("matches_truncated", found.matches_truncated),
    })
}

fn completed_stat(stat: &StatDelivery) -> Result<Completion, Malformed> {
    let result = stat_result(stat).ok_or("a stat result does not fit the wire")?;
    Ok(Completion {
        output: ToolOutput {
            fs_stat: Some(result),
            ..no_output()
        },
        class: "STATED",
        content_bytes: 0,
        fields: Fields::new().text("kind", stat.kind.as_str()),
    })
}

fn completed_write(
    content: &[u8],
    created: bool,
    debris: bool,
) -> Result<Result<Completion, Malformed>, AuthorityError> {
    let sha256 = content_digest(content)?;
    let Some(length) = ByteCount::new(count(content.len())) else {
        return Ok(Err("a write length does not fit the wire"));
    };
    Ok(Ok(Completion {
        output: ToolOutput {
            fs_write: Some(FsWriteResult {
                created,
                length,
                sha256: sha256.clone(),
            }),
            ..no_output()
        },
        class: if created { "CREATED" } else { "REPLACED" },
        content_bytes: count(content.len()),
        fields: Fields::new()
            .flag("created", created)
            .int("length", count(content.len()))
            .text("content_sha256", sha256.as_str())
            .flag("debris", debris),
    }))
}

fn completed_patch(post: &ContentRevision, outcome: PatchOutcome, debris: bool) -> Completion {
    Completion {
        output: ToolOutput {
            fs_patch: Some(FsPatchResult {
                outcome,
                post: post.clone(),
            }),
            ..no_output()
        },
        class: match outcome {
            PatchOutcome::Applied => "APPLIED",
            PatchOutcome::AlreadyApplied => "ALREADY_APPLIED",
        },
        content_bytes: match outcome {
            PatchOutcome::Applied => u64::from(post.length.get()),
            PatchOutcome::AlreadyApplied => 0,
        },
        fields: Fields::new()
            .text("patch_outcome", outcome.as_str())
            .text("post_sha256", post.sha256.as_str())
            .int("post_length", u64::from(post.length.get()))
            .flag("debris", debris),
    }
}

/// A listing, checked and classified: at most `max` entries, strictly
/// ascending by name bytes; the names a canonical path can name, and a count
/// of those it cannot. A name the grammar refuses is counted, never rewritten.
fn listing(max: usize, raw: &[RawListEntry]) -> Result<(Vec<FsListEntry>, usize), Malformed> {
    if raw.len() > max {
        return Err("the broker listed more entries than were authorised");
    }
    if raw.windows(2).any(|pair| match pair {
        [a, b] => a.name >= b.name,
        _ => false,
    }) {
        return Err("a listing is not in ascending byte order");
    }
    let names: Vec<&[u8]> = raw.iter().map(|entry| entry.name.as_slice()).collect();
    let addressable = crate::resource::fs::addressable_names(&names);
    let mut entries = Vec::new();
    let mut unaddressable = 0usize;
    for (entry, ok) in raw.iter().zip(addressable) {
        let name = ok
            .then(|| core::str::from_utf8(&entry.name).ok())
            .flatten()
            .and_then(EntryName::new);
        match name {
            Some(name) => entries.push(FsListEntry {
                name,
                kind: entry.kind,
            }),
            None => unaddressable = unaddressable.saturating_add(1),
        }
    }
    Ok((entries, unaddressable))
}

/// Whether a search delivery is within its authorisation: at most the scan
/// bound scanned, at most `max_matches` offsets, strictly ascending, each a
/// whole occurrence within the scanned bytes.
fn search_fits(
    found: &SearchDelivery,
    needle: &dwk_proto::wire::scalar::Needle,
    max_scan: u32,
    max_matches: u16,
) -> Result<(), Malformed> {
    let needle_len = u64::try_from(needle.to_bytes().len()).unwrap_or(u64::MAX);
    if found.scanned > u64::from(max_scan) {
        return Err("the broker scanned more than was authorised");
    }
    if found.offsets.len() > usize::from(max_matches) {
        return Err("the broker reported more matches than were authorised");
    }
    if found.offsets.windows(2).any(|pair| match pair {
        [a, b] => a >= b,
        _ => false,
    }) {
        return Err("search offsets are not ascending");
    }
    if found.offsets.iter().any(|offset| {
        offset
            .checked_add(needle_len)
            .is_none_or(|end| end > found.scanned)
    }) {
        return Err("a search offset lies outside the scanned bytes");
    }
    if found.matches_truncated && found.offsets.len() != usize::from(max_matches) {
        return Err("a truncated search did not report its full bound");
    }
    Ok(())
}

/// A stat delivery on the wire: the executable flag from the mode, and never
/// for a directory.
fn stat_result(stat: &StatDelivery) -> Option<FsStatResult> {
    Some(FsStatResult {
        kind: stat.kind,
        size: ByteCount::new(stat.size)?,
        link_count: LinkCount::new(stat.link_count)?,
        executable: stat.kind == StatKind::RegularFile && stat.mode & 0o111 != 0,
    })
}

/// Classify the broker's answer. Effect-free tools keep M4b's classes: any
/// broker trouble is a failure, because a read cannot have changed anything.
/// A tool with an effect is `FAILED` only when the broker provably changed
/// nothing — it was told nothing, or it said it refused — and `UNKNOWN`
/// otherwise.
pub(super) fn classify(
    call: &Call,
    plan: &ToolPlan,
    result: Result<BrokerDelivery, BrokerError>,
) -> Result<(Ending, Option<(BrokerFailure, bool)>), AuthorityError> {
    let effect = plan::has_effect(call.tool());
    Ok(match result {
        Ok(delivery) => match complete(call, plan, delivery)? {
            Ok(completion) => (Ending::Completed(Box::new(completion)), None),
            Err(why) => {
                let failure = BrokerFailure::Protocol(why);
                if effect {
                    (Ending::Unknown, Some((failure, true)))
                } else {
                    (
                        Ending::Failed(FsFailureReason::BrokerProtocolError),
                        Some((failure, true)),
                    )
                }
            }
        },
        Err(error) => {
            let detail = Some((error.failure, error.sent));
            if effect && !error.provably_without_effect() {
                (Ending::Unknown, detail)
            } else {
                (Ending::Failed(failure_reason(error.failure)), detail)
            }
        }
    })
}

/// End an open invocation: exactly one row, from `INTENT`.
fn end(
    work: &mut Work<'_>,
    invocation: &InvocationId,
    ending: &Ending,
) -> Result<(), AuthorityError> {
    let now = to_sql(work.now)?;
    let ended = match ending {
        Ending::Completed(completion) => work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = 'COMPLETED', completion = ?2, content_bytes = ?3, \
             ended_ms = ?4 WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![
                invocation.as_str(),
                completion.class,
                to_sql(completion.content_bytes)?,
                now
            ],
        ))?,
        Ending::Failed(reason) => work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation.as_str(), reason.as_str(), now],
        ))?,
        Ending::Unknown => work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = 'UNKNOWN', ended_ms = ?2 \
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

/// The fields that say what the broker did wrong, for a failure's record.
fn broker_fields(failure: BrokerFailure, sent: bool) -> Fields {
    let fields = Fields::new()
        .text("broker_failure", failure.class())
        .flag("authorisation_sent", sent);
    match failure {
        BrokerFailure::Unreachable(why) => fields.text("unreachable", why.as_str()),
        BrokerFailure::PeerRefused { observed_uid } => {
            fields.int("observed_uid", u64::from(observed_uid))
        }
        BrokerFailure::Protocol(why) => fields.text("protocol", why),
        BrokerFailure::Refused(why) => fields.text("broker_refusal", why.as_str()),
        BrokerFailure::Indeterminate(why) => fields.text("indeterminate", why.as_str()),
        BrokerFailure::NotConfigured => fields,
    }
}

/// Step 6: the outcome — and, for a read-family result, the taint it brings —
/// recorded before the runtime is answered. `staging_clear` says the broker's
/// answer proves no staging directory is left: nothing was sent, or it
/// answered `done` with no debris.
pub(super) fn record_outcome(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    tool: FsTool,
    (ending, detail): (&Ending, Option<(BrokerFailure, bool)>),
    staging_clear: bool,
) -> Result<(), AuthorityError> {
    end(work, invocation, ending)?;
    if staging_clear {
        staging::clear(work, invocation)?;
    }
    let head = Fields::new()
        .text("run_id", run.as_str())
        .text("invocation_id", invocation.as_str())
        .text("tool", tool.as_str());
    match ending {
        Ending::Completed(completion) => {
            let mut fields = head;
            fields.extend(completion.fields.clone());
            if plan::taints(tool) {
                // Workspace content — bytes, names, offsets, metadata — is
                // content the operator pointed the run at: LOCAL_UNVERIFIED,
                // never lower (CONTEXT.md). Raised before it can reach
                // cognition; a crash after this is over-taint, the safe way.
                let taint = query::raise_taint(
                    work,
                    run,
                    TaintLevel::LocalUnverified,
                    TaintCause::ToolResult,
                )?;
                fields.extend(Fields::new().text("taint", taint.as_str()));
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
                .text("retry_class", plan::retry_class(tool).as_str())
                .text("cause", "broker");
            if let Some((failure, sent)) = detail {
                fields.extend(broker_fields(failure, sent));
            }
            work.audit(AuditEvent::ToolOutcomeUnknown, fields)
        }
    }
}

/// End every invocation a previous incarnation left open. **Nothing is
/// performed**: a tool without effect is recorded `INTERRUPTED` — its result,
/// if the broker produced one, was never delivered — and a tool with one
/// `UNKNOWN` — the broker may have acted, and nothing on this side proves
/// whether. Runs in the start-up transaction, before anything is served.
pub(super) fn reconcile_open(work: &mut Work<'_>) -> Result<(u64, u64), AuthorityError> {
    let open: Vec<(String, String, String, String, i64)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, run_id, tool, retry_class, incarnation FROM tool_invocation \
             WHERE state = 'INTENT' ORDER BY intent_ms, invocation_id",
        ))?;
        let rows = work.db(statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        }))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    let mut interrupted = 0u64;
    let mut unknown = 0u64;
    for (invocation, run, tool, retry, incarnation) in &open {
        let tool = FsTool::ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == tool)
            .ok_or(AuthorityError::Invariant(
                "a stored invocation names no tool",
            ))?;
        let (state, event) = if plan::has_effect(tool) {
            unknown = unknown.saturating_add(1);
            ("UNKNOWN", AuditEvent::ToolOutcomeUnknown)
        } else {
            interrupted = interrupted.saturating_add(1);
            ("INTERRUPTED", AuditEvent::ToolInterrupted)
        };
        let ended = work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation, state, to_sql(work.now)?],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant(
                "an open invocation could not be ended",
            ));
        }
        let mut fields = Fields::new()
            .text("invocation_id", invocation.clone())
            .text("run_id", run.clone())
            .int(
                "intent_incarnation",
                u64::try_from(*incarnation).unwrap_or(0),
            );
        if event == AuditEvent::ToolOutcomeUnknown {
            fields.extend(
                Fields::new()
                    .text("tool", tool.as_str())
                    .text("retry_class", retry.clone())
                    .text("cause", "restart"),
            );
        }
        work.audit(event, fields)?;
    }
    Ok((interrupted, unknown))
}
