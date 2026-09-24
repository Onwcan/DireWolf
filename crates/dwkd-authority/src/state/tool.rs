//! `ToolInvoke` and `CanonicalPreview`: one canonical action, two gates, and —
//! for an invocation both allow — one brokered effect (M4b, [ADR-0043]).
//!
//! # The order, and why each step is where it is
//!
//! ```text
//! 1  (transaction)  locate: the fence, the run, the declared path's syntax,
//!                   the run's root binding; a refusal is recorded here
//! 2  (none)         M4a resolution beneath the pinned root: O_PATH
//!                   descriptors only -- the canonical path is the one the
//!                   FILESYSTEM supplies, never the spelling; a refusal is
//!                   recorded in its own transaction
//! 3  (transaction)  decide: the fence and the run again; the required
//!                   capability and the complete canonical action from the
//!                   resolved path; both gates. A preview records its answer
//!                   and stops. A denial is recorded and stops. An allowed
//!                   invocation mints its id and records the INTENT; COMMIT,
//!                   and the audit record is fsynced before this returns
//! 4  (none)         only now is the checked object opened for reading,
//!                   relative to its retained parent, and proved to be the
//!                   object resolved; a failure ends the invocation FAILED
//! 5  (none)         the broker channel: one authorisation, one descriptor
//! 6  (transaction)  the outcome and, for a result, the taint; COMMIT, fsync
//!                   -- only then is the runtime answered
//! ```
//!
//! **No readable descriptor exists before the intent is durable**: step 2
//! holds only `O_PATH` handles, and step 4 is the first `O_RDONLY` open. No
//! SQLite transaction is open across resolution, the open or the broker.
//!
//! Both operations share steps 1-3, so a preview and an invocation of the
//! same call resolve the same object, build the same action and apply the same
//! gates by construction. The required capability is derived here and never
//! read from the request: `fs.read:<canonical path>?max_bytes=<bound>&no_symlink_targets=true`
//! (`no_symlink_targets` is true of every object the resolver returns, because
//! it never follows one). The action's environment is `HOST` (the broker reads
//! on the host until M5) and its `byte_count` is the requested bound, so policy
//! decides on the most that could be read, before anything is.
//!
//! **What resolving first costs.** Resolution precedes the gates, so the
//! answer to a path the run may not read still says whether it resolved: a
//! refusal (`NOT_FOUND`, `SYMLINK`, …) or a denial. The class of a workspace
//! path is visible to the runtime; its content never is.
//!
//! The intent inserts the invocation's `tool_invocation` row in state `INTENT`;
//! step 4 or step 6 ends it `COMPLETED` or `FAILED`. A process that dies
//! between them leaves the row open, and the next incarnation ends it
//! `INTERRUPTED` before it serves anything ([`interrupt_open`]).
//!
//! [ADR-0043]: ../../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

use dwk_proto::dwkp::messages::FsReadCall;
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::{
    Epoch, ReadLimit, ToolFailureReason, ToolOperation, ToolRefusalReason,
};
use rusqlite::OptionalExtension as _;

use crate::broker::{BrokerFailure, FsReadDelivery};
use crate::capability::{
    Action, Capability, ConstraintSet, DeclaredPath, Namespace, NoSymlinkTargets, Scope, Verb,
};
use crate::policy::{CanonicalAction, Environment, TaintLevel};
use crate::resource::CanonicalPath;
use crate::resource::fs::{PathError, ResolveError, ResolvedResource, RootError};

use super::Work;
use super::admission;
use super::audit::{AuditEvent, Fields};
use super::config::RootBinding;
use super::digest::{self, DomainHash};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord, TaintCause};
use super::resolution::{self, ResolutionRefused};

/// A tool action the two gates decided: what the wire reports about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDecision {
    action: CanonicalAction,
    canonical: CanonicalPath,
    max_bytes: ReadLimit,
    record: DecisionRecord,
}

impl ToolDecision {
    /// The canonical action decided on.
    #[must_use]
    pub const fn action(&self) -> &CanonicalAction {
        &self.action
    }

    /// Its canonical path.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The byte bound it was decided with.
    #[must_use]
    pub const fn max_bytes(&self) -> ReadLimit {
        self.max_bytes
    }

    /// Both gates' results.
    #[must_use]
    pub const fn record(&self) -> &DecisionRecord {
        &self.record
    }
}

/// How a tool operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolReply {
    /// An invocation allowed, performed on the checked object, and recorded.
    Done {
        /// The authority's id for it.
        invocation: InvocationId,
        /// The decision.
        decision: ToolDecision,
        /// What the broker read.
        delivery: FsReadDelivery,
    },
    /// The path resolved; the two gates refused. Nothing was opened for
    /// reading or sent.
    Denied(ToolDecision),
    /// A preview: the path resolved, and the gates' decision on the action it
    /// names. Nothing was opened for reading.
    Previewed(ToolDecision),
    /// Refused before any effect was authorised.
    Refused(ToolOperation, ToolRefusalReason),
    /// An authorised invocation produced no result.
    Failed {
        /// The authority's id for it.
        invocation: InvocationId,
        /// Why.
        reason: ToolFailureReason,
    },
}

/// What step 1 found.
#[derive(Debug)]
pub(super) enum Located {
    /// Refused, and recorded.
    Refused(ToolRefusalReason),
    /// Where the path is to be resolved.
    At {
        /// The declared path, syntactically a path.
        declared: DeclaredPath,
        /// The run's root binding.
        binding: RootBinding,
    },
}

/// What step 3 decided, all of it recorded before it returns.
#[derive(Debug)]
pub(super) enum Decided {
    /// Refused (the fence or the run changed since step 1), and recorded.
    Refused(ToolRefusalReason),
    /// The gates refused an invocation.
    Denied(ToolDecision),
    /// A preview's answer.
    Previewed(ToolDecision),
    /// An invocation both gates allowed, its intent durable.
    Authorised {
        /// The decision.
        decision: ToolDecision,
        /// The authority's id for the invocation.
        invocation: InvocationId,
    },
}

/// The capability an `fs.read` of `canonical`, bounded at `max_bytes`,
/// requires. The single derivation; nothing on the wire states one.
pub(super) fn required_capability(
    canonical: CanonicalPath,
    max_bytes: ReadLimit,
) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Fs, Action::Read)
        .ok_or(AuthorityError::Invariant("fs.read is not a verb"))?;
    let constraints = ConstraintSet {
        max_bytes: Some(u64::from(max_bytes.get())),
        no_symlink_targets: Some(NoSymlinkTargets),
        ..ConstraintSet::unconstrained()
    };
    Capability::new(verb, Scope::Path(canonical), constraints)
        .map_err(|_| AuthorityError::Invariant("an fs.read capability does not assemble"))
}

/// A refusal for a spelling the grammar does not accept.
pub(super) const fn path_refusal(error: PathError) -> ToolRefusalReason {
    match error {
        PathError::OutsideWorkspace => ToolRefusalReason::PathOutsideWorkspace,
        PathError::Traversal { .. } => ToolRefusalReason::PathTraversal,
        PathError::EmptyComponent { .. }
        | PathError::Separator { .. }
        | PathError::UnsupportedCharacter { .. }
        | PathError::NotNormalized { .. }
        | PathError::NameTooLong { .. }
        | PathError::TooDeep => ToolRefusalReason::PathNotCanonical,
    }
}

/// A refusal for a path that did not resolve.
pub(super) const fn resolve_refusal(error: ResolveError) -> ToolRefusalReason {
    match error {
        ResolveError::Path(path) => path_refusal(path),
        ResolveError::NotFound { .. } => ToolRefusalReason::NotFound,
        ResolveError::NotADirectory { .. } => ToolRefusalReason::NotADirectory,
        ResolveError::Symlink { .. } => ToolRefusalReason::Symlink,
        ResolveError::MagicLink { .. } => ToolRefusalReason::MagicLink,
        ResolveError::MountCrossing { .. } => ToolRefusalReason::MountCrossing,
        ResolveError::NameMismatch { .. } => ToolRefusalReason::NameMismatch,
        ResolveError::NormalizationAmbiguity { .. } => ToolRefusalReason::NormalizationAmbiguity,
        ResolveError::SpecialFile { .. } => ToolRefusalReason::SpecialFile,
        // A read never asks to modify, so a hard-link refusal cannot arise;
        // mapped to the kind refusal to keep the function total.
        ResolveError::WrongKind { .. } | ResolveError::HardlinkAliased { .. } => {
            ToolRefusalReason::WrongKind
        }
        ResolveError::Race { .. } => ToolRefusalReason::Race,
        ResolveError::PermissionDenied { .. } => ToolRefusalReason::PermissionDenied,
        ResolveError::DirectoryTooLarge { .. } => ToolRefusalReason::DirectoryTooLarge,
        ResolveError::Unsupported => ToolRefusalReason::UnsupportedPlatform,
        ResolveError::Io { .. } => ToolRefusalReason::IoError,
    }
}

/// A refusal for a root that could not be pinned.
pub(super) const fn root_refusal(error: RootError) -> ToolRefusalReason {
    match error {
        RootError::Replaced => ToolRefusalReason::RootReplaced,
        RootError::Unsupported => ToolRefusalReason::UnsupportedPlatform,
        RootError::NotAbsolute
        | RootError::TooLong
        | RootError::Nul
        | RootError::Missing
        | RootError::NotADirectory
        | RootError::Symlink
        | RootError::UnsupportedFilesystem
        | RootError::PermissionDenied
        | RootError::Io(_) => ToolRefusalReason::RootUnavailable,
    }
}

/// The wire class of a broker failure.
pub(super) const fn failure_reason(failure: BrokerFailure) -> ToolFailureReason {
    match failure {
        BrokerFailure::NotConfigured
        | BrokerFailure::Unreachable(_)
        | BrokerFailure::PeerRefused { .. } => ToolFailureReason::BrokerUnavailable,
        BrokerFailure::Protocol(_) => ToolFailureReason::BrokerProtocolError,
        BrokerFailure::Refused(_) => ToolFailureReason::BrokerExecutionError,
    }
}

/// The wire class of a failure to open the checked object for reading after
/// its intent was recorded: another object is there now, or it cannot be read.
pub(super) const fn open_failure(error: ResolveError) -> ToolFailureReason {
    match error {
        ResolveError::PermissionDenied { .. }
        | ResolveError::Io { .. }
        | ResolveError::Unsupported => ToolFailureReason::ObjectUnreadable,
        _ => ToolFailureReason::ObjectChanged,
    }
}

/// Whether the caller holds `run`: active, theirs, this session's and fenced
/// to `epoch`. Also its activation must be the one in force.
fn run_is_live(
    work: &Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    active: &ActiveAuthority,
) -> Result<bool, AuthorityError> {
    let activation: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT activation_id FROM run WHERE run_id = ?1 AND session_id = ?2 \
                 AND subject = ?3 AND epoch = ?4 AND state = 'ACTIVE'",
            rusqlite::params![
                run.as_str(),
                session.as_str(),
                caller.subject().storage_key(),
                to_sql(epoch.get())?
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

/// Who asked, about what: the fields every tool record starts with.
fn base_fields(
    caller: &CallerContext,
    operation: ToolOperation,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
) -> Fields {
    Fields::new()
        .text("operation", operation.as_str())
        .text("tool", "fs.read")
        .text("subject", caller.subject().storage_key())
        .text("holder", caller.holder().to_string())
        .text("session_id", session.as_str())
        .text("run_id", run.as_str())
        .int("epoch", epoch.get())
}

/// The decision's fields: the canonical action and both gates.
fn decision_fields(active: &ActiveAuthority, decision: &ToolDecision) -> Fields {
    let record = &decision.record;
    Fields::new()
        .text("policy_revision", active.revision.to_hex())
        .text("canonical_path", decision.canonical.to_string())
        .int("byte_count", u64::from(decision.max_bytes.get()))
        .text("environment", decision.action.environment().as_str())
        .text(
            "required_capability",
            record.required().to_canonical_string(),
        )
        .flag("capability_satisfied", record.capability_satisfied())
        .maybe_text(
            "covering_cap_id",
            record.covering_grant().map(|c| c.as_str().to_owned()),
        )
        .text("policy_effect", record.policy().effect().as_str())
        .flag("policy_satisfied", record.policy_satisfied())
        .text("rule_id", record.policy().rule_id().as_str())
        .text("rule_source", record.policy().rule_source().to_string())
        .text("reason", record.policy().reason().as_str())
        .maybe_text(
            "unevaluable",
            record.policy().unevaluable().map(|u| u.to_string()),
        )
        .text("effect", if record.permits() { "ALLOW" } else { "DENY" })
}

/// Record a refusal and return it.
#[allow(clippy::too_many_arguments)]
pub(super) fn refuse(
    work: &mut Work<'_>,
    caller: &CallerContext,
    operation: ToolOperation,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    reason: ToolRefusalReason,
) -> Result<ToolRefusalReason, AuthorityError> {
    work.audit(
        AuditEvent::ToolRefused,
        base_fields(caller, operation, session, run, epoch).text("refusal", reason.as_str()),
    )?;
    Ok(reason)
}

/// Step 1: the fence, the run, the path's syntax and the run's root binding.
/// A refusal is recorded here and is final.
#[allow(clippy::too_many_arguments)]
pub(super) fn locate(
    work: &mut Work<'_>,
    caller: &CallerContext,
    operation: ToolOperation,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    call: &FsReadCall,
    active: &ActiveAuthority,
) -> Result<Located, AuthorityError> {
    let refused = |work: &mut Work<'_>, reason| {
        refuse(work, caller, operation, session, run, epoch, reason).map(Located::Refused)
    };
    if !lease::fence(work, caller, session, epoch)? {
        return refused(work, ToolRefusalReason::StaleEpoch);
    }
    if !run_is_live(work, caller, session, run, epoch, active)? {
        return refused(work, ToolRefusalReason::UnknownRun);
    }
    let Some(declared) = DeclaredPath::new(call.path.as_str()) else {
        return refused(work, ToolRefusalReason::PathNotCanonical);
    };
    match resolution::run_root(work, run.as_str())? {
        Ok(binding) => Ok(Located::At { declared, binding }),
        Err(ResolutionRefused::NoWorkspace | ResolutionRefused::NoWorkspaceRoot) => {
            refused(work, ToolRefusalReason::WorkspaceUnbound)
        }
        Err(_) => Err(AuthorityError::Invariant(
            "a live run's root binding could not be read",
        )),
    }
}

/// Step 3: the fence and the run again (step 2 ran outside any transaction),
/// the canonical action from the path the resolver derived, both gates — and
/// for an allowed invocation, the durable intent. Everything decided here is
/// recorded before it returns.
#[allow(clippy::too_many_arguments)]
pub(super) fn decide(
    work: &mut Work<'_>,
    caller: &CallerContext,
    operation: ToolOperation,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    max_bytes: ReadLimit,
    resolved: &ResolvedResource,
    active: &ActiveAuthority,
) -> Result<Decided, AuthorityError> {
    let refused = |work: &mut Work<'_>, reason| {
        refuse(work, caller, operation, session, run, epoch, reason).map(Decided::Refused)
    };
    if !lease::fence(work, caller, session, epoch)? {
        return refused(work, ToolRefusalReason::StaleEpoch);
    }
    if !run_is_live(work, caller, session, run, epoch, active)? {
        return refused(work, ToolRefusalReason::UnknownRun);
    }
    // The canonical path is the resolver's: the filesystem supplied it.
    let canonical = resolved.canonical_path().clone();
    let capability = required_capability(canonical.clone(), max_bytes)?;
    let action = CanonicalAction::new(capability, Environment::Host)
        .with_byte_count(u64::from(max_bytes.get()));
    let admission = admission::load(work, run.as_str())?;
    let context = query::policy_context(work, run.as_str(), active)?;
    let record = query::decide(&action, &admission, &context, active);
    let decision = ToolDecision {
        action,
        canonical,
        max_bytes,
        record,
    };
    let mut fields = base_fields(caller, operation, session, run, epoch);
    fields.extend(decision_fields(active, &decision));
    if operation == ToolOperation::CanonicalPreview {
        work.audit(AuditEvent::ToolPreviewed, fields)?;
        return Ok(Decided::Previewed(decision));
    }
    if !decision.record.permits() {
        work.audit(AuditEvent::ToolDenied, fields)?;
        return Ok(Decided::Denied(decision));
    }
    // The durable intent: everything the broker will be told, before the file
    // is even opened for reading.
    let invocation = work.invocation_id()?;
    let identity = resolved.identity();
    let root = resolved.root_identity();
    let incarnation = work.incarnation();
    work.db(work.tx.execute(
        "INSERT INTO tool_invocation (invocation_id, run_id, tool, canonical_path, byte_count, \
         object_device, object_inode, incarnation, state, failure, bytes_returned, intent_ms, \
         ended_ms) VALUES (?1, ?2, 'fs.read', ?3, ?4, ?5, ?6, ?7, 'INTENT', NULL, NULL, ?8, NULL)",
        rusqlite::params![
            invocation.as_str(),
            run.as_str(),
            decision.canonical.to_string(),
            i64::from(decision.max_bytes.get()),
            identity.device().to_string(),
            identity.inode().to_string(),
            to_sql(incarnation)?,
            to_sql(work.now)?
        ],
    ))?;
    fields.extend(
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("object_device", identity.device().to_string())
            .text("object_inode", identity.inode().to_string())
            .text("root_device", root.device().to_string())
            .text("root_inode", root.inode().to_string())
            .text("assurance", resolved.assurance().as_str()),
    );
    work.audit(AuditEvent::ToolIntentRecorded, fields)?;
    Ok(Decided::Authorised {
        decision,
        invocation,
    })
}

/// Step 4 failed: the checked object could not be opened for reading after its
/// intent was recorded. The invocation ends here, `FAILED`; nothing was sent
/// to the broker and nothing was read.
pub(super) fn record_open_failure(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    error: ResolveError,
) -> Result<ToolFailureReason, AuthorityError> {
    let reason = open_failure(error);
    let ended = work.db(work.tx.execute(
        "UPDATE tool_invocation SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
         WHERE invocation_id = ?1 AND state = 'INTENT'",
        rusqlite::params![invocation.as_str(), reason.as_str(), to_sql(work.now)?],
    ))?;
    if ended != 1 {
        return Err(AuthorityError::Invariant(
            "an open failure names no open invocation",
        ));
    }
    work.audit(
        AuditEvent::ToolFailed,
        Fields::new()
            .text("run_id", run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("failure", reason.as_str())
            .text("open_failure", resolve_refusal(error).as_str()),
    )?;
    Ok(reason)
}

/// Step 6: the outcome — and, for a result, the taint it brings — recorded
/// before the runtime is answered.
pub(super) fn record_outcome(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    outcome: &Result<FsReadDelivery, BrokerFailure>,
) -> Result<(), AuthorityError> {
    let ended = match outcome {
        Ok(delivery) => {
            let bytes = i64::try_from(delivery.content.len())
                .map_err(|_| AuthorityError::Invariant("a result length exceeds i64"))?;
            work.db(work.tx.execute(
                "UPDATE tool_invocation SET state = 'COMPLETED', bytes_returned = ?2, ended_ms = ?3 \
                 WHERE invocation_id = ?1 AND state = 'INTENT'",
                rusqlite::params![invocation.as_str(), bytes, to_sql(work.now)?],
            ))?
        }
        Err(failure) => work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = 'FAILED', failure = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![
                invocation.as_str(),
                failure_reason(*failure).as_str(),
                to_sql(work.now)?
            ],
        ))?,
    };
    if ended != 1 {
        return Err(AuthorityError::Invariant(
            "an outcome names no open invocation",
        ));
    }
    match outcome {
        Ok(delivery) => {
            // Workspace content is content the operator pointed the run at:
            // LOCAL_UNVERIFIED, never lower (CONTEXT.md). Raised before the
            // bytes can reach cognition; a crash after this is over-taint,
            // which is the safe direction.
            let taint = query::raise_taint(
                work,
                run,
                TaintLevel::LocalUnverified,
                TaintCause::ToolResult,
            )?;
            let digest = DomainHash::new(digest::TOOL_CONTENT)
                .bytes(&delivery.content)
                .finish();
            work.audit(
                AuditEvent::ToolCompleted,
                Fields::new()
                    .text("run_id", run.as_str())
                    .text("invocation_id", invocation.as_str())
                    .int(
                        "bytes_returned",
                        u64::try_from(delivery.content.len()).unwrap_or(u64::MAX),
                    )
                    .flag("eof_observed", delivery.eof_observed)
                    .text("content_sha256", digest.to_hex())
                    .text("taint", taint.as_str()),
            )
        }
        Err(failure) => {
            let mut fields = Fields::new()
                .text("run_id", run.as_str())
                .text("invocation_id", invocation.as_str())
                .text("failure", failure_reason(*failure).as_str())
                .text("broker_failure", failure.class());
            match failure {
                BrokerFailure::Unreachable(why) => {
                    fields.extend(Fields::new().text("unreachable", why.as_str()));
                }
                BrokerFailure::PeerRefused { observed_uid } => {
                    fields.extend(Fields::new().int("observed_uid", u64::from(*observed_uid)));
                }
                BrokerFailure::Protocol(why) => {
                    fields.extend(Fields::new().text("protocol", *why));
                }
                BrokerFailure::Refused(why) => {
                    fields.extend(Fields::new().text("broker_refusal", why.as_str()));
                }
                BrokerFailure::NotConfigured => {}
            }
            work.audit(AuditEvent::ToolFailed, fields)
        }
    }
}

/// End every invocation a previous incarnation left open, recording each as
/// interrupted. Runs in the start-up transaction, before anything is served.
pub(super) fn interrupt_open(work: &mut Work<'_>) -> Result<u64, AuthorityError> {
    let open: Vec<(String, String, i64)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, run_id, incarnation FROM tool_invocation \
             WHERE state = 'INTENT' ORDER BY intent_ms, invocation_id",
        ))?;
        let rows =
            work.db(statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    for (invocation, run, incarnation) in &open {
        let ended = work.db(work.tx.execute(
            "UPDATE tool_invocation SET state = 'INTERRUPTED', ended_ms = ?2 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation, to_sql(work.now)?],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant(
                "an open invocation could not be ended",
            ));
        }
        work.audit(
            AuditEvent::ToolInterrupted,
            Fields::new()
                .text("invocation_id", invocation.clone())
                .text("run_id", run.clone())
                .int(
                    "intent_incarnation",
                    u64::try_from(*incarnation).unwrap_or(0),
                ),
        )?;
    }
    Ok(u64::try_from(open.len()).unwrap_or(u64::MAX))
}
