//! The staging directories a write, a patch or a delete may leave in a
//! workspace, as the authority records and settles them (M4c, [ADR-0044] §10).
//!
//! The broker makes at most one staging directory per invocation —
//! `.dwkd-<invocation id>`, beside the one name the invocation changes. So
//! that a crash can never leave one untracked, the authority records **where
//! it will be** (the checked parent's canonical path and identity, the name,
//! the operation, the object authorised) in `tool_staging`, **in the same
//! transaction as the intent** — before any descriptor that could create it
//! exists.
//!
//! The row settles once:
//!
//! | how | state |
//! |---|---|
//! | nothing was sent to the broker, or it answered `done` with no debris | `CLEARED` |
//! | a reclamation found no directory | `CLEARED` |
//! | a reclamation found only the broker's own uncommitted data, and removed it | `REMOVED` |
//! | a reclamation found a workspace object, or the evidence of an effect | `RETAINED`, with what it holds |
//! | a reclamation found something by that name that is not the broker's | `FOREIGN` |
//!
//! Every other outcome — a refusal, an indeterminate answer, no answer, a
//! crash — leaves the row `EXPECTED`, and the authority asks the broker to
//! reclaim it (`broker.fs_reclaim`): right after the invocation's outcome is
//! recorded, after later invocations of the same run, and at start-up. **Only
//! for an invocation whose outcome is recorded** — a live invocation's
//! staging directory is never judged — and never as the invocation performed
//! again: a reclamation removes nothing but the broker's own uncommitted data,
//! and the invocation's `UNKNOWN` stays `UNKNOWN`. A retained directory, and
//! the object in it, stay for the operator and for M9's reconciliation, which
//! find them by this row.
//!
//! The authority itself changes nothing here, and **no stored path is
//! authority**: the row holds the parent's logical canonical path
//! (`/workspace/…`) and identity, never a host path. To reclaim, the authority
//! reopens the workspace's root binding — immutable: a different root is a
//! different workspace — and proves it by its M4a fingerprint, refusing a
//! symlink at its path (`PinnedRoot::reopen`); resolves the recorded parent
//! beneath that pinned root, one component at a time; requires it to be the
//! directory recorded, by identity; and hands the broker that one directory,
//! open for reading. A root renamed, replaced or redirected, or a parent
//! replaced beneath it, hands over nothing: the row stays `EXPECTED`, and
//! whatever is at the old path is never touched.
//!
//! [ADR-0044]: ../../../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md

use dwk_proto::brokerp::{ReclaimState, StagingHolds, StagingOperation};
use dwk_proto::wire::id::{InvocationId, RunId};
use dwk_proto::wire::scalar::FsRefusalReason;

use crate::broker::{BrokerDelivery, BrokerError, StagingSpec};
use crate::capability::DeclaredPath;
use crate::resource::ObjectHandoff;
use crate::resource::fs::{Access, Expect, PinnedRoot, ResolvedResource, Target};

use super::Work;
use super::audit::{AuditEvent, Fields};
use super::config::RootBinding;
use super::error::AuthorityError;
use super::lease::to_sql;
use super::plan::Call;
use super::resolution;
use super::tool::Targets;

/// The most staging records one sweep settles.
pub const MAX_RECLAIMS_PER_SWEEP: usize = 64;

/// Where an authorised write, patch or delete may make its one staging
/// directory, and what for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Staged {
    spec: StagingSpec,
    parent_path: String,
    parent: (u64, u64),
}

/// The canonical path of the directory that holds `canonical`.
fn parent_of(canonical: &str) -> Option<String> {
    canonical
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_owned())
        .filter(|parent| parent == "/workspace" || parent.starts_with("/workspace/"))
}

fn existing(
    operation: StagingOperation,
    resolved: &ResolvedResource,
) -> Result<Staged, FsRefusalReason> {
    let leaf = resolved.leaf_name().ok_or(FsRefusalReason::WorkspaceRoot)?;
    let parent = resolved
        .parent_identity()
        .map_err(|_| FsRefusalReason::IoError)?;
    let target = resolved.identity();
    Ok(Staged {
        spec: StagingSpec {
            operation,
            leaf: leaf.to_owned(),
            target: Some((target.device(), target.inode())),
        },
        parent_path: parent_of(&resolved.canonical_path().to_string())
            .ok_or(FsRefusalReason::WorkspaceRoot)?,
        parent: (parent.device(), parent.inode()),
    })
}

/// The staging directory `call` may make, from its resolved targets: `None`
/// for a tool that makes none.
///
/// # Errors
///
/// The refusal, when the checked parent cannot be identified — before any
/// intent is recorded.
pub(super) fn staged(call: &Call, targets: &Targets) -> Result<Option<Staged>, FsRefusalReason> {
    Ok(Some(match (call, targets) {
        (Call::Write { .. }, Targets::Write(Target::Existing(resolved)))
        | (Call::Patch { .. }, Targets::One(resolved)) => {
            existing(StagingOperation::Replace, resolved)?
        }
        (Call::Delete { .. }, Targets::One(resolved)) => {
            existing(StagingOperation::Delete, resolved)?
        }
        (Call::Write { .. }, Targets::Write(Target::Vacant(vacant))) => {
            let parent = vacant.parent_identity();
            Staged {
                spec: StagingSpec {
                    operation: StagingOperation::Create,
                    leaf: vacant.leaf_name().to_owned(),
                    target: None,
                },
                parent_path: parent_of(&vacant.canonical_path().to_string())
                    .ok_or(FsRefusalReason::WorkspaceRoot)?,
                parent: (parent.device(), parent.inode()),
            }
        }
        _ => return Ok(None),
    }))
}

/// The name of an invocation's staging directory.
pub(super) fn directory_name(invocation: &InvocationId) -> String {
    format!(".dwkd-{}", invocation.as_str())
}

/// Record, with the intent, where `invocation` may make its staging
/// directory. Returns the fields its intent's audit record carries.
pub(super) fn record(
    work: &mut Work<'_>,
    invocation: &InvocationId,
    staged: &Staged,
) -> Result<Fields, AuthorityError> {
    let target = staged.spec.target;
    work.db(work.tx.execute(
        "INSERT INTO tool_staging (invocation_id, operation, parent_path, parent_device, \
         parent_inode, leaf, target_device, target_inode, state, holds, held_device, \
         held_inode, recorded_ms, settled_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
         'EXPECTED', NULL, NULL, NULL, ?9, NULL)",
        rusqlite::params![
            invocation.as_str(),
            staged.spec.operation.as_str(),
            staged.parent_path,
            staged.parent.0.to_string(),
            staged.parent.1.to_string(),
            staged.spec.leaf,
            target.map(|t| t.0.to_string()),
            target.map(|t| t.1.to_string()),
            to_sql(work.now)?
        ],
    ))?;
    Ok(Fields::new()
        .text("staging_directory", directory_name(invocation))
        .text("staging_parent", staged.parent_path.clone()))
}

/// Settle `invocation`'s staging record `CLEARED`: the broker was told
/// nothing, or it answered `done` and left nothing behind. Nothing to do for a
/// tool that stages nothing.
pub(super) fn clear(work: &mut Work<'_>, invocation: &InvocationId) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "UPDATE tool_staging SET state = 'CLEARED', settled_ms = ?2 \
         WHERE invocation_id = ?1 AND state = 'EXPECTED'",
        rusqlite::params![invocation.as_str(), to_sql(work.now)?],
    ))?;
    Ok(())
}

/// A staging record still `EXPECTED`, for an invocation whose outcome is
/// recorded: what a reclamation needs.
#[derive(Debug, Clone)]
pub(super) struct Pending {
    pub(super) invocation: InvocationId,
    run: String,
    pub(super) spec: StagingSpec,
    parent_path: String,
    parent: (u64, u64),
    binding: Option<RootBinding>,
}

type PendingRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn number(text: &str) -> Result<u64, AuthorityError> {
    text.parse()
        .map_err(|_| AuthorityError::Invariant("a stored identity is not a number"))
}

/// At most `limit` `EXPECTED` staging records — of `run` only, if given —
/// oldest first, **for invocations whose outcome is recorded**: an invocation
/// still open is never reclaimed from under itself.
pub(super) fn pending(
    work: &Work<'_>,
    run: Option<&RunId>,
    limit: usize,
) -> Result<Vec<Pending>, AuthorityError> {
    let rows: Vec<PendingRow> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT s.invocation_id, i.run_id, s.operation, s.parent_path, s.parent_device, \
             s.parent_inode, s.leaf, s.target_device, s.target_inode \
             FROM tool_staging s JOIN tool_invocation i ON i.invocation_id = s.invocation_id \
             WHERE s.state = 'EXPECTED' AND i.state != 'INTENT' \
             AND (?1 IS NULL OR i.run_id = ?1) \
             ORDER BY s.recorded_ms, s.invocation_id LIMIT ?2",
        ))?;
        let rows = work.db(statement.query_map(
            rusqlite::params![
                run.map(RunId::as_str),
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| {
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
            },
        ))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    let mut found = Vec::with_capacity(rows.len());
    for (invocation, run, operation, parent_path, device, inode, leaf, t_device, t_inode) in rows {
        let operation = StagingOperation::ALL
            .iter()
            .copied()
            .find(|op| op.as_str() == operation)
            .ok_or(AuthorityError::Invariant("a stored staging operation"))?;
        let target = match (t_device, t_inode) {
            (Some(d), Some(i)) => Some((number(&d)?, number(&i)?)),
            _ => None,
        };
        found.push(Pending {
            invocation: InvocationId::parse(&invocation)
                .ok_or(AuthorityError::Invariant("a stored invocation id"))?,
            binding: resolution::recorded_root(work, &run)?,
            run,
            spec: StagingSpec {
                operation,
                leaf,
                target,
            },
            parent_path,
            parent: (number(&device)?, number(&inode)?),
        });
    }
    Ok(found)
}

/// The recorded parent directory, resolved beneath the run's root — re-pinned
/// by its fingerprint, never followed by its path — proved to be the directory
/// recorded, and opened for reading; or `None` when that cannot be done now
/// (no root, a root renamed, replaced or behind a symlink, a moved or replaced
/// parent), and the record stays `EXPECTED`. Call with no transaction open.
pub(super) fn directory(pending: &Pending) -> Option<ObjectHandoff> {
    let binding = pending.binding.as_ref()?;
    let root = PinnedRoot::reopen(&binding.host_path, &binding.fingerprint).ok()?;
    let declared = DeclaredPath::new(&pending.parent_path)?;
    let resolved = root
        .resolve(&declared, Access::Observe, Expect::Directory)
        .ok()?;
    let identity = resolved.identity();
    if (identity.device(), identity.inode()) != pending.parent {
        return None;
    }
    resolved.into_list_handoff().ok()
}

/// What one reclamation settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// No staging directory was there.
    Absent,
    /// It held only the broker's own uncommitted data, and is gone.
    Removed,
    /// It is kept: it may hold a workspace object, or is the evidence of an
    /// effect.
    Retained,
    /// Something by that name that is not the broker's; untouched.
    Foreign,
}

/// Settle `pending` from the broker's answer to a reclamation. A failure — no
/// broker, a refusal, an indeterminate or malformed answer — settles nothing:
/// the record stays `EXPECTED`, to be reclaimed later.
pub(super) fn settle(
    work: &mut Work<'_>,
    pending: &Pending,
    result: &Result<BrokerDelivery, BrokerError>,
) -> Result<Option<Settled>, AuthorityError> {
    let Ok(BrokerDelivery::Reclaim { state, holds, held }) = result else {
        return Ok(None);
    };
    let (state, holds, held) = (*state, *holds, *held);
    let (stored, settled) = match state {
        ReclaimState::Absent => ("CLEARED", Settled::Absent),
        ReclaimState::Removed => ("REMOVED", Settled::Removed),
        ReclaimState::Retained => ("RETAINED", Settled::Retained),
        ReclaimState::Foreign => ("FOREIGN", Settled::Foreign),
    };
    let changed = work.db(work.tx.execute(
        "UPDATE tool_staging SET state = ?2, holds = ?3, held_device = ?4, held_inode = ?5, \
         settled_ms = ?6 WHERE invocation_id = ?1 AND state = 'EXPECTED'",
        rusqlite::params![
            pending.invocation.as_str(),
            stored,
            holds.map(StagingHolds::as_str),
            held.map(|h| h.0.to_string()),
            held.map(|h| h.1.to_string()),
            to_sql(work.now)?
        ],
    ))?;
    if changed != 1 {
        return Ok(None);
    }
    work.audit(
        AuditEvent::ToolStagingSettled,
        Fields::new()
            .text("invocation_id", pending.invocation.as_str())
            .text("run_id", pending.run.clone())
            .text("operation", pending.spec.operation.as_str())
            .text("staging_directory", directory_name(&pending.invocation))
            .text("staging_parent", pending.parent_path.clone())
            .text("staging", stored)
            .maybe_text("holds", holds.map(|h| h.as_str().to_owned()))
            .maybe_text("held_device", held.map(|h| h.0.to_string()))
            .maybe_text("held_inode", held.map(|h| h.1.to_string())),
    )?;
    Ok(Some(settled))
}

#[cfg(test)]
mod tests {
    use super::parent_of;

    #[test]
    fn a_staging_directory_is_beside_the_name_in_the_workspace() {
        assert_eq!(parent_of("/workspace/a").as_deref(), Some("/workspace"));
        assert_eq!(parent_of("/workspace/a/b").as_deref(), Some("/workspace/a"));
        assert_eq!(parent_of("/workspace"), None, "the root has no parent here");
        assert_eq!(parent_of("/workspacex/a"), None);
    }
}
