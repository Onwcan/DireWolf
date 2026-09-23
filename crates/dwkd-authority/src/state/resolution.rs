//! Resolving a declared path for a run (M4a, [ADR-0042] §8–§10).
//!
//! The state layer owns *which* root a run resolves beneath: the run's
//! workspace, recorded at admission, and the root the operator bound to that
//! workspace. The resource layer owns *how*. So this module reads the binding
//! from `kernel.db`, and [`crate::resource::fs`] opens it, proves it is the
//! directory that was installed, and resolves beneath it — the store never
//! reaches the resolver and the resolver never reaches the store (TX005,
//! TX011).
//!
//! # Nothing on the wire reaches this
//!
//! These are in-process entry points. `ToolInvoke` and `CanonicalPreview` —
//! the first callers that will span the wire — are M4b's, and remain reserved
//! operations with no handler; `QueryAuthority` still answers a proposal with
//! `NO_CANONICAL_ACTION`, because a resolved path is one fact of a canonical
//! action, not all of them (ADR-0040).
//!
//! # Not audited
//!
//! A resolution is an internal step of a decision, not an effect and not a
//! decision ([ADR-0027]): no record is written for one, refused or not. The
//! operator's binding of a root *is* audited, when it is installed.
//!
//! [ADR-0027]: ../../../../../docs/adr/0027-audit-scope-boundary.md
//! [ADR-0042]: ../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

use core::fmt;

use rusqlite::OptionalExtension as _;

use crate::resource::fs::{ResolveError, RootError};

use super::Work;
use super::config::{self, RootBinding};
use super::error::AuthorityError;

/// Why a run's declared path was not resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionRefused {
    /// The kernel holds no such run.
    UnknownRun,
    /// The run has ended: its authority, and its claim on a root, ended with it.
    RunNotActive,
    /// The run's session is bound to no workspace, so `/workspace` means
    /// nothing for it.
    NoWorkspace,
    /// The run's workspace has no filesystem root bound.
    NoWorkspaceRoot,
    /// The bound root could not be pinned — above all
    /// [`RootError::Replaced`]: its path now names another directory.
    Root(RootError),
    /// The declared path did not resolve beneath the pinned root.
    Resolve(ResolveError),
    /// The authority could not answer.
    Authority(AuthorityError),
}

impl fmt::Display for ResolutionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRun => f.write_str("no such run"),
            Self::RunNotActive => f.write_str("the run is not active"),
            Self::NoWorkspace => f.write_str("the run has no workspace"),
            Self::NoWorkspaceRoot => f.write_str("the run's workspace has no bound root"),
            Self::Root(error) => write!(f, "the workspace root: {error}"),
            Self::Resolve(error) => write!(f, "{error}"),
            Self::Authority(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ResolutionRefused {}

impl From<AuthorityError> for ResolutionRefused {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

/// The root a run resolves beneath, if it has one: the run must be active,
/// its session bound to a workspace, and that workspace bound to a root.
pub(super) fn run_root(
    work: &Work<'_>,
    run: &str,
) -> Result<Result<RootBinding, ResolutionRefused>, AuthorityError> {
    let row: Option<(String, Option<String>)> = work.db(work
        .tx
        .query_row(
            "SELECT r.state, p.workspace_id FROM run r \
                 LEFT JOIN run_policy_input p ON p.run_id = r.run_id WHERE r.run_id = ?1",
            [run],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let Some((state, workspace)) = row else {
        return Ok(Err(ResolutionRefused::UnknownRun));
    };
    if state != "ACTIVE" {
        return Ok(Err(ResolutionRefused::RunNotActive));
    }
    let Some(workspace) = workspace else {
        return Ok(Err(ResolutionRefused::NoWorkspace));
    };
    Ok(config::workspace_root(work.tx, &workspace)?.ok_or(ResolutionRefused::NoWorkspaceRoot))
}

/// Whether a run's workspace has a bound root — the kernel-owned fact that
/// makes `${WORKSPACE}` resolvable for it.
pub(super) fn run_workspace_bound(work: &Work<'_>, run: &str) -> Result<bool, AuthorityError> {
    let workspace: Option<Option<String>> = work.db(work
        .tx
        .query_row(
            "SELECT workspace_id FROM run_policy_input WHERE run_id = ?1",
            [run],
            |row| row.get(0),
        )
        .optional())?;
    match workspace.flatten() {
        Some(workspace) => Ok(config::workspace_root(work.tx, &workspace)?.is_some()),
        None => Ok(false),
    }
}
