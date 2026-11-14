//! Who may hold a session, use a workspace and run under an agent profile
//! (F-18, [ADR-0063], Proposed).
//!
//! # The principal is the kernel's uid
//!
//! A principal is an [`AuthenticatedSubject`]: the uid the kernel reported
//! for the peer, never anything a message says. Being an allowed peer
//! (`--allow-uid`) lets a uid *speak* to the authority; it no longer lets it
//! act on every session, workspace and profile the store holds.
//!
//! # What a subject may hold
//!
//! | record | made by | means |
//! |---|---|---|
//! | `session_owner` | the operator, the single-principal adoption, or a **new** session's first acquirer | the session's one owner, fixed for its life; revoking it retires the session |
//! | `session_delegate` | the operator | another subject that may hold the session |
//! | `workspace_principal` | the operator | a subject whose sessions may be bound to the workspace and held while bound |
//! | `profile_principal` | the operator | a subject that may name the profile in `AdmitRun` |
//! | `workspace_root_share` | the operator | a workspace whose root more than one principal reaches |
//!
//! A subject may hold a session ([`standing`]) only as its owner or an
//! active delegate, only while its owner stands, and -- for a session bound
//! to a workspace -- only while it is an active principal of that workspace.
//! A session nobody owns is claimed by its first acquirer only when it is
//! new: never held, never bound, and not one the store held before schema
//! 14 (`legacy_session`). Everything else refuses: a legacy or bound session
//! without a declared owner is `SESSION_UNOWNED` until the operator declares
//! one.
//!
//! Refusals reuse the public reasons: a session the subject may not hold is
//! `LEASE_HELD`, a profile it may not run under `UNKNOWN_AGENT_PROFILE`.
//! Neither says whether the session or the profile exists; the audit record
//! names the ownership reason for the operator.
//!
//! # History is never authority
//!
//! `ownership_observation` holds what the store's history showed when it
//! was migrated -- lease holders, run subjects, profile and workspace use,
//! conflicts. One module reads it, [`super::adoption`], and only to
//! **refuse**; no decision here reads it, and a boundary rule (TX064)
//! keeps every other source file from naming it.
//!
//! # Revocation is two-phase
//!
//! [`revoke`] is the first phase, in one transaction: the grant is revoked,
//! every live lease the affected subjects hold on the affected sessions is
//! invalidated, their active runs are reaped (cause `principal_revoked`), the
//! destruction of each run's live environment is recorded (`REVOKED`), and
//! the revocation and its runs are recorded. From that commit nothing the
//! subject sends passes the fence or the ownership check. The second phase --
//! the broker removing each environment -- happens after the commit
//! ([`super::Authority`]), and [`report`] reads whether it is complete. Until
//! an environment is removed, a workload already running in it keeps what
//! its launch was granted.
//!
//! [ADR-0063]: ../../../../../docs/adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md

use dwk_proto::wire::id::{RunId, SessionId};
use dwk_proto::wire::scalar::AgentProfileName;
use rusqlite::{Connection, OptionalExtension as _};

use super::Work;
use super::audit::{AuditEvent, Fields};
use super::config::{ConfigError, WorkspaceId};
use super::environment;
use super::error::AuthorityError;
use super::identity::AuthenticatedSubject;
use super::lease::{self, Teardown};

/// Why a subject may not hold a session. The answer is `LEASE_HELD`
/// whichever it is; the audit record says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The session has an owner, and the subject is neither it nor an
    /// active delegate.
    NotPermitted,
    /// The session is legacy, bound, or already held, and nobody has been
    /// declared its owner.
    Unowned,
    /// The session's owner was revoked: nobody holds it again.
    Retired,
    /// The session is bound to a workspace the subject is not an active
    /// principal of.
    WorkspaceNotPermitted,
}

impl Refusal {
    /// The audit spelling.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NotPermitted => "SESSION_NOT_PERMITTED",
            Self::Unowned => "SESSION_UNOWNED",
            Self::Retired => "SESSION_RETIRED",
            Self::WorkspaceNotPermitted => "WORKSPACE_NOT_PERMITTED",
        }
    }
}

/// What a subject's standing on a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// It may hold the session.
    Permitted,
    /// Nobody owns the session and it is new: its first acquirer owns it.
    Claimable,
    /// It may not.
    Refused(Refusal),
}

/// The subject's standing on `session`, from the ownership records alone.
pub(super) fn standing(
    work: &Work<'_>,
    subject: AuthenticatedSubject,
    session: &SessionId,
) -> Result<Standing, AuthorityError> {
    let key = subject.storage_key();
    let owner: Option<(String, Option<i64>)> = work.db(work
        .tx
        .query_row(
            "SELECT subject, revoked_ms FROM session_owner WHERE session_id = ?1",
            [session.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let Some((owner, revoked)) = owner else {
        // Nobody owns it: only a session never seen before is claimable.
        let seen: bool = work.db(work.tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM legacy_session WHERE session_id = ?1) \
             OR EXISTS (SELECT 1 FROM session_workspace WHERE session_id = ?1) \
             OR EXISTS (SELECT 1 FROM session_lease WHERE session_id = ?1)",
            [session.as_str()],
            |row| row.get(0),
        ))?;
        return Ok(if seen {
            Standing::Refused(Refusal::Unowned)
        } else {
            Standing::Claimable
        });
    };
    if revoked.is_some() {
        return Ok(Standing::Refused(Refusal::Retired));
    }
    let named = owner == key
        || work.db(work.tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM session_delegate WHERE session_id = ?1 \
             AND subject = ?2 AND revoked_ms IS NULL)",
            rusqlite::params![session.as_str(), key],
            |row| row.get(0),
        ))?;
    if !named {
        return Ok(Standing::Refused(Refusal::NotPermitted));
    }
    let in_workspace: bool = work.db(work.tx.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM session_workspace w WHERE w.session_id = ?1 \
         AND NOT EXISTS (SELECT 1 FROM workspace_principal p \
                         WHERE p.workspace_id = w.workspace_id AND p.subject = ?2 \
                           AND p.revoked_ms IS NULL))",
        rusqlite::params![session.as_str(), key],
        |row| row.get(0),
    ))?;
    Ok(if in_workspace {
        Standing::Permitted
    } else {
        Standing::Refused(Refusal::WorkspaceNotPermitted)
    })
}

/// Record a new session's first acquirer as its owner, in the transaction
/// that grants it the session's first lease.
pub(super) fn record_first_acquirer(
    work: &mut Work<'_>,
    subject: AuthenticatedSubject,
    session: &SessionId,
) -> Result<(), AuthorityError> {
    let key = subject.storage_key();
    work.db(work.tx.execute(
        "INSERT INTO session_owner (session_id, subject, basis, recorded_ms) \
         VALUES (?1, ?2, 'FIRST_ACQUIRER', ?3)",
        rusqlite::params![session.as_str(), key, lease::to_sql(work.now)?],
    ))?;
    work.audit(
        AuditEvent::OwnershipDeclared,
        Fields::new()
            .text("kind", "SESSION_OWNER")
            .text("resource", session.as_str())
            .text("subject", key)
            .text("basis", "FIRST_ACQUIRER"),
    )
}

/// Whether `subject` may name `profile` in `AdmitRun`: an active grant, and
/// nothing else.
pub(super) fn profile_permitted(
    work: &Work<'_>,
    subject: AuthenticatedSubject,
    profile: &str,
) -> Result<bool, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM profile_principal WHERE profile = ?1 AND subject = ?2 \
         AND revoked_ms IS NULL)",
        rusqlite::params![profile, subject.storage_key()],
        |row| row.get(0),
    ))
}

/// Whether `run` was reaped by a revocation.
pub(super) fn revoked_run(work: &Work<'_>, run: &RunId) -> Result<bool, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM ownership_revocation_run WHERE run_id = ?1)",
        [run.as_str()],
        |row| row.get(0),
    ))
}

// ---------------------------------------------------------------------------
// The operator's declarations: in-process only, each audited.
// ---------------------------------------------------------------------------

#[expect(
    clippy::needless_pass_by_value,
    reason = "written point-free as `.map_err(sql)`, which passes the error by value"
)]
pub(super) fn sql(error: rusqlite::Error) -> ConfigError {
    ConfigError::Authority(super::db::to_error(&super::db::classify(&error)))
}

fn declared(
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
    kind: &'static str,
    resource: &str,
    subject: Option<&str>,
    basis: &'static str,
) -> Result<(), ConfigError> {
    let mut fields = Fields::new()
        .text("kind", kind)
        .text("resource", resource)
        .text("basis", basis);
    if let Some(subject) = subject {
        fields = fields.text("subject", subject);
    }
    audit(AuditEvent::OwnershipDeclared, fields).map_err(ConfigError::Authority)
}

fn workspace_known(tx: &Connection, workspace: &WorkspaceId) -> Result<(), ConfigError> {
    let known: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM workspace WHERE workspace_id = ?1)",
            [workspace.as_str()],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if known {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "no workspace `{workspace}` is installed"
        )))
    }
}

fn is_workspace_principal(
    tx: &Connection,
    workspace: &str,
    subject: &str,
) -> Result<bool, ConfigError> {
    tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM workspace_principal WHERE workspace_id = ?1 \
         AND subject = ?2 AND revoked_ms IS NULL)",
        rusqlite::params![workspace, subject],
        |row| row.get(0),
    )
    .map_err(sql)
}

/// The workspace a session is bound to, if it is.
fn bound_workspace(tx: &Connection, session: &str) -> Result<Option<String>, ConfigError> {
    tx.query_row(
        "SELECT workspace_id FROM session_workspace WHERE session_id = ?1",
        [session],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql)
}

/// A root reached by more than one principal is shared, and every workspace
/// bound to it must say so: the operator's acknowledgement, not an
/// accident of two grants. Checked after a grant or a root binding, in its
/// transaction, so a refusal writes nothing.
pub(super) fn check_root_sharing(
    tx: &Connection,
    workspace: &WorkspaceId,
) -> Result<(), ConfigError> {
    let (principals, unacknowledged): (i64, i64) = tx
        .query_row(
            "WITH same AS (SELECT r2.workspace_id FROM workspace_root r1 JOIN workspace_root r2 \
                           ON r2.root_device = r1.root_device AND r2.root_inode = r1.root_inode \
                           WHERE r1.workspace_id = ?1 \
                           UNION SELECT ?1) \
             SELECT (SELECT count(DISTINCT subject) FROM workspace_principal \
                     WHERE revoked_ms IS NULL \
                       AND workspace_id IN (SELECT workspace_id FROM same)), \
                    (SELECT count(*) FROM same WHERE workspace_id NOT IN \
                     (SELECT workspace_id FROM workspace_root_share))",
            [workspace.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql)?;
    if principals > 1 && unacknowledged > 0 {
        return Err(ConfigError::Invalid(format!(
            "the root of workspace `{workspace}` would be reached by more than one principal; \
             acknowledge that it is shared on every workspace bound to it first"
        )));
    }
    Ok(())
}

/// Grant `subject` the workspace. Idempotent for an active grant.
pub(super) fn grant_workspace_principal(
    tx: &Connection,
    now_ms: i64,
    workspace: &WorkspaceId,
    subject: AuthenticatedSubject,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    workspace_known(tx, workspace)?;
    let key = subject.storage_key();
    if is_workspace_principal(tx, workspace.as_str(), &key)? {
        return Ok(());
    }
    let (others, acknowledged): (bool, bool) = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM workspace_principal WHERE workspace_id = ?1 \
                            AND revoked_ms IS NULL AND subject <> ?2), \
                    EXISTS (SELECT 1 FROM workspace_root_share WHERE workspace_id = ?1)",
            rusqlite::params![workspace.as_str(), key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql)?;
    if others && !acknowledged {
        return Err(ConfigError::Invalid(format!(
            "workspace `{workspace}` already has a principal; acknowledge that its root is \
             shared before granting another"
        )));
    }
    tx.execute(
        "INSERT INTO workspace_principal (workspace_id, subject, granted_ms) VALUES (?1, ?2, ?3)",
        rusqlite::params![workspace.as_str(), key, now_ms],
    )
    .map_err(sql)?;
    check_root_sharing(tx, workspace)?;
    declared(
        audit,
        "WORKSPACE_PRINCIPAL",
        workspace.as_str(),
        Some(&key),
        "OPERATOR",
    )
}

/// Acknowledge that the workspace's root is shared by its principals.
pub(super) fn acknowledge_root_share(
    tx: &Connection,
    now_ms: i64,
    workspace: &WorkspaceId,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    workspace_known(tx, workspace)?;
    let inserted = tx
        .execute(
            "INSERT INTO workspace_root_share (workspace_id, acknowledged_ms) VALUES (?1, ?2) \
             ON CONFLICT (workspace_id) DO NOTHING",
            rusqlite::params![workspace.as_str(), now_ms],
        )
        .map_err(sql)?;
    if inserted == 0 {
        return Ok(());
    }
    declared(audit, "ROOT_SHARE", workspace.as_str(), None, "OPERATOR")
}

/// Grant `subject` the profile. Idempotent for an active grant.
pub(super) fn grant_profile_principal(
    tx: &Connection,
    now_ms: i64,
    profile: &AgentProfileName,
    subject: AuthenticatedSubject,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let key = subject.storage_key();
    let (installed, granted): (bool, bool) = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM agent_profile WHERE name = ?1), \
                    EXISTS (SELECT 1 FROM profile_principal WHERE profile = ?1 AND subject = ?2 \
                            AND revoked_ms IS NULL)",
            rusqlite::params![profile.as_str(), key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql)?;
    if !installed {
        return Err(ConfigError::Invalid(format!(
            "no agent profile `{}` is installed",
            profile.as_str()
        )));
    }
    if granted {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO profile_principal (profile, subject, granted_ms) VALUES (?1, ?2, ?3)",
        rusqlite::params![profile.as_str(), key, now_ms],
    )
    .map_err(sql)?;
    declared(
        audit,
        "PROFILE_PRINCIPAL",
        profile.as_str(),
        Some(&key),
        "OPERATOR",
    )
}

/// Declare `subject` the owner of `session`: a legacy session, or one not
/// yet acquired. Idempotent for the same standing owner; any other owner is
/// refused, because an owner is fixed for the session's life.
pub(super) fn declare_session_owner(
    tx: &Connection,
    now_ms: i64,
    session: &SessionId,
    subject: AuthenticatedSubject,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let key = subject.storage_key();
    let current: Option<(String, Option<i64>)> = tx
        .query_row(
            "SELECT subject, revoked_ms FROM session_owner WHERE session_id = ?1",
            [session.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    match current {
        Some((owner, None)) if owner == key => return Ok(()),
        Some((_, Some(_))) => {
            return Err(ConfigError::Invalid(format!(
                "session {} is retired: its owner was revoked",
                session.as_str()
            )));
        }
        Some(_) => {
            return Err(ConfigError::Invalid(format!(
                "session {} already has an owner, fixed for its life",
                session.as_str()
            )));
        }
        None => {}
    }
    if let Some(workspace) = bound_workspace(tx, session.as_str())?
        && !is_workspace_principal(tx, &workspace, &key)?
    {
        return Err(ConfigError::Invalid(format!(
            "session {} is bound to workspace `{workspace}`, of which {key} is not a principal",
            session.as_str()
        )));
    }
    tx.execute(
        "INSERT INTO session_owner (session_id, subject, basis, recorded_ms) \
         VALUES (?1, ?2, 'OPERATOR', ?3)",
        rusqlite::params![session.as_str(), key, now_ms],
    )
    .map_err(sql)?;
    declared(
        audit,
        "SESSION_OWNER",
        session.as_str(),
        Some(&key),
        "OPERATOR",
    )
}

/// Let `subject` hold `session` beside its owner. Idempotent for an active
/// delegate.
pub(super) fn add_session_delegate(
    tx: &Connection,
    now_ms: i64,
    session: &SessionId,
    subject: AuthenticatedSubject,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let key = subject.storage_key();
    let owner: Option<String> = tx
        .query_row(
            "SELECT subject FROM session_owner WHERE session_id = ?1 AND revoked_ms IS NULL",
            [session.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(owner) = owner else {
        return Err(ConfigError::Invalid(format!(
            "session {} has no standing owner to delegate for",
            session.as_str()
        )));
    };
    if owner == key {
        return Err(ConfigError::Invalid(format!(
            "{key} owns session {}; a delegate is another subject",
            session.as_str()
        )));
    }
    if let Some(workspace) = bound_workspace(tx, session.as_str())?
        && !is_workspace_principal(tx, &workspace, &key)?
    {
        return Err(ConfigError::Invalid(format!(
            "session {} is bound to workspace `{workspace}`, of which {key} is not a principal",
            session.as_str()
        )));
    }
    let active: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM session_delegate WHERE session_id = ?1 \
             AND subject = ?2 AND revoked_ms IS NULL)",
            rusqlite::params![session.as_str(), key],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if active {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO session_delegate (session_id, subject, granted_ms) VALUES (?1, ?2, ?3)",
        rusqlite::params![session.as_str(), key, now_ms],
    )
    .map_err(sql)?;
    declared(
        audit,
        "SESSION_DELEGATE",
        session.as_str(),
        Some(&key),
        "OPERATOR",
    )
}

/// What binding `session` to `workspace` needs (F-18): a standing owner who
/// is an active principal of the workspace, and every active delegate one
/// too.
pub(super) fn check_binding(
    tx: &Connection,
    session: &str,
    workspace: &WorkspaceId,
) -> Result<(), ConfigError> {
    let owner: Option<String> = tx
        .query_row(
            "SELECT subject FROM session_owner WHERE session_id = ?1 AND revoked_ms IS NULL",
            [session],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(owner) = owner else {
        return Err(ConfigError::Invalid(format!(
            "session {session} has no owner; declare its owner, a principal of workspace \
             `{workspace}`, before binding it"
        )));
    };
    if !is_workspace_principal(tx, workspace.as_str(), &owner)? {
        return Err(ConfigError::Invalid(format!(
            "the owner of session {session}, {owner}, is not a principal of workspace \
             `{workspace}`"
        )));
    }
    let outside: i64 = tx
        .query_row(
            "SELECT count(*) FROM session_delegate d WHERE d.session_id = ?1 \
             AND d.revoked_ms IS NULL AND NOT EXISTS (SELECT 1 FROM workspace_principal p \
                 WHERE p.workspace_id = ?2 AND p.subject = d.subject AND p.revoked_ms IS NULL)",
            rusqlite::params![session, workspace.as_str()],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if outside > 0 {
        return Err(ConfigError::Invalid(format!(
            "a delegate of session {session} is not a principal of workspace `{workspace}`"
        )));
    }
    Ok(())
}

pub(super) fn changed(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// What ownership is missing, and so refuses until it is declared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnershipGaps {
    /// Sessions the store held before schema 14 that no owner has been
    /// declared for.
    pub legacy_sessions_undeclared: u64,
    /// Sessions bound to a workspace without a standing owner.
    pub bound_sessions_unowned: u64,
    /// Workspaces no active principal holds.
    pub workspaces_without_principal: u64,
    /// Agent profiles no active principal may run under.
    pub profiles_without_principal: u64,
}

impl OwnershipGaps {
    /// Whether nothing is missing.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.legacy_sessions_undeclared == 0
            && self.bound_sessions_unowned == 0
            && self.workspaces_without_principal == 0
            && self.profiles_without_principal == 0
    }
}

fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// What ownership is missing now.
pub(super) fn gaps(work: &Work<'_>) -> Result<OwnershipGaps, AuthorityError> {
    let (legacy, bound, workspaces, profiles): (i64, i64, i64, i64) =
        work.db(work.tx.query_row(
            "SELECT (SELECT count(*) FROM legacy_session l WHERE NOT EXISTS \
                 (SELECT 1 FROM session_owner o WHERE o.session_id = l.session_id)), \
                (SELECT count(*) FROM session_workspace s WHERE NOT EXISTS \
                 (SELECT 1 FROM session_owner o WHERE o.session_id = s.session_id \
                  AND o.revoked_ms IS NULL)), \
                (SELECT count(*) FROM workspace w WHERE NOT EXISTS \
                 (SELECT 1 FROM workspace_principal p WHERE p.workspace_id = w.workspace_id \
                  AND p.revoked_ms IS NULL)), \
                (SELECT count(*) FROM (SELECT DISTINCT name FROM agent_profile) a WHERE NOT EXISTS \
                 (SELECT 1 FROM profile_principal p WHERE p.profile = a.name \
                  AND p.revoked_ms IS NULL))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ))?;
    Ok(OwnershipGaps {
        legacy_sessions_undeclared: count(legacy),
        bound_sessions_unowned: count(bound),
        workspaces_without_principal: count(workspaces),
        profiles_without_principal: count(profiles),
    })
}

/// At start (OD-11): what is missing, recorded once. The authority starts
/// either way; whatever is missing refuses per request.
pub(super) fn report_gaps(work: &mut Work<'_>) -> Result<OwnershipGaps, AuthorityError> {
    let found = gaps(work)?;
    if !found.is_complete() {
        work.audit(
            AuditEvent::OwnershipIncomplete,
            Fields::new()
                .int(
                    "legacy_sessions_undeclared",
                    found.legacy_sessions_undeclared,
                )
                .int("bound_sessions_unowned", found.bound_sessions_unowned)
                .int(
                    "workspaces_without_principal",
                    found.workspaces_without_principal,
                )
                .int(
                    "profiles_without_principal",
                    found.profiles_without_principal,
                ),
        )?;
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// Revocation: the first phase.
// ---------------------------------------------------------------------------

/// What is revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Target {
    /// A session's owner: the session is retired, its delegates with it.
    SessionOwner(SessionId),
    /// One delegate of a session.
    SessionDelegate(SessionId, AuthenticatedSubject),
    /// One principal of a workspace.
    WorkspacePrincipal(WorkspaceId, AuthenticatedSubject),
    /// One principal of an agent profile.
    ProfilePrincipal(AgentProfileName, AuthenticatedSubject),
}

/// What the first phase did, and left to the broker.
#[derive(Debug)]
pub(super) struct Revoked {
    pub(super) id: i64,
    pub(super) teardown: Teardown,
}

/// The sessions and subjects whose leases and runs a revocation ends:
/// `None` for every subject.
type Affected = Vec<(String, Option<String>)>;

/// A grant just revoked: its kind, resource and subject, and what it ends.
type Granted = (&'static str, String, String, Affected);

/// Retire a session: revoke its owner, and its delegates with it.
fn retire(
    work: &Work<'_>,
    session: &SessionId,
    now: i64,
) -> Result<Result<Granted, String>, AuthorityError> {
    let owner: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT subject FROM session_owner WHERE session_id = ?1 AND revoked_ms IS NULL",
            [session.as_str()],
            |row| row.get(0),
        )
        .optional())?;
    let Some(owner) = owner else {
        return Ok(Err(format!(
            "session {} has no standing owner",
            session.as_str()
        )));
    };
    work.db(work.tx.execute(
        "UPDATE session_owner SET revoked_ms = ?2 WHERE session_id = ?1",
        rusqlite::params![session.as_str(), now],
    ))?;
    work.db(work.tx.execute(
        "UPDATE session_delegate SET revoked_ms = ?2 \
             WHERE session_id = ?1 AND revoked_ms IS NULL",
        rusqlite::params![session.as_str(), now],
    ))?;
    Ok(Ok((
        "SESSION_OWNER",
        session.as_str().to_owned(),
        owner,
        vec![(session.as_str().to_owned(), None)],
    )))
}

/// Revoke the grant, and record what it ends. `Ok(Err(why))` when there is
/// nothing to revoke; nothing is written then.
fn revoke_grant(
    work: &Work<'_>,
    target: &Target,
) -> Result<Result<Granted, String>, AuthorityError> {
    let now = lease::to_sql(work.now)?;
    Ok(match target {
        Target::SessionOwner(session) => return retire(work, session, now),
        Target::SessionDelegate(session, subject) => {
            let key = subject.storage_key();
            let revoked = work.db(work.tx.execute(
                "UPDATE session_delegate SET revoked_ms = ?3 \
                 WHERE session_id = ?1 AND subject = ?2 AND revoked_ms IS NULL",
                rusqlite::params![session.as_str(), key, now],
            ))?;
            if revoked == 0 {
                return Ok(Err(format!(
                    "{key} is not a delegate of session {}",
                    session.as_str()
                )));
            }
            Ok((
                "SESSION_DELEGATE",
                session.as_str().to_owned(),
                key.clone(),
                vec![(session.as_str().to_owned(), Some(key))],
            ))
        }
        Target::WorkspacePrincipal(workspace, subject) => {
            let key = subject.storage_key();
            let revoked = work.db(work.tx.execute(
                "UPDATE workspace_principal SET revoked_ms = ?3 \
                 WHERE workspace_id = ?1 AND subject = ?2 AND revoked_ms IS NULL",
                rusqlite::params![workspace.as_str(), key, now],
            ))?;
            if revoked == 0 {
                return Ok(Err(format!(
                    "{key} is not a principal of workspace `{workspace}`"
                )));
            }
            let sessions: Vec<String> = {
                let mut statement = work.db(work.tx.prepare(
                    "SELECT session_id FROM session_workspace WHERE workspace_id = ?1 \
                     ORDER BY session_id",
                ))?;
                let rows = work.db(statement.query_map([workspace.as_str()], |row| row.get(0)))?;
                work.db(rows.collect::<rusqlite::Result<_>>())?
            };
            Ok((
                "WORKSPACE_PRINCIPAL",
                workspace.as_str().to_owned(),
                key.clone(),
                sessions
                    .into_iter()
                    .map(|s| (s, Some(key.clone())))
                    .collect(),
            ))
        }
        Target::ProfilePrincipal(profile, subject) => {
            let key = subject.storage_key();
            let revoked = work.db(work.tx.execute(
                "UPDATE profile_principal SET revoked_ms = ?3 \
                 WHERE profile = ?1 AND subject = ?2 AND revoked_ms IS NULL",
                rusqlite::params![profile.as_str(), key, now],
            ))?;
            if revoked == 0 {
                return Ok(Err(format!(
                    "{key} is not a principal of agent profile `{}`",
                    profile.as_str()
                )));
            }
            Ok((
                "PROFILE_PRINCIPAL",
                profile.as_str().to_owned(),
                key,
                Vec::new(),
            ))
        }
    })
}

/// The runs a revocation reaps: on each affected session, those of the
/// affected subject (or of every subject); for a profile principal, the
/// subject's runs under that profile.
fn reap_affected(
    work: &Work<'_>,
    target: &Target,
    affected: &Affected,
) -> Result<Vec<(String, String)>, AuthorityError> {
    let now = lease::to_sql(work.now)?;
    let mut reaped = Vec::new();
    let mut collect = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Result<(), AuthorityError> {
        let mut statement = work.db(work.tx.prepare(sql))?;
        let rows = work.db(statement.query_map(params, |row| Ok((row.get(0)?, row.get(1)?))))?;
        let rows: Vec<(String, String)> = work.db(rows.collect::<rusqlite::Result<_>>())?;
        reaped.extend(rows);
        Ok(())
    };
    if let Target::ProfilePrincipal(profile, subject) = target {
        collect(
            "UPDATE run SET state = 'REAPED', ended_ms = ?3 \
             WHERE subject = ?1 AND agent_profile = ?2 AND state = 'ACTIVE' \
             RETURNING run_id, session_id",
            rusqlite::params![subject.storage_key(), profile.as_str(), now],
        )?;
    }
    for (session, subject) in affected {
        collect(
            "UPDATE run SET state = 'REAPED', ended_ms = ?3 \
             WHERE session_id = ?1 AND state = 'ACTIVE' AND (?2 IS NULL OR subject = ?2) \
             RETURNING run_id, session_id",
            rusqlite::params![session, subject, now],
        )?;
    }
    reaped.sort();
    Ok(reaped)
}

/// The first phase of a revocation, in the caller's one transaction. From
/// its commit the affected subjects hold nothing the grant gave them: no
/// live lease, no active run, and no live environment that is not being
/// destroyed. `Ok(Err(why))` when there is nothing to revoke.
pub(super) fn revoke(
    work: &mut Work<'_>,
    target: &Target,
) -> Result<Result<Revoked, String>, AuthorityError> {
    let (kind, resource, subject, affected) = match revoke_grant(work, target)? {
        Ok(revoked) => revoked,
        Err(why) => return Ok(Err(why)),
    };
    // The fence: every live lease the affected subjects hold on the
    // affected sessions ends now.
    let mut leases = 0u64;
    for (session, holder) in &affected {
        if let Some((holder, epoch)) = lease::invalidate_held(work, session, holder.as_deref())? {
            leases = leases.saturating_add(1);
            work.audit(
                AuditEvent::LeaseRevoked,
                Fields::new()
                    .text("session_id", session.as_str())
                    .text("subject", holder)
                    .int("epoch", epoch)
                    .text("revoked", kind),
            )?;
        }
    }
    // Their runs end, and with each its environment's destruction begins.
    let reaped = reap_affected(work, target, &affected)?;
    let mut teardown = Vec::new();
    for (run, session) in &reaped {
        let id =
            RunId::parse(run).ok_or(AuthorityError::Invariant("a stored run_id is malformed"))?;
        work.audit(
            AuditEvent::RunReaped,
            Fields::new()
                .text("session_id", session.as_str())
                .text("run_id", run.as_str())
                .text("cause", "principal_revoked"),
        )?;
        teardown.extend(environment::begin_run_end(work, &id, "REVOKED")?);
    }
    let runs = u64::try_from(reaped.len()).unwrap_or(u64::MAX);
    let id: i64 = work.db(work.tx.query_row(
        "INSERT INTO ownership_revocation (kind, resource, subject, leases_invalidated, \
         runs_reaped, revoked_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING revocation_id",
        rusqlite::params![
            kind,
            resource,
            subject,
            lease::to_sql(leases)?,
            lease::to_sql(runs)?,
            lease::to_sql(work.now)?
        ],
        |row| row.get(0),
    ))?;
    for (run, _) in &reaped {
        work.db(work.tx.execute(
            "INSERT INTO ownership_revocation_run (revocation_id, run_id) VALUES (?1, ?2)",
            rusqlite::params![id, run],
        ))?;
    }
    let pending = teardown
        .iter()
        .filter(|begun| matches!(begun, environment::DestroyBegun::Pending { .. }))
        .count();
    work.audit(
        AuditEvent::OwnershipRevoked,
        Fields::new()
            .int("revocation_id", u64::try_from(id).unwrap_or(0))
            .text("kind", kind)
            .text("resource", resource)
            .text("subject", subject)
            .int("leases_invalidated", leases)
            .int("runs_reaped", runs)
            .int("environments_destroying", changed(pending)),
    )?;
    Ok(Ok(Revoked { id, teardown }))
}

/// Whether a revocation's effects have ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The grant, the leases and the runs ended at the revocation's commit;
    /// an environment, a workload or a host process of a reaped run may
    /// still be running.
    Revoked,
    /// Every environment of every reaped run is gone, and none of their
    /// workloads or host processes is still running.
    Complete,
}

/// A revocation, as [`report`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationReport {
    /// Which revocation.
    pub revocation: i64,
    /// Whether it is complete.
    pub status: RevocationStatus,
    /// Live leases it invalidated.
    pub leases_invalidated: u64,
    /// Active runs it reaped.
    pub runs_reaped: u64,
    /// Environments of those runs not yet gone.
    pub environments_live: u64,
    /// Workloads of those runs still `LAUNCHING`.
    pub workloads_running: u64,
    /// Host processes of those runs still launching or running.
    pub processes_running: u64,
}

/// Read a revocation's state. `None` for one that does not exist.
pub(super) fn report(
    work: &Work<'_>,
    revocation: i64,
) -> Result<Option<RevocationReport>, AuthorityError> {
    let row: Option<(i64, i64, i64, i64, i64)> = work.db(work
        .tx
        .query_row(
            "SELECT leases_invalidated, runs_reaped, \
                    (SELECT count(*) FROM environment e JOIN ownership_revocation_run r \
                     ON r.run_id = e.run_id WHERE r.revocation_id = ?1 \
                     AND e.state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')), \
                    (SELECT count(*) FROM workload w JOIN ownership_revocation_run r \
                     ON r.run_id = w.run_id WHERE r.revocation_id = ?1 \
                     AND w.state = 'LAUNCHING'), \
                    (SELECT count(*) FROM tool_process p JOIN ownership_revocation_run r \
                     ON r.run_id = p.run_id WHERE r.revocation_id = ?1 \
                     AND p.state IN ('LAUNCHING', 'RUNNING')) \
             FROM ownership_revocation WHERE revocation_id = ?1",
            [revocation],
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
    Ok(
        row.map(|(leases, runs, environments, workloads, processes)| {
            let ended = environments == 0 && workloads == 0 && processes == 0;
            RevocationReport {
                revocation,
                status: if ended {
                    RevocationStatus::Complete
                } else {
                    RevocationStatus::Revoked
                },
                leases_invalidated: count(leases),
                runs_reaped: count(runs),
                environments_live: count(environments),
                workloads_running: count(workloads),
                processes_running: count(processes),
            }
        }),
    )
}
