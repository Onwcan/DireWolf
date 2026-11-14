//! The single-principal adoption (F-18, [ADR-0063], Proposed): the one
//! place that reads what a store's history showed, and only to refuse.
//!
//! A deployment with one runtime identity may declare it the principal of
//! every legacy session, workspace and agent profile in one audited operator
//! act. The act is refused -- and nothing written -- when the
//! `ownership_observation` the migration recorded shows any other subject or
//! any conflict, or when any ownership record names another subject: history
//! may stop an adoption, and never grants one. It never runs by itself.
//!
//! This is the only module that names `ownership_observation` besides the
//! schema (TX064): no authorization decision can come to read it.
//!
//! [ADR-0063]: ../../../../../docs/adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md

use rusqlite::Connection;

use super::audit::{AuditEvent, Fields};
use super::config::ConfigError;
use super::error::AuthorityError;
use super::identity::AuthenticatedSubject;
use super::ownership::{changed, sql};

/// What the single-principal adoption declared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Adoption {
    /// Legacy sessions it declared the principal's.
    pub sessions: u64,
    /// Workspaces it granted the principal.
    pub workspaces: u64,
    /// Agent profiles it granted the principal.
    pub profiles: u64,
}

/// The operator's statement that this store has exactly one runtime
/// principal: every legacy session, workspace and profile is declared
/// `subject`'s. Refused -- and nothing written -- when the store's history
/// shows any other subject or any ambiguity, or when any ownership record
/// names another subject. Never automatic.
pub(super) fn adopt_single_principal(
    tx: &Connection,
    now_ms: i64,
    subject: AuthenticatedSubject,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<Adoption, ConfigError> {
    let key = subject.storage_key();
    // History is read here, and only to refuse.
    let (history, records): (i64, i64) = tx
        .query_row(
            "SELECT (SELECT count(*) FROM ownership_observation \
                     WHERE subject <> ?1 OR ambiguous = 1), \
                    (SELECT count(*) FROM session_owner WHERE subject <> ?1) \
                    + (SELECT count(*) FROM session_delegate) \
                    + (SELECT count(*) FROM workspace_principal WHERE subject <> ?1) \
                    + (SELECT count(*) FROM profile_principal WHERE subject <> ?1)",
            [key.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql)?;
    if history > 0 {
        return Err(ConfigError::Invalid(format!(
            "the store's history shows a subject other than {key}, or a conflict \
             ({history} observations): declare ownership explicitly"
        )));
    }
    if records > 0 {
        return Err(ConfigError::Invalid(format!(
            "ownership records already name a subject other than {key} ({records}): declare \
             ownership explicitly"
        )));
    }
    let workspaces = tx
        .execute(
            "INSERT INTO workspace_principal (workspace_id, subject, granted_ms) \
             SELECT w.workspace_id, ?1, ?2 FROM workspace w WHERE NOT EXISTS \
             (SELECT 1 FROM workspace_principal p WHERE p.workspace_id = w.workspace_id \
              AND p.subject = ?1 AND p.revoked_ms IS NULL)",
            rusqlite::params![key, now_ms],
        )
        .map_err(sql)?;
    let profiles = tx
        .execute(
            "INSERT INTO profile_principal (profile, subject, granted_ms) \
             SELECT DISTINCT a.name, ?1, ?2 FROM agent_profile a WHERE NOT EXISTS \
             (SELECT 1 FROM profile_principal p WHERE p.profile = a.name AND p.subject = ?1 \
              AND p.revoked_ms IS NULL)",
            rusqlite::params![key, now_ms],
        )
        .map_err(sql)?;
    let sessions = tx
        .execute(
            "INSERT INTO session_owner (session_id, subject, basis, recorded_ms) \
             SELECT l.session_id, ?1, 'ADOPTED', ?2 FROM legacy_session l WHERE NOT EXISTS \
             (SELECT 1 FROM session_owner o WHERE o.session_id = l.session_id)",
            rusqlite::params![key, now_ms],
        )
        .map_err(sql)?;
    let adoption = Adoption {
        sessions: changed(sessions),
        workspaces: changed(workspaces),
        profiles: changed(profiles),
    };
    audit(
        AuditEvent::OwnershipAdopted,
        Fields::new()
            .text("subject", key)
            .int("sessions", adoption.sessions)
            .int("workspaces", adoption.workspaces)
            .int("profiles", adoption.profiles),
    )
    .map_err(ConfigError::Authority)?;
    Ok(adoption)
}
