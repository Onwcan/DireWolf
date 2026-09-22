//! Session leases and epoch fencing ([ADR-0011]).
//!
//! # The epoch is `kernel.db`'s
//!
//! One row per session, never deleted, holding the session's **current epoch**
//! and, while a lease is live, its holder and absolute expiry. The runtime's
//! copy of the epoch is a cache ([`DATA_MODEL.md`] §3); this row is the value
//! every epoch-carrying request is fenced against.
//!
//! # `AcquireLease`
//!
//! | found | outcome |
//! |---|---|
//! | no row | epoch 1, held by the caller |
//! | held, unexpired, by **another** holder | `LEASE_HELD` |
//! | held, unexpired, by **this** holder | re-issued at `epoch + 1` |
//! | held and expired, released, or invalidated by a restart | `epoch + 1`, held by the caller |
//!
//! Every successful acquire therefore moves to an epoch **strictly greater**
//! than any the session has had, and a `BEFORE UPDATE` trigger refuses any
//! write that would begin a new tenure without one. The counter is never
//! reset and never wraps: at the wire's maximum (2^53 − 1) the session is
//! exhausted and acquisition fails closed.
//!
//! Re-issuing to the current holder is the one case that might look like
//! sharing, and is not: it is the same connection — the same single writer —
//! asking again, typically after losing a response. It gets a fresh epoch, which
//! fences any request it sent under the old one. It is a deliberate
//! **rotation**, with the same consequence as any other end of tenure: every
//! run admitted under the old epoch is reaped in the same transaction (cause
//! `lease_reacquired`), and a retry of such a run's admission key is
//! thereafter `ADMISSION_ENDED` (ADR-0040). A *different* connection from
//! the same authenticated subject is a different holder and gets `LEASE_HELD`:
//! the same uid is not evidence of the same writer.
//!
//! # The fence
//!
//! An epoch-carrying request passes only if **all** hold, checked before
//! anything else the operation does — idempotency included:
//!
//! 1. the session has a live lease,
//! 2. the presented epoch equals the current epoch,
//! 3. the caller is the lease's holder, and
//! 4. the lease has not expired.
//!
//! Any failure is `STALE_EPOCH`, one answer for all four, carrying nothing: the
//! refusal never distinguishes "wrong holder" from "no lease" from "expired",
//! and never reveals the current epoch ([ADR-0036] §10).
//!
//! # When a lease ends, its runs' authority ends
//!
//! A run is admitted under an epoch and fenced to it. When the lease that
//! epoch belonged to is released, rotated by its own holder, expires and is
//! re-acquired, or is invalidated by a restart, every active run admitted
//! under it is **reaped**:
//! its state becomes `REAPED`, its grants are no longer effective, and a
//! trigger guarantees it never becomes active again. Resuming work means a new
//! admission ([`RELIABILITY.md`] §7: "a run suspended for three days must not
//! resume on authority revoked yesterday").
//!
//! [ADR-0011]: ../../../../../docs/adr/0011-session-concurrency.md
//! [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
//! [`DATA_MODEL.md`]: ../../../../../docs/DATA_MODEL.md
//! [`RELIABILITY.md`]: ../../../../../docs/RELIABILITY.md

use dwk_proto::wire::id::SessionId;
use dwk_proto::wire::scalar::{Epoch, RefusalReason, RefusedOperation};
use rusqlite::OptionalExtension as _;

use super::audit::{AuditEvent, Fields};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::{Reply, Work};

/// A lease lives this long without a heartbeat ([`RELIABILITY.md`] §7a).
///
/// [`RELIABILITY.md`]: ../../../../../docs/RELIABILITY.md
pub const DEFAULT_LEASE_TTL_MS: u64 = 60_000;

/// The shortest configurable lease.
pub const MIN_LEASE_TTL_MS: u64 = 1_000;

/// The longest configurable lease.
pub const MAX_LEASE_TTL_MS: u64 = 600_000;

/// The largest epoch the wire can carry. Reaching it exhausts the session.
pub const MAX_EPOCH: u64 = Epoch::MAX;

/// A lease row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Lease {
    pub(super) epoch: u64,
    pub(super) state: String,
    pub(super) holder_subject: Option<String>,
    pub(super) holder: Option<(u64, u64)>,
    pub(super) expires_ms: Option<u64>,
    pub(super) last_holder: Option<(u64, u64)>,
}

/// One `session_lease` row, as SQLite returns it.
type LeaseRow = (
    i64,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn load(work: &Work<'_>, session: &SessionId) -> Result<Option<Lease>, AuthorityError> {
    let row: Option<LeaseRow> = work.db(work
        .tx
        .query_row(
            "SELECT epoch, state, holder_subject, holder_incarnation, holder_connection, \
                     expires_ms, last_holder_incarnation, last_holder_connection \
                     FROM session_lease WHERE session_id = ?1",
            [session.as_str()],
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
                ))
            },
        )
        .optional())?;
    let Some((epoch, state, subject, inc, conn, expires, last_inc, last_conn)) = row else {
        return Ok(None);
    };
    let pair = |a: Option<i64>, b: Option<i64>| -> Option<(u64, u64)> {
        Some((u64::try_from(a?).ok()?, u64::try_from(b?).ok()?))
    };
    Ok(Some(Lease {
        epoch: u64::try_from(epoch)
            .map_err(|_| AuthorityError::Invariant("a stored epoch is negative"))?,
        state,
        holder_subject: subject,
        holder: pair(inc, conn),
        expires_ms: expires.and_then(|e| u64::try_from(e).ok()),
        last_holder: pair(last_inc, last_conn),
    }))
}

fn holder_pair(caller: &CallerContext) -> (u64, u64) {
    (caller.holder().incarnation(), caller.holder().connection())
}

/// Whether `lease` is live, held by `caller`, at `epoch`, now.
fn fenced_ok(lease: &Lease, caller: &CallerContext, epoch: u64, now: u64) -> bool {
    lease.state == "HELD"
        && lease.epoch == epoch
        && lease.holder == Some(holder_pair(caller))
        && lease.holder_subject.as_deref() == Some(caller.subject().storage_key().as_str())
        && lease.expires_ms.is_some_and(|expires| expires > now)
}

/// The fence. `Ok(true)` when the request may proceed.
///
/// On failure the caller must audit the refusal and answer `STALE_EPOCH`, and
/// must not look at anything else first.
pub(super) fn fence(
    work: &Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    epoch: Epoch,
) -> Result<bool, AuthorityError> {
    Ok(load(work, session)?.is_some_and(|lease| fenced_ok(&lease, caller, epoch.get(), work.now)))
}

/// The audit record of a refusal: who asked, for what, and why. The presented
/// epoch is the caller's claim and is recorded as such; the current epoch is
/// **not** recorded here, because this record's fields mirror the answer.
pub(super) fn refusal_fields(
    caller: &CallerContext,
    operation: RefusedOperation,
    reason: RefusalReason,
    session: &SessionId,
    presented_epoch: Option<Epoch>,
) -> Fields {
    let fields = Fields::new()
        .text("operation", operation.as_str())
        .text("reason", reason.as_str())
        .text("subject", caller.subject().storage_key())
        .text("holder", caller.holder().to_string())
        .text("session_id", session.as_str());
    match presented_epoch {
        Some(epoch) => fields.int("presented_epoch", epoch.get()),
        None => fields,
    }
}

/// `AcquireLease`.
pub(super) fn acquire(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    ttl_ms: u64,
) -> Result<Reply<Epoch>, AuthorityError> {
    let now = work.now;
    let expires = now.saturating_add(ttl_ms);
    let (inc, conn) = holder_pair(caller);
    let current = load(work, session)?;

    let (epoch, prior) = match &current {
        None => (1, "none"),
        Some(lease) => {
            let live = lease.state == "HELD" && lease.expires_ms.is_some_and(|e| e > now);
            if live && lease.holder != Some((inc, conn)) {
                work.audit(
                    AuditEvent::LeaseRefused,
                    refusal_fields(
                        caller,
                        RefusedOperation::AcquireLease,
                        RefusalReason::LeaseHeld,
                        session,
                        None,
                    ),
                )?;
                return Ok(Reply::Refused(RefusalReason::LeaseHeld));
            }
            if lease.epoch >= MAX_EPOCH {
                return Err(AuthorityError::EpochExhausted);
            }
            let prior = match lease.state.as_str() {
                "HELD" if live => "reissued",
                "HELD" => "expired",
                "RELEASED" => "released",
                _ => "invalidated",
            };
            (lease.epoch.saturating_add(1), prior)
        }
    };
    let epoch_sql = to_sql(epoch)?;
    let subject = caller.subject().storage_key();
    if current.is_none() {
        work.db(work.tx.execute(
            "INSERT INTO session_lease (session_id, epoch, state, holder_subject, \
             holder_incarnation, holder_connection, expires_ms) \
             VALUES (?1, ?2, 'HELD', ?3, ?4, ?5, ?6)",
            rusqlite::params![
                session.as_str(),
                epoch_sql,
                subject,
                to_sql(inc)?,
                to_sql(conn)?,
                to_sql(expires)?
            ],
        ))?;
    } else {
        work.db(work.tx.execute(
            "UPDATE session_lease SET epoch = ?2, state = 'HELD', holder_subject = ?3, \
             holder_incarnation = ?4, holder_connection = ?5, expires_ms = ?6 \
             WHERE session_id = ?1",
            rusqlite::params![
                session.as_str(),
                epoch_sql,
                subject,
                to_sql(inc)?,
                to_sql(conn)?,
                to_sql(expires)?
            ],
        ))?;
        reap(work, session, epoch, "lease_reacquired")?;
    }
    work.audit(
        AuditEvent::LeaseAcquired,
        Fields::new()
            .text("subject", subject)
            .text("holder", caller.holder().to_string())
            .text("session_id", session.as_str())
            .int("epoch", epoch)
            .text("prior", prior)
            .int("expires_ms", expires),
    )?;
    Epoch::new(epoch)
        .map(Reply::Done)
        .ok_or(AuthorityError::EpochExhausted)
}

/// `Heartbeat`: renew a live lease by one TTL. Not audited on success — it
/// grants nothing new, and a record per renewal would be telemetry rather
/// than forensics. A fenced heartbeat is audited.
pub(super) fn heartbeat(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    epoch: Epoch,
    ttl_ms: u64,
) -> Result<Reply<()>, AuthorityError> {
    if !fence(work, caller, session, epoch)? {
        work.audit(
            AuditEvent::LeaseRefused,
            refusal_fields(
                caller,
                RefusedOperation::Heartbeat,
                RefusalReason::StaleEpoch,
                session,
                Some(epoch),
            ),
        )?;
        return Ok(Reply::Refused(RefusalReason::StaleEpoch));
    }
    let expires = work.now.saturating_add(ttl_ms);
    work.db(work.tx.execute(
        "UPDATE session_lease SET expires_ms = ?2 WHERE session_id = ?1",
        rusqlite::params![session.as_str(), to_sql(expires)?],
    ))?;
    Ok(Reply::Done(()))
}

/// `ReleaseLease`: surrender a live lease. Idempotent for its own holder: a
/// retry of a release that already happened, by the connection that released
/// it, at the epoch it released, is acknowledged rather than refused.
pub(super) fn release(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    epoch: Epoch,
) -> Result<Reply<()>, AuthorityError> {
    let lease = load(work, session)?;
    let pair = holder_pair(caller);
    if let Some(lease) = &lease {
        if fenced_ok(lease, caller, epoch.get(), work.now) {
            work.db(work.tx.execute(
                "UPDATE session_lease SET state = 'RELEASED', holder_subject = NULL, \
                 holder_incarnation = NULL, holder_connection = NULL, expires_ms = NULL, \
                 last_holder_incarnation = ?2, last_holder_connection = ?3 \
                 WHERE session_id = ?1",
                rusqlite::params![session.as_str(), to_sql(pair.0)?, to_sql(pair.1)?],
            ))?;
            reap(
                work,
                session,
                lease.epoch.saturating_add(1),
                "lease_released",
            )?;
            work.audit(
                AuditEvent::LeaseReleased,
                Fields::new()
                    .text("subject", caller.subject().storage_key())
                    .text("holder", caller.holder().to_string())
                    .text("session_id", session.as_str())
                    .int("epoch", lease.epoch),
            )?;
            return Ok(Reply::Done(()));
        }
        if lease.state == "RELEASED"
            && lease.epoch == epoch.get()
            && lease.last_holder == Some(pair)
        {
            return Ok(Reply::Done(()));
        }
    }
    work.audit(
        AuditEvent::LeaseRefused,
        refusal_fields(
            caller,
            RefusedOperation::ReleaseLease,
            RefusalReason::StaleEpoch,
            session,
            Some(epoch),
        ),
    )?;
    Ok(Reply::Refused(RefusalReason::StaleEpoch))
}

/// End every active run of `session` admitted under an epoch below
/// `below_epoch`. Each is audited.
fn reap(
    work: &mut Work<'_>,
    session: &SessionId,
    below_epoch: u64,
    cause: &'static str,
) -> Result<(), AuthorityError> {
    let reaped: Vec<String> = {
        let mut statement = work.db(work.tx.prepare(
            "UPDATE run SET state = 'REAPED', ended_ms = ?3 \
             WHERE session_id = ?1 AND state = 'ACTIVE' AND epoch < ?2 RETURNING run_id",
        ))?;
        let rows = work.db(statement.query_map(
            rusqlite::params![session.as_str(), to_sql(below_epoch)?, to_sql(work.now)?],
            |row| row.get::<_, String>(0),
        ))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    for run in reaped {
        work.audit(
            AuditEvent::RunReaped,
            Fields::new()
                .text("session_id", session.as_str())
                .text("run_id", run)
                .text("cause", cause),
        )?;
    }
    Ok(())
}

/// At startup: every live holder belonged to the previous process, so every
/// held lease is invalidated and every active run is reaped. Epochs are
/// untouched — the next acquire of each session moves strictly past them.
pub(super) fn invalidate_all(work: &Work<'_>) -> Result<(u64, u64), AuthorityError> {
    let leases = work.db(work.tx.execute(
        "UPDATE session_lease SET state = 'INVALIDATED', \
         last_holder_incarnation = holder_incarnation, last_holder_connection = holder_connection, \
         holder_subject = NULL, holder_incarnation = NULL, holder_connection = NULL, \
         expires_ms = NULL WHERE state = 'HELD'",
        [],
    ))?;
    let runs = work.db(work.tx.execute(
        "UPDATE run SET state = 'REAPED', ended_ms = ?1 WHERE state = 'ACTIVE'",
        [to_sql(work.now)?],
    ))?;
    Ok((
        u64::try_from(leases).unwrap_or(u64::MAX),
        u64::try_from(runs).unwrap_or(u64::MAX),
    ))
}

pub(super) fn to_sql(value: u64) -> Result<i64, AuthorityError> {
    i64::try_from(value).map_err(|_| AuthorityError::Invariant("a value exceeds i64"))
}
