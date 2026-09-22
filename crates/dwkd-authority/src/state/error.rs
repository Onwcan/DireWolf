//! Errors of the durable authority state.
//!
//! Three families, because a caller must treat them differently:
//!
//! * A **refusal** is not an error. It is a well-formed answer —
//!   `STALE_EPOCH`, `LEASE_HELD`, … — returned as
//!   [`Reply::Refused`](super::Reply::Refused), and it goes back to the peer.
//! * An [`AuthorityError`] means the authority could not answer at all. No
//!   authority was granted, and the caller receives none. Some of these
//!   **poison** the store: every later operation fails fast without touching
//!   the files.
//! * A [`StartError`] means the authority refused to start. It never "starts
//!   anyway" on an empty store: a store that cannot be proven sound stays shut
//!   until an operator intervenes.

use core::fmt;

use super::crash::CrashPoint;

/// Why a store stopped accepting operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoisonReason {
    /// SQLite reported `SQLITE_CORRUPT`: structural damage to `kernel.db`.
    Corrupt,
    /// SQLite reported `SQLITE_NOTADB`: `kernel.db` is not a database.
    NotADatabase,
    /// SQLite reported an I/O error. The transaction was rolled back, but the
    /// file's state after a failed write or sync is exactly what nobody should
    /// guess about.
    StorageIo,
    /// Writing or syncing `audit.log` failed. After a failed `fsync` a later
    /// `fsync` can succeed without the data being durable, so no retry is
    /// believed; recovery on the next start re-verifies the whole log.
    AuditIo,
    /// `audit.log` and `kernel.db` disagree about the chain.
    AuditDiverged(String),
    /// A crash hook stopped an operation at this point. The in-process
    /// equivalent of the process having died there.
    Interrupted(CrashPoint),
}

impl PoisonReason {
    /// Whether this is **structural** damage, which writes a durable
    /// quarantine marker beside the store so that a restart refuses too.
    ///
    /// An I/O failure or an interruption is not: the next start re-verifies
    /// everything from the files, and refuses if the verification fails.
    #[must_use]
    pub const fn is_structural(&self) -> bool {
        matches!(
            self,
            Self::Corrupt | Self::NotADatabase | Self::AuditDiverged(_)
        )
    }
}

impl fmt::Display for PoisonReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => f.write_str("kernel.db is structurally corrupt (SQLITE_CORRUPT)"),
            Self::NotADatabase => f.write_str("kernel.db is not a database (SQLITE_NOTADB)"),
            Self::StorageIo => f.write_str("kernel.db reported an I/O error"),
            Self::AuditIo => f.write_str("audit.log could not be written or synced"),
            Self::AuditDiverged(why) => write!(f, "audit.log disagrees with kernel.db: {why}"),
            Self::Interrupted(point) => {
                write!(f, "an operation was stopped at crash point {point}")
            }
        }
    }
}

/// The authority could not answer.
///
/// In every case, **no authority was returned to the caller.** An operation
/// that failed after its transaction committed (a crash window, an audit I/O
/// error) may have recorded authority in `kernel.db`; the caller does not hold
/// it, the audit record is pending, and recovery makes both consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// The store is poisoned. Nothing touched the files.
    Poisoned(PoisonReason),
    /// Another writer held the database for longer than the busy timeout.
    /// The transaction did not happen.
    Busy,
    /// A database constraint refused the write: a trigger guarding an
    /// append-only table or a monotonic column, or a uniqueness violation.
    /// That is a bug or an attack, and it failed closed.
    Rejected(String),
    /// `kernel.db` holds state that contradicts an invariant this module
    /// maintains. Fail closed rather than guess which half is wrong.
    Invariant(&'static str),
    /// Every id this store can mint has been minted.
    IdSpaceExhausted,
    /// The session's epoch has reached the largest value the wire can carry.
    /// It is never wrapped and never reset; the session can no longer be
    /// leased.
    EpochExhausted,
    /// The message is not one of the six authority requests.
    NotAnAuthorityRequest,
    /// Any other SQLite failure, rolled back.
    Sqlite(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned(why) => write!(f, "the authority store is poisoned: {why}"),
            Self::Busy => f.write_str("kernel.db was busy past the timeout"),
            Self::Rejected(why) => write!(f, "kernel.db refused the write: {why}"),
            Self::Invariant(what) => write!(f, "kernel.db violates an invariant: {what}"),
            Self::IdSpaceExhausted => f.write_str("the store's id counter is exhausted"),
            Self::EpochExhausted => f.write_str("the session's epoch counter is exhausted"),
            Self::NotAnAuthorityRequest => f.write_str("not an authority request"),
            Self::Sqlite(why) => write!(f, "kernel.db: {why}"),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// The authority refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// Another authority holds the state directory's lock.
    Locked,
    /// A quarantine marker is present. An operator must investigate and remove
    /// it; the authority never clears it itself.
    Quarantined(String),
    /// The state directory or a state file is not private to the authority.
    Permissions(String),
    /// A state file is missing, or present when it must not be. The store is
    /// never recreated around a missing piece.
    Layout(String),
    /// `kernel.db` is a SQLite database, and not a DireWolf kernel store.
    ForeignDatabase,
    /// `kernel.db` was written by a newer build.
    FutureSchema {
        /// The version found.
        found: i64,
        /// The newest version this build understands.
        supported: i64,
    },
    /// The schema metadata or the schema itself is not what that version
    /// defines.
    MalformedSchema(String),
    /// Structural corruption was found while opening or verifying.
    Corrupt(String),
    /// A migration failed and was rolled back.
    Migration(String),
    /// `audit.log` could not be reconciled with `kernel.db`.
    Audit(String),
    /// The configured policy did not load, compose or install.
    Policy(String),
    /// The configured mode ceiling, flags or lease TTL are invalid.
    Configuration(String),
    /// A filesystem operation failed.
    Io(String),
    /// A SQLite operation failed.
    Sqlite(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("another authority holds the state directory"),
            Self::Quarantined(why) => write!(f, "the store is quarantined: {why}"),
            Self::Permissions(why) => write!(f, "state is not private: {why}"),
            Self::Layout(why) => write!(f, "state directory layout: {why}"),
            Self::ForeignDatabase => f.write_str("kernel.db is not a DireWolf kernel store"),
            Self::FutureSchema { found, supported } => write!(
                f,
                "kernel.db schema version {found} is newer than this build supports ({supported})"
            ),
            Self::MalformedSchema(why) => write!(f, "kernel.db schema: {why}"),
            Self::Corrupt(why) => write!(f, "kernel.db is corrupt: {why}"),
            Self::Migration(why) => write!(f, "kernel.db migration failed and rolled back: {why}"),
            Self::Audit(why) => write!(f, "audit.log: {why}"),
            Self::Policy(why) => write!(f, "policy: {why}"),
            Self::Configuration(why) => write!(f, "configuration: {why}"),
            Self::Io(why) => write!(f, "I/O: {why}"),
            Self::Sqlite(why) => write!(f, "SQLite: {why}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<AuthorityError> for StartError {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Poisoned(
                reason @ (PoisonReason::Corrupt | PoisonReason::NotADatabase),
            ) => Self::Corrupt(reason.to_string()),
            AuthorityError::Poisoned(PoisonReason::AuditDiverged(why)) => Self::Audit(why),
            other => Self::Sqlite(other.to_string()),
        }
    }
}
