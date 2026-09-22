//! Opening and configuring a `kernel.db` connection, and classifying what
//! SQLite reports.
//!
//! # Every pragma, and why
//!
//! Nothing security-relevant is left to a host or build default. Each setting
//! below is **set and then read back**, and a connection whose read-back
//! disagrees is refused: a pragma that silently did not apply is a durability
//! claim nobody is making.
//!
//! | setting | value | why |
//! |---|---|---|
//! | `journal_mode` | `WAL` | [ADR-0009]: readers never block the writer, and a commit is one append to the WAL. |
//! | `synchronous` | `FULL` | [`STORAGE.md`] §2: `kernel.db` holds authority; losing a committed lease or admission to a power cut is a security event. Under WAL, `FULL` syncs the WAL on every commit, so an acknowledged transaction survives power loss as far as the storage stack honours `fsync`. |
//! | `fullfsync` | `ON` | On Apple platforms `fsync` does not flush the drive's cache; `F_FULLFSYNC` does, and SQLite uses it only when told to. A no-op elsewhere. |
//! | `foreign_keys` | `ON` | Off by default in SQLite. The schema's `ON DELETE RESTRICT` edges are how security history refuses to disappear with the entity it describes ([`DATA_MODEL.md`] §6). |
//! | `busy_timeout` | 5 s | Several handles contend for one writer. `BEGIN IMMEDIATE` waits for the lock instead of failing at once; past the timeout the operation fails closed with [`AuthorityError::Busy`]. |
//! | `trusted_schema` | `OFF` | A schema object — a trigger, a view — may not call a function SQLite marks unsafe. The schema is ours, but a store read after tampering should not be able to run code by being read. |
//! | `mmap_size` | `0` | Memory-mapped reads turn an I/O error or a truncated file into a signal in the authority process. `read()` turns it into an error code this module can classify and poison on. |
//! | `DEFENSIVE` | on | Refuses the SQL-level operations that can corrupt a database on purpose (`writable_schema`, raw page writes). Nothing here needs them; a bug that reached for one should fail. |
//! | `NO_CKPT_ON_CLOSE` | on | Closing the last connection normally checkpoints the WAL into the main file. After corruption has poisoned the store, that checkpoint is how a recoverable problem becomes an unrecoverable one ([ADR-0009] point 4). Checkpoints still happen, automatically, while the store is healthy. |
//!
//! Left at SQLite's defaults, deliberately: `wal_autocheckpoint` (1000 pages;
//! the WAL stays bounded while healthy), `auto_vacuum` (`NONE`; the store is
//! append-mostly and never needs to shrink), and the cache and temp-store
//! sizes, which are performance rather than correctness.
//!
//! # No URI, no symlink
//!
//! The file is opened without `SQLITE_OPEN_URI`, so no query parameter in a
//! path can change how it is opened, and with `SQLITE_OPEN_NOFOLLOW`, so a
//! `kernel.db` that is a symlink is refused rather than followed.
//!
//! [ADR-0009]: ../../../../../docs/adr/0009-storage-strategy.md
//! [`STORAGE.md`]: ../../../../../docs/STORAGE.md
//! [`DATA_MODEL.md`]: ../../../../../docs/DATA_MODEL.md

use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags};

use super::error::{AuthorityError, PoisonReason};

/// How long a writer waits for another.
pub(super) const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Open an existing `kernel.db` for reading and writing.
///
/// Never creates one: the authority creates the file itself, private, before
/// SQLite sees it, so SQLite's own default file mode never applies.
pub(super) fn open(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )
}

/// Open `kernel.db` read-only, for verification. Nothing it does can write.
pub(super) fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )
}

/// Apply and verify every setting in the table above.
///
/// # Errors
///
/// A SQLite error, or a description of the setting whose read-back disagreed.
pub(super) fn configure(conn: &Connection) -> Result<(), ConfigureError> {
    set_flag(conn, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true, "DEFENSIVE")?;
    set_flag(
        conn,
        DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
        false,
        "TRUSTED_SCHEMA",
    )?;
    set_flag(
        conn,
        DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
        "NO_CKPT_ON_CLOSE",
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;

    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    expect("journal_mode", mode.eq_ignore_ascii_case("wal"), &mode)?;

    conn.pragma_update(None, "synchronous", "FULL")?;
    expect_int(conn, "synchronous", 2)?;
    conn.pragma_update(None, "fullfsync", "ON")?;
    expect_int(conn, "fullfsync", 1)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    expect_int(conn, "foreign_keys", 1)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    expect_int(conn, "trusted_schema", 0)?;
    let mmap: i64 = conn.pragma_update_and_check(None, "mmap_size", 0, |row| row.get(0))?;
    expect("mmap_size", mmap == 0, &mmap.to_string())?;
    Ok(())
}

fn set_flag(
    conn: &Connection,
    flag: DbConfig,
    value: bool,
    name: &'static str,
) -> Result<(), ConfigureError> {
    let applied = conn.set_db_config(flag, value)?;
    expect(name, applied == value, &applied.to_string())
}

fn expect_int(conn: &Connection, pragma: &'static str, wanted: i64) -> Result<(), ConfigureError> {
    let got: i64 = conn.pragma_query_value(None, pragma, |row| row.get(0))?;
    expect(pragma, got == wanted, &got.to_string())
}

fn expect(setting: &'static str, ok: bool, got: &str) -> Result<(), ConfigureError> {
    if ok {
        Ok(())
    } else {
        Err(ConfigureError::Mismatch(format!(
            "{setting} did not take effect (read back {got})"
        )))
    }
}

/// Why a connection could not be configured.
#[derive(Debug)]
pub(super) enum ConfigureError {
    /// SQLite refused.
    Sqlite(rusqlite::Error),
    /// A setting read back differently from what was set.
    Mismatch(String),
}

impl From<rusqlite::Error> for ConfigureError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// What a SQLite error means for the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Class {
    /// Structural damage: poison, and quarantine.
    Poison(PoisonReason),
    /// Lock contention past the timeout.
    Busy,
    /// A constraint or trigger refused the write.
    Constraint(String),
    /// Anything else. The transaction rolled back.
    Other(String),
}

/// Classify a SQLite error.
///
/// The extended result code decides, never the message: `SQLITE_CORRUPT` and
/// `SQLITE_NOTADB` are structural and poison the store, an I/O error poisons it
/// too (the file's state after a failed write is exactly what should not be
/// guessed at), and contention is transient.
pub(super) fn classify(error: &rusqlite::Error) -> Class {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseCorrupt) => Class::Poison(PoisonReason::Corrupt),
        Some(ErrorCode::NotADatabase) => Class::Poison(PoisonReason::NotADatabase),
        Some(ErrorCode::SystemIoFailure) => Class::Poison(PoisonReason::StorageIo),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Class::Busy,
        Some(ErrorCode::ConstraintViolation) => Class::Constraint(error.to_string()),
        _ => Class::Other(error.to_string()),
    }
}

/// Map a classification to the error an operation returns. Poisoning itself
/// is the caller's job, because only the caller holds the shared poison state.
pub(super) fn to_error(class: &Class) -> AuthorityError {
    match class {
        Class::Poison(reason) => AuthorityError::Poisoned(reason.clone()),
        Class::Busy => AuthorityError::Busy,
        Class::Constraint(why) => AuthorityError::Rejected(why.clone()),
        Class::Other(why) => AuthorityError::Sqlite(why.clone()),
    }
}

/// Every setting in the module table, as SQLite reports it on one connection.
///
/// Read back, not remembered: this is what the connection is actually doing,
/// which is the claim a test or `direwolf doctor` should check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSettings {
    /// `PRAGMA journal_mode`.
    pub journal_mode: String,
    /// `PRAGMA synchronous` (2 is `FULL`).
    pub synchronous: i64,
    /// `PRAGMA fullfsync`.
    pub fullfsync: i64,
    /// `PRAGMA foreign_keys`.
    pub foreign_keys: i64,
    /// `PRAGMA busy_timeout`, in milliseconds.
    pub busy_timeout_ms: i64,
    /// `PRAGMA trusted_schema`.
    pub trusted_schema: i64,
    /// `PRAGMA mmap_size`.
    pub mmap_size: i64,
    /// `SQLITE_DBCONFIG_DEFENSIVE`.
    pub defensive: bool,
    /// `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`.
    pub no_checkpoint_on_close: bool,
    /// `PRAGMA application_id`.
    pub application_id: i64,
    /// `PRAGMA user_version`: the schema version.
    pub user_version: i64,
    /// `PRAGMA wal_autocheckpoint`, left at SQLite's default.
    pub wal_autocheckpoint: i64,
    /// `PRAGMA auto_vacuum`, left at SQLite's default (0, `NONE`).
    pub auto_vacuum: i64,
}

/// Read every setting back from `conn`.
pub(super) fn settings(conn: &Connection) -> rusqlite::Result<StorageSettings> {
    let int = |pragma: &str| conn.pragma_query_value(None, pragma, |row| row.get::<_, i64>(0));
    Ok(StorageSettings {
        journal_mode: conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?,
        synchronous: int("synchronous")?,
        fullfsync: int("fullfsync")?,
        foreign_keys: int("foreign_keys")?,
        busy_timeout_ms: int("busy_timeout")?,
        trusted_schema: int("trusted_schema")?,
        mmap_size: int("mmap_size")?,
        defensive: conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?,
        no_checkpoint_on_close: conn.db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)?,
        application_id: int("application_id")?,
        user_version: int("user_version")?,
        wal_autocheckpoint: int("wal_autocheckpoint")?,
        auto_vacuum: int("auto_vacuum")?,
    })
}
