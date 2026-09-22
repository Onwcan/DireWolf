//! Durable authority state: `kernel.db`, epoch fencing, leases, run
//! admission, idempotency, kernel-owned policy inputs and the hash-chained
//! audit log (M3d).
//!
//! > **Authority state must survive a crash without becoming ambiguous.**
//!
//! # What this module is
//!
//! The state machine behind the M3 authority operations. It persists what the
//! pure cores decide — M3b's capability lattice mints grants, M3c's policy
//! engine decides actions — and it owns every fact those decisions are made
//! from: the epoch, the lease holder, the admitted run, its grants, its policy
//! inputs, the policy revision. The cores stay pure and know nothing of SQLite;
//! this module calls them.
//!
//! # What this module is not
//!
//! It listens on nothing, authenticates nobody, executes nothing, resolves no
//! filesystem resource and grants no approval. M3e binds these operations to a
//! real socket and a real peer; M4 supplies canonical resources; M6 approvals.
//! A caller of this module is trusted in-process code, and the identities it
//! passes in ([`AuthenticatedSubject`], and a [`LeaseHolder`] it obtained from
//! [`Authority::connect`]) are assertions it makes, not facts this module
//! checked.
//!
//! # The files
//!
//! A private state directory (`0700`) holding `kernel.db` (SQLite, WAL,
//! `synchronous = FULL`), `audit.log` (the authoritative hash chain), an
//! exclusive lock file, and — only after structural damage — a quarantine
//! marker. See [`files`] and [`db`].
//!
//! # Startup
//!
//! 1. The configured policy loads and composes, **or the authority does not
//!    start**. Nothing is written before this succeeds.
//! 2. The directory is private; the lock is taken; no quarantine marker is
//!    present; every state file is private and not a symlink.
//! 3. `kernel.db` is created (only if the directory holds no state at all),
//!    migrated, or verified — exactly: the schema, `quick_check`, foreign
//!    keys, the critical singleton rows, and every stored policy revision
//!    recomputed from its stored sources.
//! 4. `audit.log` is reconciled with `kernel.db`'s outbox, or the store is
//!    quarantined.
//! 5. A new **incarnation**: every held lease is invalidated and every active
//!    run reaped. Epochs are not reset.
//! 6. The policy revision is installed if new, and activated.
//!
//! A store that fails any step is **never** recreated, renamed away or
//! repaired into something empty. Structural damage writes a quarantine
//! marker, and every later start refuses until an operator removes it.
//!
//! [`files`]: self::files
//! [`db`]: self::db

mod admission;
mod audit;
mod clock;
mod config;
mod crash;
mod db;
mod digest;
mod error;
mod files;
mod identity;
mod ids;
mod lease;
mod policy_state;
mod query;
mod schema;
pub mod wire;

use core::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dwk_proto::dwkp::messages::Ack;
use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{CapId, RunId, SessionId};
use dwk_proto::wire::scalar::{Epoch, RefusalReason, RefusedOperation};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior};

use crate::policy::{ConfigFlags, PolicyContext, TaintLevel};

pub use admission::{Admission, Grant, Withheld, WithheldCause, request_digest};
pub use audit::{
    AUDIT_FORMAT_VERSION, AuditEvent, AuditLogFault, AuditLogSummary, MAX_RECORD_BYTES,
    RecordFault, StoreAuditFault, StoreComparison, verify_audit_against_store, verify_audit_log,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    AgentProfileSpec, ConfigError, MAX_BASELINE_SKILLS, MAX_DECLARED_CAPABILITIES, SkillSpec,
    SkillTrust, WorkspaceId, WorkspaceSensitivity,
};
pub use crash::{CrashHook, CrashPoint, HookAction};
pub use db::StorageSettings;
pub use digest::Sha256Hash;
pub use dwk_proto::wire::scalar::ProfileName as Mode;
pub use error::{AuthorityError, PoisonReason, StartError};
pub use files::{AUDIT_LOG, KERNEL_DB, LOCK_FILE, QUARANTINE_MARKER};
pub use identity::{AuthenticatedSubject, CallerContext, LeaseHolder};
pub use lease::{DEFAULT_LEASE_TTL_MS, MAX_EPOCH, MAX_LEASE_TTL_MS, MIN_LEASE_TTL_MS};
pub use policy_state::{MAX_CEILING_CAPABILITIES, MAX_POLICY_SOURCES, PolicySet, PolicySource};
pub use query::{AuthorityAnswer, DecisionRecord, Proposal, TaintCause, Undecidable};
pub use wire::WireGap;

use audit::{AuditWriter, Fields, FlushFailure};
use db::Class;
use digest::DomainHash;
use files::{Layout, StatePaths};
use policy_state::ActiveAuthority;
use schema::{Shape, ShapeError};

/// The `kernel.db` schema version this build creates and understands.
pub const KERNEL_SCHEMA_VERSION: i64 = schema::CURRENT_VERSION;

/// What the operator configures, read once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfig {
    /// The policy to install and activate.
    pub policy: PolicySet,
    /// The mode ceiling runs are admitted under — what `RunGrant.profile`
    /// reports.
    pub mode: Mode,
    /// The mode's capability ceiling: the widest authority any run may be
    /// minted, whatever its profile says.
    pub ceiling: Vec<String>,
    /// Operator configuration flags policy may read (`unless.config`).
    pub flags: ConfigFlags,
    /// How long a lease lives without a heartbeat.
    pub lease_ttl_ms: u64,
}

impl StartupConfig {
    /// A configuration with every flag off and the default lease TTL.
    #[must_use]
    pub fn new(policy: PolicySet, mode: Mode, ceiling: Vec<String>) -> Self {
        Self {
            policy,
            mode,
            ceiling,
            flags: ConfigFlags::default(),
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
        }
    }
}

/// How to run: which clock, and whether a crash hook is consulted.
#[derive(Clone)]
pub struct StartOptions {
    /// Authority time.
    pub clock: Arc<dyn Clock>,
    /// Consulted at every [`CrashPoint`]. See [`crash`](self::crash).
    pub crash_hook: Option<CrashHook>,
}

impl Default for StartOptions {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            crash_hook: None,
        }
    }
}

impl fmt::Debug for StartOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartOptions")
            .field("clock", &self.clock)
            .field("crash_hook", &self.crash_hook.is_some())
            .finish()
    }
}

/// What startup found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartReport {
    /// A new store was created.
    pub created: bool,
    /// The schema version now in force.
    pub schema_version: i64,
    /// This process's incarnation.
    pub incarnation: u64,
    /// Held leases the previous process left, now invalidated.
    pub leases_invalidated: u64,
    /// Active runs the previous process left, now reaped.
    pub runs_reaped: u64,
    /// Audit records already in `audit.log` above the flushed mark: reconciled,
    /// not appended again.
    pub audit_reconciled: u64,
    /// Audit records appended from the outbox.
    pub audit_appended: u64,
    /// Bytes of a torn final audit record removed before re-appending it.
    pub audit_torn_tail_bytes: u64,
    /// The active policy revision.
    pub policy_revision: Sha256Hash,
    /// The active activation.
    pub activation_id: i64,
}

/// A well-formed answer: done, or refused with a typed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply<T> {
    /// The operation happened.
    Done(T),
    /// The authority's state does not permit it. Nothing was granted.
    Refused(RefusalReason),
}

impl<T> Reply<T> {
    /// The result, if the operation happened.
    #[must_use]
    pub fn done(self) -> Option<T> {
        match self {
            Self::Done(value) => Some(value),
            Self::Refused(_) => None,
        }
    }

    /// The refusal, if it was refused.
    #[must_use]
    pub const fn refused(&self) -> Option<RefusalReason> {
        match self {
            Self::Done(_) => None,
            Self::Refused(reason) => Some(*reason),
        }
    }
}

/// What every handle shares.
struct Shared {
    paths: StatePaths,
    clock: Arc<dyn Clock>,
    crash_hook: Option<CrashHook>,
    incarnation: AtomicU64,
    store_instance: u32,
    next_connection: AtomicU64,
    poisoned: AtomicBool,
    poison_reason: Mutex<Option<PoisonReason>>,
    audit: Mutex<Option<AuditWriter>>,
    active: OnceLock<ActiveAuthority>,
    lease_ttl_ms: u64,
    // Held for the life of the process; the OS releases it on exit.
    _lock: std::fs::File,
}

impl Shared {
    fn check(&self) -> Result<(), AuthorityError> {
        if !self.poisoned.load(Ordering::SeqCst) {
            return Ok(());
        }
        let reason = self
            .poison_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or(PoisonReason::StorageIo);
        Err(AuthorityError::Poisoned(reason))
    }

    /// Poison the store. Immediate, in memory, for every handle; structural
    /// damage also writes the quarantine marker. Returns the error to answer.
    fn poison(&self, reason: PoisonReason) -> AuthorityError {
        if let Ok(mut slot) = self.poison_reason.lock()
            && slot.is_none()
        {
            *slot = Some(reason.clone());
        }
        self.poisoned.store(true, Ordering::SeqCst);
        if reason.is_structural() {
            files::write_quarantine(&self.paths, &reason.to_string());
        }
        AuthorityError::Poisoned(reason)
    }

    fn sql(&self, error: &rusqlite::Error) -> AuthorityError {
        match db::classify(error) {
            Class::Poison(reason) => self.poison(reason),
            other => db::to_error(&other),
        }
    }

    fn crash(&self, point: CrashPoint) -> Result<(), AuthorityError> {
        match &self.crash_hook {
            Some(hook) if hook(point) == HookAction::Stop => {
                Err(self.poison(PoisonReason::Interrupted(point)))
            }
            _ => Ok(()),
        }
    }

    fn active(&self) -> Result<&ActiveAuthority, AuthorityError> {
        self.active
            .get()
            .ok_or(AuthorityError::Invariant("no authority is active yet"))
    }

    fn flush(&self, conn: &Connection, target: u64) -> Result<(), AuthorityError> {
        self.check()?;
        let mut guard = self
            .audit
            .lock()
            .map_err(|_| self.poison(PoisonReason::AuditIo))?;
        let Some(writer) = guard.as_mut() else {
            return Err(AuthorityError::Invariant("the audit writer is not open"));
        };
        let mut hook = |point| self.crash(point);
        match writer.flush_through(conn, target, &mut hook) {
            Ok(()) => Ok(()),
            Err(FlushFailure::Stopped(error)) => Err(error),
            Err(FlushFailure::Io) => Err(self.poison(PoisonReason::AuditIo)),
            Err(FlushFailure::Sqlite(error)) => Err(self.sql(&error)),
            Err(FlushFailure::Diverged(why)) => Err(self.poison(PoisonReason::AuditDiverged(why))),
        }
    }
}

/// One transaction's working context.
pub(crate) struct Work<'a> {
    pub(crate) tx: &'a Connection,
    shared: &'a Shared,
    pub(crate) now: u64,
    last_seq: Option<u64>,
}

impl Work<'_> {
    /// Classify a SQLite result, poisoning on structural damage.
    pub(crate) fn db<T>(&self, result: rusqlite::Result<T>) -> Result<T, AuthorityError> {
        result.map_err(|error| self.shared.sql(&error))
    }

    /// Append an audit record to this transaction's outbox.
    pub(crate) fn audit(
        &mut self,
        event: AuditEvent,
        fields: Fields,
    ) -> Result<(), AuthorityError> {
        match audit::append(self.tx, self.now, event, fields) {
            Ok(seq) => {
                self.last_seq = Some(seq);
                Ok(())
            }
            Err(audit::AuditAppendError::Sqlite(error)) => Err(self.shared.sql(&error)),
            Err(audit::AuditAppendError::Authority(error)) => Err(error),
        }
    }

    fn next_uuid(&self) -> Result<u128, AuthorityError> {
        let current: i64 = self.db(self.tx.query_row(
            "SELECT id_counter FROM store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        ))?;
        let current = u64::try_from(current)
            .map_err(|_| AuthorityError::Invariant("the id counter is negative"))?;
        if current >= ids::MAX_ID_COUNTER {
            return Err(AuthorityError::IdSpaceExhausted);
        }
        let next: i64 = self.db(self.tx.query_row(
            "UPDATE store_meta SET id_counter = id_counter + 1 WHERE singleton = 1 \
             RETURNING id_counter",
            [],
            |row| row.get(0),
        ))?;
        let next = u64::try_from(next)
            .map_err(|_| AuthorityError::Invariant("the id counter is negative"))?;
        ids::uuid7(self.now, next, self.shared.store_instance)
            .ok_or(AuthorityError::IdSpaceExhausted)
    }

    pub(crate) fn run_id(&self) -> Result<RunId, AuthorityError> {
        RunId::from_uuid(self.next_uuid()?)
            .ok_or(AuthorityError::Invariant("a minted run id is not a UUIDv7"))
    }

    pub(crate) fn cap_id(&self) -> Result<CapId, AuthorityError> {
        CapId::from_uuid(self.next_uuid()?)
            .ok_or(AuthorityError::Invariant("a minted cap id is not a UUIDv7"))
    }
}

/// The durable authority: one handle onto one state directory.
///
/// A handle owns one SQLite connection and is used from one thread at a time.
/// [`Authority::handle`] opens another onto the same store — same process
/// lock, same poison state, same audit writer — so several threads can contend
/// for the store through SQLite's own locking, which is what the concurrency
/// evidence exercises.
pub struct Authority {
    shared: Arc<Shared>,
    conn: Connection,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("state_dir", &self.shared.paths.dir)
            .field(
                "incarnation",
                &self.shared.incarnation.load(Ordering::SeqCst),
            )
            .field("poisoned", &self.shared.poisoned.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

fn io_error(context: &'static str) -> impl Fn(std::io::Error) -> StartError {
    move |error| StartError::Io(format!("{context}: {error}"))
}

impl Authority {
    /// Start the authority on `dir`.
    ///
    /// # Errors
    ///
    /// [`StartError`] — and in every case the store is left as it was found,
    /// apart from a quarantine marker when structural damage was the reason.
    pub fn start(
        dir: &Path,
        config: &StartupConfig,
        options: StartOptions,
    ) -> Result<(Self, StartReport), StartError> {
        if !(MIN_LEASE_TTL_MS..=MAX_LEASE_TTL_MS).contains(&config.lease_ttl_ms) {
            return Err(StartError::Configuration(format!(
                "lease TTL {} ms is outside {MIN_LEASE_TTL_MS}..={MAX_LEASE_TTL_MS}",
                config.lease_ttl_ms
            )));
        }
        // The policy first, before anything is touched: a policy that does not
        // load is a start that does not happen.
        let prepared = policy_state::prepare(&config.policy).map_err(StartError::Policy)?;
        let (ceiling, ceiling_set) =
            policy_state::prepare_ceiling(&config.ceiling).map_err(StartError::Configuration)?;
        if prepared.compiled.default_rule().is_none() {
            return Err(StartError::Policy(
                "the composed policy has no default".to_owned(),
            ));
        }

        files::prepare_directory(dir)?;
        files::check_directory(dir)?;
        let paths = StatePaths::new(dir);
        let lock = files::lock(&paths)?;
        if let Some(marker) = files::quarantine_marker(&paths) {
            return Err(StartError::Quarantined(marker.trim().to_owned()));
        }
        for path in [&paths.db, &paths.wal, &paths.shm, &paths.audit, &paths.lock] {
            files::check_file(path)?;
        }
        let layout = files::layout(&paths)?;
        if layout == Layout::Fresh {
            files::create_private_file(&paths.db)?;
            files::create_private_file(&paths.audit)?;
            files::sync_directory(dir)?;
        }

        let clock = Arc::clone(&options.clock);
        let Opened {
            conn,
            created,
            store_instance,
        } = open_store(&paths, layout, clock.now_ms())?;

        let recovered = audit::recover(&conn, &paths.audit).map_err(|error| match error {
            audit::RecoveryError::Diverged(fault) => {
                let why = fault.to_string();
                files::write_quarantine(&paths, &why);
                StartError::Audit(why)
            }
            audit::RecoveryError::Io(why) => StartError::Io(why),
            audit::RecoveryError::Sqlite(error) => opened(&paths, &error),
        })?;
        let writer = AuditWriter::open(&paths.audit, &recovered)
            .map_err(io_error("opening audit.log for appending"))?;

        let shared = Arc::new(Shared {
            paths,
            clock,
            crash_hook: options.crash_hook,
            incarnation: AtomicU64::new(0),
            store_instance,
            next_connection: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
            poison_reason: Mutex::new(None),
            audit: Mutex::new(Some(writer)),
            active: OnceLock::new(),
            lease_ttl_ms: config.lease_ttl_ms,
            _lock: lock,
        });
        let mut authority = Self { shared, conn };

        let (incarnation, leases_invalidated, runs_reaped) =
            authority.begin_incarnation(created, &recovered)?;
        let activation_id = authority.activate(&prepared, config.mode, config.flags, &ceiling)?;
        let revision = prepared.revision;
        let _ = authority.shared.active.set(ActiveAuthority {
            activation_id,
            revision,
            mode: config.mode,
            flags: config.flags,
            ceiling: ceiling_set,
            compiled: prepared.compiled,
        });

        let report = StartReport {
            created,
            schema_version: schema::CURRENT_VERSION,
            incarnation,
            leases_invalidated,
            runs_reaped,
            audit_reconciled: recovered.reconciled,
            audit_appended: recovered.appended,
            audit_torn_tail_bytes: recovered.torn_tail_bytes,
            policy_revision: revision,
            activation_id,
        };
        Ok((authority, report))
    }

    /// A new incarnation: nothing the previous process held is still held.
    /// Returns the incarnation and how many leases and runs it ended.
    fn begin_incarnation(
        &mut self,
        created: bool,
        recovered: &audit::Recovered,
    ) -> Result<(u64, u64, u64), AuthorityError> {
        let (incarnation, leases, runs) = self.transact(|work| {
            let incarnation: i64 = work.db(work.tx.query_row(
                "UPDATE store_meta SET incarnation = incarnation + 1 WHERE singleton = 1                  RETURNING incarnation",
                [],
                |row| row.get(0),
            ))?;
            let incarnation = u64::try_from(incarnation)
                .map_err(|_| AuthorityError::Invariant("the incarnation is negative"))?;
            let (leases, runs) = lease::invalidate_all(work)?;
            work.audit(
                AuditEvent::StoreOpened,
                Fields::new()
                    .int("incarnation", incarnation)
                    .int("schema_version", u64::try_from(schema::CURRENT_VERSION).unwrap_or(0))
                    .flag("created", created)
                    .int("leases_invalidated", leases)
                    .int("runs_reaped", runs)
                    .int("audit_reconciled", recovered.reconciled)
                    .int("audit_appended", recovered.appended)
                    .int("audit_torn_tail_bytes", recovered.torn_tail_bytes),
            )?;
            Ok((incarnation, leases, runs))
        })?;
        self.shared.incarnation.store(incarnation, Ordering::SeqCst);
        Ok((incarnation, leases, runs))
    }

    /// Install the prepared policy revision if it is new, and make it, the
    /// mode, the flags and the ceiling the active authority.
    fn activate(
        &mut self,
        prepared: &policy_state::Prepared,
        mode: Mode,
        flags: ConfigFlags,
        ceiling: &[String],
    ) -> Result<i64, AuthorityError> {
        self.transact(|work| {
            let tx = work.tx;
            let now = work.now;
            let mut audit = |event: AuditEvent, fields: Fields| work.audit(event, fields);
            policy_state::install(tx, now, prepared, &mut audit)?;
            policy_state::activate(
                tx,
                now,
                &prepared.revision,
                mode,
                flags,
                ceiling,
                &mut audit,
            )
        })
    }

    /// Another handle onto the same store, with its own SQLite connection.
    ///
    /// # Errors
    ///
    /// The store is poisoned, or the connection could not be opened and
    /// configured.
    pub fn handle(&self) -> Result<Self, AuthorityError> {
        self.shared.check()?;
        let conn = db::open(&self.shared.paths.db).map_err(|e| self.shared.sql(&e))?;
        db::configure(&conn).map_err(|error| match error {
            db::ConfigureError::Sqlite(error) => self.shared.sql(&error),
            db::ConfigureError::Mismatch(why) => AuthorityError::Sqlite(why),
        })?;
        Ok(Self {
            shared: Arc::clone(&self.shared),
            conn,
        })
    }

    /// A caller context for one new connection by `subject`: a fresh
    /// [`LeaseHolder`], never equal to any other, bound to this incarnation.
    ///
    /// M3e calls this once per accepted socket, with the subject it derived
    /// from the peer's credentials. **M3d performs no authentication**: the
    /// subject is whatever the caller asserts.
    #[must_use]
    pub fn connect(&self, subject: AuthenticatedSubject) -> CallerContext {
        let connection = self
            .shared
            .next_connection
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        CallerContext::new(
            subject,
            LeaseHolder::new(self.shared.incarnation.load(Ordering::SeqCst), connection),
        )
    }

    /// The state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.shared.paths.dir
    }

    /// This process's incarnation.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.shared.incarnation.load(Ordering::SeqCst)
    }

    /// Why the store is poisoned, if it is.
    #[must_use]
    pub fn poisoned(&self) -> Option<PoisonReason> {
        self.shared.check().err().and_then(|error| match error {
            AuthorityError::Poisoned(reason) => Some(reason),
            _ => None,
        })
    }

    /// The storage settings as this handle's SQLite connection reports them.
    ///
    /// # Errors
    ///
    /// The store is poisoned, or SQLite could not answer.
    pub fn storage_settings(&self) -> Result<StorageSettings, AuthorityError> {
        self.shared.check()?;
        db::settings(&self.conn).map_err(|e| self.shared.sql(&e))
    }

    /// The active policy revision.
    #[must_use]
    pub fn policy_revision(&self) -> Option<Sha256Hash> {
        self.shared.active.get().map(|active| active.revision)
    }

    /// Run `body` in one `BEGIN IMMEDIATE` transaction, then make its audit
    /// records durable before returning. Crash points A–G are crossed here.
    fn transact<R>(
        &mut self,
        body: impl FnOnce(&mut Work<'_>) -> Result<R, AuthorityError>,
    ) -> Result<R, AuthorityError> {
        let Self { shared, conn } = self;
        let shared: &Shared = shared;
        shared.check()?;
        shared.crash(CrashPoint::BeforeTransaction)?;
        let now = shared.clock.now_ms();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| shared.sql(&e))?;
        let (result, last_seq) = {
            let mut work = Work {
                tx: &tx,
                shared,
                now,
                last_seq: None,
            };
            match body(&mut work) {
                Ok(result) => (result, work.last_seq),
                Err(error) => {
                    if let AuthorityError::Poisoned(reason) = &error {
                        let _ = shared.poison(reason.clone());
                    }
                    return Err(error);
                }
            }
        };
        shared.crash(CrashPoint::BeforeCommit)?;
        tx.commit().map_err(|e| shared.sql(&e))?;
        if let Some(seq) = last_seq {
            shared.flush(conn, seq)?;
        }
        Ok(result)
    }

    /// `AcquireLease` for `session`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn acquire_lease(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
    ) -> Result<Reply<Epoch>, AuthorityError> {
        let ttl = self.shared.lease_ttl_ms;
        self.transact(|work| lease::acquire(work, caller, session, ttl))
    }

    /// `Heartbeat`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn heartbeat(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        epoch: Epoch,
    ) -> Result<Reply<()>, AuthorityError> {
        let ttl = self.shared.lease_ttl_ms;
        self.transact(|work| lease::heartbeat(work, caller, session, epoch, ttl))
    }

    /// `ReleaseLease`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn release_lease(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        epoch: Epoch,
    ) -> Result<Reply<()>, AuthorityError> {
        self.transact(|work| lease::release(work, caller, session, epoch))
    }

    /// `AdmitRun`, given the **decoded** request: its canonical form is what
    /// the idempotency key is bound to.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer, including when the
    /// message is not an `AdmitRun`.
    pub fn admit_run(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
    ) -> Result<Reply<Admission>, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        self.transact(|work| admission::admit(work, caller, message, active))
    }

    /// `ReleaseRun`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn release_run(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
    ) -> Result<Reply<()>, AuthorityError> {
        self.transact(|work| admission::release(work, caller, session, run, epoch))
    }

    /// `QueryAuthority`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn query_authority(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        proposal: Option<Proposal<'_>>,
    ) -> Result<Reply<AuthorityAnswer>, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        self.transact(|work| query::query(work, caller, session, run, epoch, proposal, active))
    }

    /// Raise a run's taint. The trusted interface the tool-result, artifact
    /// and memory paths of M4, M12 and M13 will call; nothing in M3d does, and
    /// nothing on the wire can.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer or the run has no
    /// policy inputs.
    pub fn raise_taint(
        &mut self,
        run: &RunId,
        observed: TaintLevel,
        cause: TaintCause,
    ) -> Result<TaintLevel, AuthorityError> {
        self.transact(|work| query::raise_taint(work, run, observed, cause))
    }

    /// The `PolicyContext` the kernel builds for `run` from `kernel.db` — the
    /// only one any decision about it uses.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the run has no policy inputs.
    pub fn policy_context_of(&mut self, run: &RunId) -> Result<PolicyContext, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        self.transact(|work| query::policy_context(work, run.as_str(), active))
    }

    /// Answer one decoded DWKP request with the response body M3e would send.
    ///
    /// Total over the six authority requests: every answer has a truthful wire
    /// form (ADR-0040). A proposal is refused with `NO_CANONICAL_ACTION`
    /// before any rule runs, an ended admission with `ADMISSION_ENDED`, and a
    /// withheld `fs` or `process` capability carries `UNRESOLVED_RESOURCE`.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer, the message is not
    /// one of the six authority requests, or a stored value does not fit its
    /// wire type (a bug, never a sound store).
    pub fn dispatch(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
    ) -> Result<DwkpBody, AuthorityError> {
        let header = &message.header;
        let missing = || AuthorityError::Invariant("a decoded request lacks an envelope field");
        let unrepresentable = |_: WireGap| {
            AuthorityError::Invariant("a stored value does not fit the wire type that carries it")
        };
        let session = header.session_id.as_ref();
        let refused = |operation: RefusedOperation, reason: RefusalReason| {
            Ok(DwkpBody::AuthorityRefused(wire::refusal(operation, reason)))
        };
        match &message.body {
            DwkpBody::LeaseAcquire(_) => {
                let session = session.ok_or_else(missing)?;
                match self.acquire_lease(caller, session)? {
                    Reply::Done(epoch) => {
                        Ok(DwkpBody::LeaseGrant(wire::lease_grant(session, epoch)))
                    }
                    Reply::Refused(reason) => refused(RefusedOperation::AcquireLease, reason),
                }
            }
            DwkpBody::Heartbeat(_) => {
                let session = session.ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                match self.heartbeat(caller, session, epoch)? {
                    Reply::Done(()) => Ok(DwkpBody::Ack(Ack {})),
                    Reply::Refused(reason) => refused(RefusedOperation::Heartbeat, reason),
                }
            }
            DwkpBody::LeaseRelease(_) => {
                let session = session.ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                match self.release_lease(caller, session, epoch)? {
                    Reply::Done(()) => Ok(DwkpBody::Ack(Ack {})),
                    Reply::Refused(reason) => refused(RefusedOperation::ReleaseLease, reason),
                }
            }
            DwkpBody::AdmitRun(_) => match self.admit_run(caller, message)? {
                Reply::Done(admission) => wire::run_grant(&admission)
                    .map(DwkpBody::RunGrant)
                    .map_err(unrepresentable),
                Reply::Refused(reason) => refused(RefusedOperation::AdmitRun, reason),
            },
            DwkpBody::ReleaseRun(_) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                match self.release_run(caller, session, run, epoch)? {
                    Reply::Done(()) => Ok(DwkpBody::Ack(Ack {})),
                    Reply::Refused(reason) => refused(RefusedOperation::ReleaseRun, reason),
                }
            }
            DwkpBody::AuthorityQuery(query) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                let proposal = query.proposed.as_ref().map(Proposal::Text);
                match self.query_authority(caller, session, run, epoch, proposal)? {
                    // A wire proposal never produces a decision, so the only
                    // gap `effective_authority` could report is unreachable
                    // here; what remains is a bug.
                    Reply::Done(answer) => wire::effective_authority(&answer)
                        .map(DwkpBody::EffectiveAuthority)
                        .map_err(unrepresentable),
                    Reply::Refused(reason) => refused(RefusedOperation::QueryAuthority, reason),
                }
            }
            _ => Err(AuthorityError::NotAnAuthorityRequest),
        }
    }

    /// The operator's configuration API. **In-process only**: no DWKP
    /// operation reaches it. See [`OperatorBootstrap`].
    pub fn operator(&mut self) -> OperatorBootstrap<'_> {
        OperatorBootstrap { authority: self }
    }
}

/// Installs kernel-owned configuration: agent profiles, skills, workspaces and
/// session bindings.
///
/// This is how an operator's own tooling — and, in M3d, the tests standing in
/// for it — puts authority configuration into `kernel.db`. It is **not** a
/// runtime authority path: nothing on the wire reaches it, and a runtime can
/// only *name* the records it creates. Every change is audited.
pub struct OperatorBootstrap<'a> {
    authority: &'a mut Authority,
}

impl fmt::Debug for OperatorBootstrap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorBootstrap").finish_non_exhaustive()
    }
}

fn config_now(now: u64) -> Result<i64, AuthorityError> {
    i64::try_from(now).map_err(|_| AuthorityError::Invariant("a timestamp exceeds i64"))
}

impl OperatorBootstrap<'_> {
    fn run<R>(
        &mut self,
        body: impl FnOnce(
            &Connection,
            i64,
            &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
        ) -> Result<R, config::ConfigError>,
    ) -> Result<R, ConfigError> {
        let mut invalid = None;
        let outcome = self.authority.transact(|work| {
            let tx = work.tx;
            let now = config_now(work.now)?;
            let mut audit = |event: AuditEvent, fields: Fields| work.audit(event, fields);
            match body(tx, now, &mut audit) {
                Ok(value) => Ok(Some(value)),
                Err(ConfigError::Authority(error)) => Err(error),
                Err(ConfigError::Invalid(why)) => {
                    invalid = Some(why);
                    // Roll the transaction back: an invalid definition writes
                    // nothing.
                    Err(AuthorityError::Rejected("invalid configuration".to_owned()))
                }
            }
        });
        match (outcome, invalid) {
            (_, Some(why)) => Err(ConfigError::Invalid(why)),
            (Ok(Some(value)), None) => Ok(value),
            (Ok(None), None) => Err(ConfigError::Authority(AuthorityError::Invariant(
                "a configuration transaction produced nothing",
            ))),
            (Err(error), None) => Err(ConfigError::Authority(error)),
        }
    }

    /// Install an agent profile revision. Identical to the current revision →
    /// no-op, returning it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for a definition that does not parse or exceeds
    /// a bound; nothing is written.
    pub fn install_agent_profile(&mut self, spec: &AgentProfileSpec) -> Result<i64, ConfigError> {
        self.run(|tx, now, audit| config::install_agent_profile(tx, now, spec, audit))
    }

    /// Install a skill revision.
    ///
    /// # Errors
    ///
    /// As [`OperatorBootstrap::install_agent_profile`].
    pub fn install_skill(&mut self, spec: &SkillSpec) -> Result<i64, ConfigError> {
        self.run(|tx, now, audit| config::install_skill(tx, now, spec, audit))
    }

    /// Install a workspace, or make an existing one stricter.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when this would loosen it.
    pub fn install_workspace(
        &mut self,
        id: &WorkspaceId,
        sensitivity: WorkspaceSensitivity,
    ) -> Result<(), ConfigError> {
        self.run(|tx, now, audit| config::install_workspace(tx, now, id, sensitivity, audit))
    }

    /// Bind a session to a workspace, for the session's life.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for an unknown workspace or a session already
    /// bound elsewhere.
    pub fn bind_session_workspace(
        &mut self,
        session: &SessionId,
        id: &WorkspaceId,
    ) -> Result<(), ConfigError> {
        self.run(|tx, now, audit| {
            config::bind_session_workspace(tx, now, session.as_str(), id, audit)
        })
    }
}

/// What [`open_store`] hands back: a verified connection.
struct Opened {
    conn: Connection,
    created: bool,
    store_instance: u32,
}

fn quarantined(paths: &StatePaths, why: String) -> StartError {
    files::write_quarantine(paths, &why);
    StartError::Corrupt(why)
}

/// A SQLite error while opening: structural damage quarantines the store.
fn opened(paths: &StatePaths, error: &rusqlite::Error) -> StartError {
    match db::classify(error) {
        Class::Poison(reason @ (PoisonReason::Corrupt | PoisonReason::NotADatabase)) => {
            quarantined(paths, format!("{reason}: {error}"))
        }
        _ => StartError::Sqlite(error.to_string()),
    }
}

/// Open `kernel.db`, create, migrate or verify it, and prove its critical
/// state is present. Never recreates anything that was there.
fn open_store(paths: &StatePaths, layout: Layout, now_ms: u64) -> Result<Opened, StartError> {
    let quarantine = |why: String| quarantined(paths, why);
    let open_error = |error: rusqlite::Error| opened(paths, &error);

    let mut conn = db::open(&paths.db).map_err(open_error)?;
    db::configure(&conn).map_err(|error| match error {
        db::ConfigureError::Sqlite(error) => open_error(error),
        db::ConfigureError::Mismatch(why) => StartError::Configuration(why),
    })?;
    for path in [&paths.wal, &paths.shm] {
        files::check_file(path)?;
    }

    let mut created = false;
    match schema::classify(&conn).map_err(open_error)? {
        Ok(Shape::Empty) => {
            let audit_empty = std::fs::metadata(&paths.audit).is_ok_and(|m| m.len() == 0);
            if layout == Layout::Existing && !audit_empty {
                return Err(StartError::Layout(
                    "kernel.db is empty while audit.log is not; the store is not recreated \
                     under an existing audit chain"
                        .to_owned(),
                ));
            }
            create_store(&mut conn, now_ms).map_err(|e| match e {
                StoreCreation::Sqlite(error) => open_error(error),
                StoreCreation::Other(why) => StartError::Migration(why),
            })?;
            created = true;
        }
        Ok(Shape::Older(version)) => migrate_store(&mut conn, version)?,
        Ok(Shape::Current) => {}
        Err(ShapeError::Foreign) => return Err(StartError::ForeignDatabase),
        Err(ShapeError::Future(found)) => {
            return Err(StartError::FutureSchema {
                found,
                supported: schema::CURRENT_VERSION,
            });
        }
        Err(ShapeError::Malformed(why)) => return Err(StartError::MalformedSchema(why)),
    }

    schema::verify_exact(&conn)
        .map_err(open_error)?
        .map_err(StartError::MalformedSchema)?;
    schema::quick_check(&conn)
        .map_err(open_error)?
        .map_err(quarantine)?;
    schema::foreign_key_check(&conn)
        .map_err(open_error)?
        .map_err(quarantine)?;
    let store_id: Option<String> = conn
        .query_row(
            "SELECT store_id FROM store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(open_error)?;
    let Some(store_id) = store_id else {
        return Err(quarantine(
            "critical state is missing: store_meta".to_owned(),
        ));
    };
    for (table, sql) in [
        (
            "audit_head",
            "SELECT count(*) FROM audit_head WHERE singleton = 1",
        ),
        (
            "audit_state",
            "SELECT count(*) FROM audit_state WHERE singleton = 1",
        ),
    ] {
        let present: i64 = conn
            .query_row(sql, [], |row| row.get(0))
            .map_err(open_error)?;
        if present != 1 {
            return Err(quarantine(format!("critical state is missing: {table}")));
        }
    }
    policy_state::verify_stored_revisions(&conn).map_err(|error| quarantine(error.to_string()))?;

    let store_instance = store_id
        .get(..8)
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .ok_or_else(|| quarantine("the store id is malformed".to_owned()))?;
    Ok(Opened {
        conn,
        created,
        store_instance,
    })
}

/// Why store creation failed.
enum StoreCreation {
    Sqlite(rusqlite::Error),
    Other(String),
}

impl From<rusqlite::Error> for StoreCreation {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Create the current schema and the genesis state in one transaction.
fn create_store(conn: &mut Connection, now_ms: u64) -> Result<(), StoreCreation> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    schema::migrate(&tx, 0, schema::MIGRATIONS)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let store_id = DomainHash::new(digest::STORE_ID)
        .int(now_ms)
        .bytes(&nanos.to_be_bytes())
        .finish();
    let now =
        i64::try_from(now_ms).map_err(|_| StoreCreation::Other("clock overflow".to_owned()))?;
    tx.execute(
        "INSERT INTO store_meta (singleton, store_id, created_ms, incarnation, id_counter) \
         VALUES (1, ?1, ?2, 0, 0)",
        rusqlite::params![store_id.to_hex(), now],
    )?;
    tx.execute(
        "INSERT INTO audit_head (singleton, seq, hash) VALUES (1, 0, ?1)",
        [Sha256Hash::ZERO.to_hex()],
    )?;
    tx.execute(
        "INSERT INTO audit_state (singleton, flushed_seq, flushed_hash) VALUES (1, 0, ?1)",
        [Sha256Hash::ZERO.to_hex()],
    )?;
    audit::append(
        &tx,
        now_ms,
        AuditEvent::StoreCreated,
        Fields::new().text("store_id", store_id.to_hex()).int(
            "schema_version",
            u64::try_from(schema::CURRENT_VERSION).unwrap_or(0),
        ),
    )
    .map_err(|error| match error {
        audit::AuditAppendError::Sqlite(error) => StoreCreation::Sqlite(error),
        audit::AuditAppendError::Authority(error) => StoreCreation::Other(error.to_string()),
    })?;
    tx.commit()?;
    Ok(())
}

/// Migrate an older store forward in one transaction; a failure rolls it back.
fn migrate_store(conn: &mut Connection, from: i64) -> Result<(), StartError> {
    let failed = |error: rusqlite::Error| StartError::Migration(error.to_string());
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    schema::migrate(&tx, from, schema::MIGRATIONS).map_err(failed)?;
    tx.commit().map_err(failed)
}
