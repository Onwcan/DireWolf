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
//! filesystem resource and grants no approval. `crate::server` (M3e) binds these
//! operations to a real socket and a kernel-identified peer; M4 supplies
//! canonical resources; M6 approvals. A caller of this module is trusted
//! in-process code, and the identities it passes in ([`AuthenticatedSubject`],
//! and a [`LeaseHolder`] it obtained from [`Authority::connect`]) are
//! assertions it makes, not facts this module checked: in the server, the
//! subject is the uid the kernel reported for the socket, and the holder is
//! minted once per accepted connection.
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
#[cfg(all(test, target_os = "linux"))]
mod lookup_tests;
mod plan;
mod policy_state;
mod process;
mod query;
mod resolution;
mod schema;
mod scopes;
mod staging;
mod tool;
mod transport;
pub mod wire;

use core::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dwk_proto::dwkp::messages::Ack;
use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{CapId, InvocationId, ProcessId, RunId, SessionId};
use dwk_proto::wire::scalar::{
    Epoch, FsFailureReason, FsRefusalReason, RefusalReason, RefusedOperation, ToolOperation,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior};

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation,
};
use crate::policy::{PolicyContext, TaintLevel};

/// The operator configuration flags a [`StartupConfig`] carries, re-exported so
/// the state API is self-contained for its callers (the DWKP server).
pub use crate::policy::ConfigFlags;
pub use admission::{Admission, Grant, Withheld, WithheldCause, request_digest};
pub use audit::{
    AUDIT_FORMAT_VERSION, AuditEvent, AuditLogFault, AuditLogSummary, AuditRecord,
    MAX_RECORD_BYTES, RecordFault, StoreAuditFault, StoreComparison, read_audit_log,
    verify_audit_against_store, verify_audit_log,
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
pub use plan::{PlannedAction, RetryClass, ToolPlan, ToolVersion};
pub use policy_state::{MAX_CEILING_CAPABILITIES, MAX_POLICY_SOURCES, PolicySet, PolicySource};
pub use process::{
    Floor, Launch, ProcessAction, ProcessOutput, ProcessPlan, ProcessReply, ProcessRequest,
    StreamSnapshot,
};
pub use query::{AuthorityAnswer, DecisionRecord, Proposal, TaintCause, Undecidable};
pub use resolution::ResolutionRefused;
pub use staging::{MAX_RECLAIMS_PER_SWEEP, Settled};
pub use tool::{ToolReply, ToolRequest};
pub use transport::{TransportClass, TransportEvent, Violation};
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

/// How to run: which clock, whether a crash hook is consulted, and which
/// broker performs authorised effects.
#[derive(Clone)]
pub struct StartOptions {
    /// Authority time.
    pub clock: Arc<dyn Clock>,
    /// Consulted at every [`CrashPoint`]. See [`crash`](self::crash).
    pub crash_hook: Option<CrashHook>,
    /// The broker that performs an invocation both gates allowed (M4b). With
    /// none, every allowed invocation fails `BROKER_UNAVAILABLE` after its
    /// intent is recorded: this authority decides, and performs nothing.
    pub broker: Option<Arc<dyn EffectBroker>>,
}

impl Default for StartOptions {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            crash_hook: None,
            broker: None,
        }
    }
}

impl fmt::Debug for StartOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartOptions")
            .field("clock", &self.clock)
            .field("crash_hook", &self.crash_hook.is_some())
            .field("broker", &self.broker)
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
    /// Tool invocations without effect the previous process authorised and
    /// never finished, now recorded as interrupted (M4b).
    pub invocations_interrupted: u64,
    /// Tool invocations with an effect the previous process authorised and
    /// never finished, now recorded as unknown — and never performed again
    /// (M4c).
    pub invocations_unknown: u64,
    /// The start-up sweep of staging directories invocations may have left
    /// behind (M4c, ADR-0044 §10).
    pub staging: StagingSweep,
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

/// How many staging records the sweep after an invocation with an effect
/// settles, at most.
const RECLAIMS_AFTER_AN_EFFECT: usize = 4;

/// What one sweep of `EXPECTED` staging records settled (ADR-0044 §10).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagingSweep {
    /// No staging directory was there.
    pub absent: u64,
    /// Removed: provably only the broker's own uncommitted data.
    pub removed: u64,
    /// Retained: a workspace object, or the evidence of an effect.
    pub retained: u64,
    /// Something by that name that is not the broker's; untouched.
    pub foreign: u64,
    /// Not reached this time — no broker, no root, a moved parent, no
    /// answer: still `EXPECTED`, still tracked.
    pub pending: u64,
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
    broker: Option<Arc<dyn EffectBroker>>,
    /// The authority's own uid: the owner of its state directory, which
    /// start-up proved is the effective uid. With root, the only owner an
    /// executable's identity may rest on (ADR-0045 §5).
    authority_uid: u32,
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

    /// This process's incarnation.
    pub(crate) fn incarnation(&self) -> u64 {
        self.shared.incarnation.load(Ordering::SeqCst)
    }

    pub(crate) fn invocation_id(&self) -> Result<InvocationId, AuthorityError> {
        InvocationId::from_uuid(self.next_uuid()?).ok_or(AuthorityError::Invariant(
            "a minted invocation id is not a UUIDv7",
        ))
    }

    /// A process handle (M4d): opaque, minted with the launch intent, never a
    /// pid.
    pub(crate) fn process_id(&self) -> Result<ProcessId, AuthorityError> {
        ProcessId::from_uuid(self.next_uuid()?).ok_or(AuthorityError::Invariant(
            "a minted process id is not a UUIDv7",
        ))
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

        // The configured directory is created if missing and checked as
        // configured; then its ancestors are resolved, once, and every state
        // path below -- every SQLite open included -- is built from the
        // resolved directory, which is checked again. `NOFOLLOW` refuses a
        // path with a symlink in any component, and the state directory
        // itself is never followed (`files::resolve_directory`).
        files::prepare_directory(dir)?;
        files::check_directory(dir)?;
        let resolved = files::resolve_directory(dir)?;
        files::check_directory(&resolved)?;
        let paths = StatePaths::new(&resolved);
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

        let authority_uid = files::owner_uid(&resolved)?;
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
            broker: options.broker,
            authority_uid,
            _lock: lock,
        });
        let mut authority = Self { shared, conn };

        let (
            incarnation,
            leases_invalidated,
            runs_reaped,
            (invocations_interrupted, invocations_unknown),
        ) = authority.begin_incarnation(created, &recovered)?;
        let activation_id = authority.activate(&prepared, config.mode, config.flags, &ceiling)?;
        // What a previous incarnation's invocations may have left in a
        // workspace is judged now; nothing is performed again.
        let staging = authority.reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)?;
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
            invocations_interrupted,
            invocations_unknown,
            staging,
            audit_reconciled: recovered.reconciled,
            audit_appended: recovered.appended,
            audit_torn_tail_bytes: recovered.torn_tail_bytes,
            policy_revision: revision,
            activation_id,
        };
        Ok((authority, report))
    }

    /// A new incarnation: nothing the previous process held is still held.
    /// Returns the incarnation and how many leases, runs and tool invocations
    /// it ended.
    fn begin_incarnation(
        &mut self,
        created: bool,
        recovered: &audit::Recovered,
    ) -> Result<(u64, u64, u64, (u64, u64)), AuthorityError> {
        let (incarnation, leases, runs, ended) = self.transact(|work| {
            let incarnation: i64 = work.db(work.tx.query_row(
                "UPDATE store_meta SET incarnation = incarnation + 1 WHERE singleton = 1                  RETURNING incarnation",
                [],
                |row| row.get(0),
            ))?;
            let incarnation = u64::try_from(incarnation)
                .map_err(|_| AuthorityError::Invariant("the incarnation is negative"))?;
            let (leases, runs) = lease::invalidate_all(work)?;
            let (fs_interrupted, fs_unknown) = tool::reconcile_open(work)?;
            let (process_interrupted, process_unknown) = process::reconcile_open(work)?;
            let interrupted = fs_interrupted.saturating_add(process_interrupted);
            let unknown = fs_unknown.saturating_add(process_unknown);
            work.audit(
                AuditEvent::StoreOpened,
                Fields::new()
                    .int("incarnation", incarnation)
                    .int("schema_version", u64::try_from(schema::CURRENT_VERSION).unwrap_or(0))
                    .flag("created", created)
                    .int("leases_invalidated", leases)
                    .int("runs_reaped", runs)
                    .int("invocations_interrupted", interrupted)
                    .int("invocations_unknown", unknown)
                    .int("audit_reconciled", recovered.reconciled)
                    .int("audit_appended", recovered.appended)
                    .int("audit_torn_tail_bytes", recovered.torn_tail_bytes),
            )?;
            Ok((incarnation, leases, runs, (interrupted, unknown)))
        })?;
        self.shared.incarnation.store(incarnation, Ordering::SeqCst);
        Ok((incarnation, leases, runs, ended))
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
    /// The DWKP server (M3e) calls this exactly once per accepted socket, with
    /// the subject the kernel reported for it. **This module performs no
    /// authentication**: the subject is whatever the caller asserts.
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

    /// The state directory, as the authority uses it: on Unix, the configured
    /// directory with its ancestors resolved — the one path every state file
    /// operation and every SQLite open is built from.
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
        let mut resolved: Option<scopes::Resolutions> = None;
        for pass in 1..=admission::PASSES {
            let last = pass == admission::PASSES;
            let answer = self.transact(|work| {
                admission::admit(work, caller, message, active, resolved.as_ref(), last)
            })?;
            match answer {
                admission::Pass::Answered(reply) => return Ok(reply),
                // No transaction is open: the M4a resolver, beneath the
                // session's pinned root (ADR-0043 §8).
                admission::Pass::Resolve {
                    binding,
                    paths,
                    executables,
                } => {
                    // Keep what an earlier pass already resolved: a pass asks
                    // only for what it has no answer to.
                    let previous = resolved.take();
                    let fs = match binding {
                        Some(binding) => scopes::resolve_paths(&binding, &paths),
                        None => previous.clone().unwrap_or_else(scopes::Resolutions::empty),
                    };
                    let answers = if executables.is_empty() {
                        previous.map_or_else(scopes::Executables::new, |p| p.executables().clone())
                    } else {
                        scopes::resolve_executables(&executables, shared.authority_uid)
                    };
                    resolved = Some(fs.with_executables(answers));
                }
            }
        }
        Err(AuthorityError::Invariant(
            "an admission's last pass asked to resolve",
        ))
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

    /// Pin the workspace root of an active run (M4a, ADR-0042 §8): open the
    /// operator's bound path and prove it is the directory that was installed.
    ///
    /// The result is an anchor held by descriptor; nothing resolved beneath it
    /// is affected by what later happens to the path. In-process only: no DWKP
    /// operation reaches it.
    ///
    /// # Errors
    ///
    /// [`ResolutionRefused`], and [`ResolutionRefused::Root`] with
    /// [`RootError::Replaced`](crate::resource::fs::RootError::Replaced) when
    /// the path now names a different directory.
    pub fn pin_run_workspace(
        &mut self,
        run: &RunId,
    ) -> Result<crate::resource::fs::PinnedRoot, ResolutionRefused> {
        let binding = self.transact(|work| resolution::run_root(work, run.as_str()))??;
        crate::resource::fs::PinnedRoot::reopen(&binding.host_path, &binding.fingerprint)
            .map_err(ResolutionRefused::Root)
    }

    /// Resolve a declared path for an active run, beneath its pinned workspace
    /// root (M4a, ADR-0042). The one production entry point from a declaration
    /// to a canonical filesystem object; M4b's `ToolInvoke` and
    /// `CanonicalPreview` will call it.
    ///
    /// Performs no effect and writes no audit record: the result is a
    /// canonical path, an identity and a checked handle, and what may be done
    /// with them is a later, separate decision.
    ///
    /// # Errors
    ///
    /// [`ResolutionRefused`], naming the class of refusal.
    pub fn resolve_for_run(
        &mut self,
        run: &RunId,
        declared: &crate::capability::DeclaredPath,
        access: crate::resource::fs::Access,
        expect: crate::resource::fs::Expect,
    ) -> Result<crate::resource::fs::ResolvedResource, ResolutionRefused> {
        let root = self.pin_run_workspace(run)?;
        root.resolve(declared, access, expect)
            .map_err(ResolutionRefused::Resolve)
    }

    /// `ToolInvoke` (M4b, ADR-0043; every filesystem tool, M4c, ADR-0044), in
    /// the order `state::tool` sets out: locate; resolve every target beneath
    /// the pinned root (`O_PATH` only, no transaction); build the plan and
    /// decide every action of it, and — if every action is allowed — record
    /// the intent durably; **only then** make the effect-capable descriptors;
    /// the broker; the outcome (completed, failed, or unknown), durably — and
    /// only then answer.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook
    /// stopping at a [`CrashPoint::TOOL`] point poisons the store, as a crash
    /// would.
    pub fn tool_invoke(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &ToolRequest,
    ) -> Result<ToolReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = tool::Asked {
            caller,
            operation: ToolOperation::ToolInvoke,
            session,
            run,
            epoch,
            request,
        };
        let (call, targets) = match self.resolve_call(&asked)? {
            Ok(found) => found,
            Err(reason) => return Ok(ToolReply::Refused(asked.operation, reason)),
        };
        let decided = self.transact(|work| tool::decide(work, &asked, &call, &targets, active))?;
        let (plan, invocation) = match decided {
            tool::Decided::Refused(reason) => {
                return Ok(ToolReply::Refused(asked.operation, reason));
            }
            tool::Decided::Denied(plan) => return Ok(ToolReply::Denied(plan)),
            tool::Decided::Previewed(_) => {
                return Err(AuthorityError::Invariant(
                    "an invocation was answered as a preview",
                ));
            }
            tool::Decided::Authorised { plan, invocation } => (plan, invocation),
        };
        // The intent is committed and its audit record fsynced. Until here
        // nothing could perform an effect: the resolver holds `O_PATH` handles.
        shared.crash(CrashPoint::ToolAfterIntent)?;

        // Only now: the descriptors the operation needs, each proved to be
        // the object checked, a vacant name re-proved vacant.
        let decided_call = call.clone();
        let operation = match tool::handoff(call, targets) {
            Ok(operation) => operation,
            Err(failure) => {
                let reason = self.transact(|work| {
                    tool::record_handoff_failure(work, run, &invocation, failure)
                })?;
                return Ok(ToolReply::Failed { invocation, reason });
            }
        };
        shared.crash(CrashPoint::ToolAfterOpen)?;

        // No transaction is open; the broker is told nothing the intent
        // record does not already hold.
        let order = BrokerOrder::new(invocation.clone(), operation);
        let result = if let Some(broker) = &shared.broker {
            broker.perform(order)
        } else {
            drop(order);
            Err(BrokerError::before_sending(BrokerFailure::NotConfigured))
        };
        shared.crash(CrashPoint::ToolAfterBroker)?;

        // A staging directory is provably not left behind only when nothing
        // was sent, or the broker answered `done` with no debris.
        let sent_nothing = matches!(&result, Err(error) if !error.sent);
        let done_clean = matches!(
            &result,
            Ok(BrokerDelivery::Write { debris: false, .. }
                | BrokerDelivery::Patch { debris: false, .. }
                | BrokerDelivery::Delete { debris: false }
                | BrokerDelivery::Move)
        );
        // Whatever carried it, a delivery that does not fit what was decided
        // is not a result; an effect that is not proved is UNKNOWN.
        let (ending, detail) = tool::classify(&decided_call, &plan, result)?;
        let staging_clear =
            sent_nothing || (done_clean && matches!(ending, tool::Ending::Completed(_)));
        self.transact(|work| {
            tool::record_outcome(
                work,
                run,
                &invocation,
                plan.tool(),
                (&ending, detail),
                staging_clear,
            )
        })?;
        shared.crash(CrashPoint::ToolAfterOutcome)?;
        if plan::has_effect(plan.tool()) {
            // This run's staging records its invocations left EXPECTED —
            // this one's first, if it did — are judged now, while the broker
            // is at hand. Bounded; the rest wait for the next sweep.
            self.reclaim_staging(Some(run), RECLAIMS_AFTER_AN_EFFECT)?;
        }
        Ok(match ending {
            tool::Ending::Completed(completion) => ToolReply::Done {
                invocation,
                plan,
                output: Box::new(completion.output),
            },
            tool::Ending::Failed(reason) => ToolReply::Failed { invocation, reason },
            tool::Ending::Unknown => ToolReply::Failed {
                invocation,
                reason: FsFailureReason::OutcomeUnknown,
            },
        })
    }

    /// Settle staging records left `EXPECTED` — at most `limit`, of `run`
    /// only if given, oldest first, and only for invocations whose outcome is
    /// recorded (ADR-0044 §10). For each, the recorded parent directory is
    /// resolved beneath the run's pinned root and proved to be the one
    /// recorded, and the broker is asked to reclaim the invocation's staging
    /// directory: it removes it only if it provably holds nothing but its own
    /// uncommitted data, and otherwise keeps it and says what it holds. The
    /// invocation is never performed again, and its outcome never changes.
    ///
    /// Runs at start-up and after every invocation with an effect; an
    /// operator may run it at any time.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the store cannot record a settlement. A broker
    /// that cannot be reached settles nothing and is not an error: the records
    /// stay `EXPECTED`.
    pub fn reclaim_staging(
        &mut self,
        run: Option<&RunId>,
        limit: usize,
    ) -> Result<StagingSweep, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let mut sweep = StagingSweep::default();
        let Some(broker) = &shared.broker else {
            return Ok(sweep);
        };
        let pending = self.transact(|work| staging::pending(work, run, limit))?;
        for item in pending {
            let Some(directory) = staging::directory(&item) else {
                sweep.pending = sweep.pending.saturating_add(1);
                continue;
            };
            let order = BrokerOrder::new(
                item.invocation.clone(),
                Operation::Reclaim {
                    directory,
                    staging: item.spec.clone(),
                },
            );
            let result = broker.perform(order);
            let count = match self.transact(|work| staging::settle(work, &item, &result))? {
                Some(Settled::Absent) => &mut sweep.absent,
                Some(Settled::Removed) => &mut sweep.removed,
                Some(Settled::Retained) => &mut sweep.retained,
                Some(Settled::Foreign) => &mut sweep.foreign,
                None => &mut sweep.pending,
            };
            *count = count.saturating_add(1);
        }
        Ok(sweep)
    }

    /// `CanonicalPreview` (M4b, ADR-0043; M4c, ADR-0044): the same locate,
    /// resolution and plan as [`Authority::tool_invoke`] — so a preview names
    /// exactly the plan an invocation would decide on — stopping there. No
    /// invocation id, no key, no intent, nothing opened for an effect, no
    /// broker.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn tool_preview(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &ToolRequest,
    ) -> Result<ToolReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = tool::Asked {
            caller,
            operation: ToolOperation::CanonicalPreview,
            session,
            run,
            epoch,
            request,
        };
        let (call, targets) = match self.resolve_call(&asked)? {
            Ok(found) => found,
            Err(reason) => return Ok(ToolReply::Refused(asked.operation, reason)),
        };
        let decided = self.transact(|work| tool::decide(work, &asked, &call, &targets, active))?;
        // The resolved targets' `O_PATH` handles close here, unused.
        drop(targets);
        Ok(match decided {
            tool::Decided::Refused(reason) => ToolReply::Refused(asked.operation, reason),
            tool::Decided::Previewed(plan) => ToolReply::Previewed(plan),
            tool::Decided::Denied(_) | tool::Decided::Authorised { .. } => {
                return Err(AuthorityError::Invariant(
                    "a preview was answered as an invocation",
                ));
            }
        })
    }

    /// Steps 1 and 2 of a tool call: locate it (one transaction), then resolve
    /// every target beneath the run's pinned root with **no transaction open**
    /// — `O_PATH` descriptors only; nothing is opened for an effect. A refusal
    /// at either step is recorded and returned.
    fn resolve_call(
        &mut self,
        asked: &tool::Asked<'_>,
    ) -> Result<Result<(plan::Call, tool::Targets), FsRefusalReason>, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let located = self.transact(|work| tool::locate(work, asked, active))?;
        let (call, binding) = match located {
            tool::Located::Refused(reason) => return Ok(Err(reason)),
            tool::Located::At { call, binding } => (call, binding),
        };
        match tool::resolve_targets(&binding, &call) {
            Ok(targets) => Ok(Ok((call, targets))),
            Err(reason) => {
                self.transact(|work| tool::refuse(work, asked, reason))?;
                Ok(Err(reason))
            }
        }
    }

    /// `ToolInvoke` of a process tool (M4d, ADR-0045), in the order
    /// `state::process` sets out: locate; for a launch, resolve the
    /// executable and the working directory (no transaction); decide — the
    /// plan, both gates, the obligations and the **host floor** — and, if
    /// every one of them passes, record the intent durably; **only then** the
    /// executable descriptor; the broker; the outcome, durably — and only then
    /// answer.
    ///
    /// In every production build the floor refuses a host launch: no approval
    /// exists before M6 (`state::process`).
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook at a
    /// [`CrashPoint::TOOL`] point poisons the store, as a crash would.
    pub fn process_invoke(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &ProcessRequest,
    ) -> Result<ProcessReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = process::Asked {
            caller,
            operation: ToolOperation::ToolInvoke,
            session,
            run,
            epoch,
            request,
        };
        let (call, resolved, stored) = match self.locate_process(&asked)? {
            Ok(found) => found,
            Err(reason) => return Ok(ProcessReply::Refused(asked.operation, reason)),
        };
        let decided = self.transact(|work| {
            let located = located_ref(&call, resolved.as_ref(), stored.as_ref())?;
            process::decide(work, &asked, &located, active)
        })?;
        let (plan, invocation, process_id) = match decided {
            process::Decided::Refused(reason) => {
                return Ok(ProcessReply::Refused(asked.operation, reason));
            }
            process::Decided::Denied(plan) => return Ok(ProcessReply::Denied(plan)),
            process::Decided::Previewed(_) => {
                return Err(AuthorityError::Invariant(
                    "an invocation was answered as a preview",
                ));
            }
            process::Decided::Authorised {
                plan,
                invocation,
                process,
            } => (plan, invocation, process),
        };
        // The intent is committed and its audit record fsynced. Until here
        // nothing could launch: the resolver holds `O_PATH` handles.
        shared.crash(CrashPoint::ToolAfterIntent)?;

        let tool = plan.tool();
        let stream_limit = plan
            .action()
            .launch()
            .map(process::Launch::stream_limit)
            .or_else(|| stored.as_ref().map(process::StoredProcess::stream_limit));
        let operation = match process::handoff(call, resolved, &plan, &process_id, stored.as_ref())
        {
            Ok(operation) => operation,
            Err(failure) => {
                let reason =
                    self.process_handoff_failed(tool, run, &invocation, &process_id, failure)?;
                return Ok(ProcessReply::Failed { invocation, reason });
            }
        };
        shared.crash(CrashPoint::ToolAfterOpen)?;

        let order = BrokerOrder::new(invocation.clone(), operation);
        let result = if let Some(broker) = &shared.broker {
            broker.perform(order)
        } else {
            drop(order);
            Err(BrokerError::before_sending(BrokerFailure::NotConfigured))
        };
        shared.crash(CrashPoint::ToolAfterBroker)?;

        let generation = match &result {
            Ok(BrokerDelivery::ProcessStarted(started)) => Some(started.generation.clone()),
            _ => None,
        };
        let (ending, detail) = process::classify(tool, &process_id, stream_limit, result);
        self.transact(|work| {
            process::record_outcome(
                work,
                run,
                &invocation,
                (tool, &process_id),
                (&ending, detail),
                generation.as_ref(),
            )
        })?;
        shared.crash(CrashPoint::ToolAfterOutcome)?;
        Ok(match ending {
            process::Ending::Completed(output) => ProcessReply::Done {
                invocation,
                plan,
                output,
            },
            process::Ending::Failed(reason) => ProcessReply::Failed { invocation, reason },
            process::Ending::Unknown => ProcessReply::Failed {
                invocation,
                reason: dwk_proto::wire::scalar::ToolFailureReasonV3::OutcomeUnknown,
            },
        })
    }

    /// A process tool's hand-off could not be built after its intent was
    /// recorded: the invocation ends `FAILED`, durably, and nothing reached the
    /// broker. A launch's process record fails with it.
    fn process_handoff_failed(
        &mut self,
        tool: dwk_proto::wire::scalar::CoreTool,
        run: &RunId,
        invocation: &InvocationId,
        process_id: &ProcessId,
        failure: (dwk_proto::wire::scalar::ToolFailureReasonV3, &'static str),
    ) -> Result<dwk_proto::wire::scalar::ToolFailureReasonV3, AuthorityError> {
        if tool == dwk_proto::wire::scalar::CoreTool::ProcessExec {
            return self.transact(|work| {
                process::record_handoff_failure(work, run, invocation, process_id, failure)
            });
        }
        let ending = process::Ending::Failed(failure.0);
        self.transact(|work| {
            process::record_outcome(
                work,
                run,
                invocation,
                (tool, process_id),
                (&ending, None),
                None,
            )
        })?;
        Ok(failure.0)
    }

    /// `CanonicalPreview` of a process tool (M4d): the same locate, resolution
    /// and plan as [`Authority::process_invoke`], stopping there. No invocation
    /// id, no process id, no key, no intent, no descriptor, no broker.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn process_preview(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &ProcessRequest,
    ) -> Result<ProcessReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = process::Asked {
            caller,
            operation: ToolOperation::CanonicalPreview,
            session,
            run,
            epoch,
            request,
        };
        let (call, resolved, stored) = match self.locate_process(&asked)? {
            Ok(found) => found,
            Err(reason) => return Ok(ProcessReply::Refused(asked.operation, reason)),
        };
        let decided = self.transact(|work| {
            let located = located_ref(&call, resolved.as_ref(), stored.as_ref())?;
            process::decide(work, &asked, &located, active)
        })?;
        // The resolved handles close here, unused.
        drop(resolved);
        Ok(match decided {
            process::Decided::Refused(reason) => ProcessReply::Refused(asked.operation, reason),
            process::Decided::Previewed(plan) => ProcessReply::Previewed(plan),
            process::Decided::Denied(_) | process::Decided::Authorised { .. } => {
                return Err(AuthorityError::Invariant(
                    "a preview was answered as an invocation",
                ));
            }
        })
    }

    /// Steps 1 and 2 of a process call: locate it (one transaction), then —
    /// for a launch — resolve the executable and the working directory with
    /// **no transaction open**. A refusal at either step is recorded.
    #[expect(
        clippy::type_complexity,
        reason = "the three parts are consumed separately by the caller"
    )]
    fn locate_process(
        &mut self,
        asked: &process::Asked<'_>,
    ) -> Result<
        Result<
            (
                process::Call,
                Option<process::Resolved>,
                Option<process::StoredProcess>,
            ),
            dwk_proto::wire::scalar::ToolRefusalReasonV3,
        >,
        AuthorityError,
    > {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let located = self.transact(|work| process::locate(work, asked, active))?;
        match located {
            process::Located::Refused(reason) => Ok(Err(reason)),
            process::Located::Handle { call, stored } => Ok(Ok((call, None, Some(stored)))),
            process::Located::Launch { call, binding } => {
                match process::resolve_launch(&binding, &call, shared.authority_uid) {
                    Ok(resolved) => Ok(Ok((call, Some(resolved), None))),
                    Err((reason, detail)) => {
                        self.transact(|work| {
                            process::refuse_resolution(work, asked, reason, detail)
                        })?;
                        Ok(Err(reason))
                    }
                }
            }
        }
    }

    /// Answer one decoded DWKP request with the response body the M3e server
    /// sends.
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
            DwkpBody::ToolInvoke(invoke) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                let request = ToolRequest::v1(&invoke.fs_read);
                let reply = self.tool_invoke(caller, session, run, epoch, &request)?;
                wire::tool_reply(&reply).map_err(unrepresentable)
            }
            DwkpBody::CanonicalPreview(preview) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                let request = ToolRequest::v1(&preview.fs_read);
                let reply = self.tool_preview(caller, session, run, epoch, &request)?;
                wire::tool_reply(&reply).map_err(unrepresentable)
            }
            DwkpBody::ToolInvokeV2(call) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                let key = header.idempotency_key.clone().ok_or_else(missing)?;
                let request = ToolRequest::v2(call.clone(), Some(key));
                let reply = self.tool_invoke(caller, session, run, epoch, &request)?;
                wire::tool_reply_v2(&reply).map_err(unrepresentable)
            }
            DwkpBody::CanonicalPreviewV2(call) => {
                let session = session.ok_or_else(missing)?;
                let run = header.run_id.as_ref().ok_or_else(missing)?;
                let epoch = header.epoch.ok_or_else(missing)?;
                let request = ToolRequest::v2(call.clone(), None);
                let reply = self.tool_preview(caller, session, run, epoch, &request)?;
                wire::tool_reply_v2(&reply).map_err(unrepresentable)
            }
            DwkpBody::ToolInvokeV3(call) => self.dispatch_v3(caller, message, call, true),
            DwkpBody::CanonicalPreviewV3(call) => self.dispatch_v3(caller, message, call, false),
            _ => Err(AuthorityError::NotAnAuthorityRequest),
        }
    }

    /// `tool.invoke` (`invoke`) or `canonical.preview` at version 3: a process
    /// tool reaches the process layer (M4d), any other the tool layer.
    fn dispatch_v3(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
        call: &dwk_proto::dwkp::procops::ToolCallV3,
        invoke: bool,
    ) -> Result<DwkpBody, AuthorityError> {
        let header = &message.header;
        let missing = || AuthorityError::Invariant("a decoded request lacks an envelope field");
        let unrepresentable = |_: WireGap| {
            AuthorityError::Invariant("a stored value does not fit the wire type that carries it")
        };
        let session = header.session_id.as_ref().ok_or_else(missing)?;
        let run = header.run_id.as_ref().ok_or_else(missing)?;
        let epoch = header.epoch.ok_or_else(missing)?;
        let key = if invoke {
            Some(header.idempotency_key.clone().ok_or_else(missing)?)
        } else {
            None
        };
        if let Some(request) = ProcessRequest::new(call.clone(), key.clone()) {
            let reply = if invoke {
                self.process_invoke(caller, session, run, epoch, &request)?
            } else {
                self.process_preview(caller, session, run, epoch, &request)?
            };
            return wire::process_reply(&reply).map_err(unrepresentable);
        }
        let request = ToolRequest::v3(call, key).ok_or_else(missing)?;
        let reply = if invoke {
            self.tool_invoke(caller, session, run, epoch, &request)?
        } else {
            self.tool_preview(caller, session, run, epoch, &request)?
        };
        wire::tool_reply_v3(&reply).map_err(unrepresentable)
    }

    /// Record a security-significant transport event (M3e): a refused peer,
    /// a refused connection, a protocol violation, or a count of records the
    /// server's rate limit withheld.
    ///
    /// The DWKP server's one audit entry point. It takes a closed
    /// [`TransportEvent`], never text or bytes, so nothing a peer sends can
    /// choose a field; no DWKP operation reaches it. The record is durable
    /// before this returns, like every other.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the record could not be made durable; a failed
    /// append or `fsync` poisons the store, as for any operation.
    pub fn record_transport_event(&mut self, event: &TransportEvent) -> Result<(), AuthorityError> {
        let (kind, fields) = event.record();
        self.transact(|work| work.audit(kind, fields))
    }

    /// The operator's configuration API. **In-process only**: no DWKP
    /// operation reaches it. See [`OperatorBootstrap`].
    pub fn operator(&mut self) -> OperatorBootstrap<'_> {
        OperatorBootstrap { authority: self }
    }
}

/// What step 3 of a process call decides from.
fn located_ref<'a>(
    call: &'a process::Call,
    resolved: Option<&'a process::Resolved>,
    stored: Option<&'a process::StoredProcess>,
) -> Result<process::LocatedRef<'a>, AuthorityError> {
    match (resolved, stored) {
        (Some(resolved), None) => Ok(process::LocatedRef::Launch { call, resolved }),
        (None, Some(stored)) => Ok(process::LocatedRef::Handle { call, stored }),
        _ => Err(AuthorityError::Invariant(
            "a process call is neither a launch nor a handle",
        )),
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

    /// Bind a workspace to the filesystem directory at `host_path` (M4a,
    /// ADR-0042 §8).
    ///
    /// The directory is opened and measured here — a real directory, not a
    /// symlink, not on procfs or sysfs — and the binding records the path and
    /// the identity it had: device, inode and, where the filesystem reports
    /// one, birth time. Every later resolution for a run in this workspace
    /// reopens the path and proves it is still that directory, so replacing
    /// the directory at the path redirects nothing.
    ///
    /// Once per workspace. The same binding again is a no-op; a different one
    /// is refused, because a different root is a different workspace. Audited
    /// as `config.workspace_root_installed`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for an unknown workspace, a path that cannot
    /// be pinned (with the [`RootError`](crate::resource::fs::RootError) code),
    /// or a workspace already bound to another root.
    pub fn install_workspace_root(
        &mut self,
        id: &WorkspaceId,
        host_path: &str,
    ) -> Result<(), ConfigError> {
        let (_measured, fingerprint) = crate::resource::fs::PinnedRoot::install(host_path)
            .map_err(|error| ConfigError::Invalid(format!("workspace root: {error}")))?;
        let binding = config::RootBinding {
            host_path: host_path.to_owned(),
            fingerprint,
        };
        self.run(|tx, now, audit| config::install_workspace_root(tx, now, id, &binding, audit))
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
        Ok(Shape::Older(version)) => migrate_store(&mut conn, version, now_ms)?,
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

/// Migrate an older store forward in one transaction, and record that it
/// happened in the same transaction; a failure rolls both back.
///
/// The record is appended to the outbox like every other and reaches
/// `audit.log` through the startup reconciliation that follows, so a
/// structural change to the store is on the chain before anything is served
/// from it (ADR-0042 §8).
fn migrate_store(conn: &mut Connection, from: i64, now_ms: u64) -> Result<(), StartError> {
    let failed = |error: rusqlite::Error| StartError::Migration(error.to_string());
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let to = schema::migrate(&tx, from, schema::MIGRATIONS).map_err(failed)?;
    audit::append(
        &tx,
        now_ms,
        AuditEvent::StoreMigrated,
        Fields::new()
            .int("from_schema_version", u64::try_from(from).unwrap_or(0))
            .int("to_schema_version", u64::try_from(to).unwrap_or(0)),
    )
    .map_err(|error| match error {
        audit::AuditAppendError::Sqlite(error) => failed(error),
        audit::AuditAppendError::Authority(error) => StartError::Migration(error.to_string()),
    })?;
    tx.commit().map_err(failed)
}
