//! The hash-chained audit log, its transactional outbox, crash
//! reconciliation, and a read-only verifier.
//!
//! # Two durable objects, no shared transaction
//!
//! `audit.log` is the authoritative, append-only security record, and it is a
//! separate file from `kernel.db` ([ADR-0009], [ADR-0010]). Nothing spans both,
//! and nothing here pretends otherwise. The design that closes the gap is a
//! **transactional outbox**:
//!
//! 1. In the **same SQLite transaction** as the authority mutation, allocate
//!    the next sequence number, build the canonical record, chain it to the
//!    head, insert it into `audit_chain`, and advance `audit_head`.
//! 2. **Commit.** The mutation and its record are now durable together, in
//!    `kernel.db`, or neither is.
//! 3. Append every record past `audit_state.flushed_seq` to `audit.log`, in
//!    sequence order, and `fsync`.
//! 4. Record the flush in `audit_state`.
//! 5. **Only then** return authority to the caller.
//!
//! A crash between 2 and 4 leaves a record in `kernel.db` that `audit.log` may
//! or may not hold, whole or in part. [`recover`] resolves every such state
//! without guessing, and refuses to start when the two files tell stories that
//! no crash can explain.
//!
//! # Record format
//!
//! One record per line: the RFC 8785 canonical JSON of an object, then `\n`.
//!
//! ```text
//! { "v": 1, "seq": n, "prev": hex(H_{n-1}), "ts_ms": t, "event": "...",
//!   ...event fields..., "hash": hex(H_n) }
//! ```
//!
//! The field set of every event is fixed by the code that emits it — there is
//! no free-form map. Integers only; no floats, so no formatting ambiguity.
//! Records carry identifiers, decisions and capability text: never a secret,
//! never prompt content, never tool output, never a credential value.
//!
//! # Hash chain
//!
//! ```text
//! C_n  = JCS(record_n without "hash")
//! H_n  = SHA-256( "direwolf.audit.record.v1" || 0x00
//!                 || u64be(32) || H_{n-1}
//!                 || u64be(len(C_n)) || C_n )
//! H_0  = 32 zero bytes          (the genesis predecessor; seq starts at 1)
//! ```
//!
//! `C_n` contains `seq` and `prev`, so a record is bound to its position; the
//! hash is over canonical bytes, so field order and number formatting cannot
//! change it. Sequence numbers are gapless: record `n` is the `n`-th line, and
//! any gap, repeat or reordering breaks the `prev` linkage at the next record.
//!
//! # Tamper-evident, not tamper-proof
//!
//! The chain detects modification of a record, deletion or reordering inside
//! the log, a record whose hash was recomputed without its successors, and —
//! compared with `kernel.db`'s copy and flushed mark — truncation of records
//! that were acknowledged as durable. It does **not** stop an attacker who can
//! rewrite `audit.log` *and* every copy of the head this host keeps, together
//! and consistently. Anchoring the head off-host is future operational work
//! ([ADR-0010], [ADR-0017]); M3d does not claim it.
//!
//! [ADR-0009]: ../../../../../docs/adr/0009-storage-strategy.md
//! [ADR-0010]: ../../../../../docs/adr/0010-event-model.md
//! [ADR-0017]: ../../../../../docs/adr/0017-observability-vs-audit.md

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use dwk_proto::json::{self, Number, Object, ParseOptions, Value};
use rusqlite::Connection;

use super::crash::CrashPoint;
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;

/// The record format this build writes and verifies.
pub const AUDIT_FORMAT_VERSION: u64 = 1;

/// The longest line a record may be. A `run.admitted` record with the wire's
/// maximum of 64 grants and 64 withheld capabilities is far below it; a line
/// past it is refused rather than buffered.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Keys the record envelope owns. An event field may not reuse one.
const RESERVED_KEYS: [&str; 6] = ["v", "seq", "prev", "ts_ms", "event", "hash"];

/// Every kind of audit record. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditEvent {
    /// The store was created. Always record 1.
    StoreCreated,
    /// The authority started: a new incarnation, and what recovery did.
    StoreOpened,
    /// A policy revision was recorded for the first time.
    PolicyInstalled,
    /// A new policy revision, mode, ceiling or flag set became active.
    AuthorityActivated,
    /// An operator installed an agent profile revision.
    AgentProfileInstalled,
    /// An operator installed a skill revision.
    SkillInstalled,
    /// An operator installed or tightened a workspace.
    WorkspaceInstalled,
    /// An operator bound a session to a workspace.
    SessionWorkspaceBound,
    /// A lease was granted, with a new epoch.
    LeaseAcquired,
    /// A lease was released by its holder.
    LeaseReleased,
    /// A lease operation was refused: `LEASE_HELD` or `STALE_EPOCH`.
    LeaseRefused,
    /// A run was admitted and its authority minted.
    RunAdmitted,
    /// An `AdmitRun` retry was answered with the recorded grant.
    RunAdmitReplayed,
    /// An `AdmitRun` was refused.
    RunAdmitRefused,
    /// A run was released by its holder.
    RunReleased,
    /// A run's authority ended because its lease did.
    RunReaped,
    /// A `ReleaseRun` was refused (`STALE_EPOCH`).
    RunReleaseRefused,
    /// Both gates decided a proposed action.
    AuthorityDecision,
    /// A `QueryAuthority` was refused.
    QueryRefused,
    /// A run's taint became more restrictive.
    TaintRaised,
    /// The DWKP server refused a connection whose kernel-reported uid the
    /// operator's peer policy does not name, before reading a byte from it.
    TransportPeerRefused,
    /// The DWKP server refused an allowed peer's connection because it was at
    /// its connection limit.
    TransportConnectionRefused,
    /// The DWKP server closed a connection for a protocol violation.
    TransportProtocolViolation,
    /// Transport records the rate limit withheld, counted rather than written.
    TransportAuditSuppressed,
    /// An operator bound a workspace to a filesystem root (M4a): the recorded
    /// host path and the identity the directory had when it was measured.
    WorkspaceRootInstalled,
    /// `kernel.db` was migrated to a newer schema version.
    StoreMigrated,
}

impl AuditEvent {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 26] = [
        Self::StoreCreated,
        Self::StoreOpened,
        Self::PolicyInstalled,
        Self::AuthorityActivated,
        Self::AgentProfileInstalled,
        Self::SkillInstalled,
        Self::WorkspaceInstalled,
        Self::SessionWorkspaceBound,
        Self::LeaseAcquired,
        Self::LeaseReleased,
        Self::LeaseRefused,
        Self::RunAdmitted,
        Self::RunAdmitReplayed,
        Self::RunAdmitRefused,
        Self::RunReleased,
        Self::RunReaped,
        Self::RunReleaseRefused,
        Self::AuthorityDecision,
        Self::QueryRefused,
        Self::TaintRaised,
        Self::TransportPeerRefused,
        Self::TransportConnectionRefused,
        Self::TransportProtocolViolation,
        Self::TransportAuditSuppressed,
        Self::WorkspaceRootInstalled,
        Self::StoreMigrated,
    ];

    /// The spelling in a record's `event` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreCreated => "store.created",
            Self::StoreOpened => "store.opened",
            Self::PolicyInstalled => "policy.installed",
            Self::AuthorityActivated => "authority.activated",
            Self::AgentProfileInstalled => "config.agent_profile_installed",
            Self::SkillInstalled => "config.skill_installed",
            Self::WorkspaceInstalled => "config.workspace_installed",
            Self::SessionWorkspaceBound => "config.session_workspace_bound",
            Self::LeaseAcquired => "lease.acquired",
            Self::LeaseReleased => "lease.released",
            Self::LeaseRefused => "lease.refused",
            Self::RunAdmitted => "run.admitted",
            Self::RunAdmitReplayed => "run.admit_replayed",
            Self::RunAdmitRefused => "run.admit_refused",
            Self::RunReleased => "run.released",
            Self::RunReaped => "run.reaped",
            Self::RunReleaseRefused => "run.release_refused",
            Self::AuthorityDecision => "authority.decision",
            Self::QueryRefused => "authority.query_refused",
            Self::TaintRaised => "run.taint_raised",
            Self::TransportPeerRefused => "transport.peer_refused",
            Self::TransportConnectionRefused => "transport.connection_refused",
            Self::TransportProtocolViolation => "transport.protocol_violation",
            Self::TransportAuditSuppressed => "transport.audit_suppressed",
            Self::WorkspaceRootInstalled => "config.workspace_root_installed",
            Self::StoreMigrated => "store.migrated",
        }
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One field value. Typed, and closed: text, a safe integer, a flag, a list,
/// or a nested object with code-fixed keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Field {
    Text(String),
    Int(u64),
    Flag(bool),
    List(Vec<Field>),
    Object(Vec<(&'static str, Field)>),
}

/// An event's fields. Keys are `&'static str`: chosen by the code that emits
/// the event, never by input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Fields(Vec<(&'static str, Field)>);

impl Fields {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn text(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.0.push((key, Field::Text(value.into())));
        self
    }

    pub(crate) fn int(mut self, key: &'static str, value: u64) -> Self {
        self.0.push((key, Field::Int(value)));
        self
    }

    pub(crate) fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.0.push((key, Field::Flag(value)));
        self
    }

    pub(crate) fn maybe_text(self, key: &'static str, value: Option<String>) -> Self {
        match value {
            Some(text) => self.text(key, text),
            None => self,
        }
    }

    pub(crate) fn list(mut self, key: &'static str, items: Vec<Field>) -> Self {
        self.0.push((key, Field::List(items)));
        self
    }

    /// Append another set of fields, in order.
    pub(crate) fn extend(&mut self, more: Self) {
        self.0.extend(more.0);
    }
}

fn field_value(field: &Field) -> Result<Value, AuthorityError> {
    Ok(match field {
        Field::Text(text) => Value::String(text.clone()),
        Field::Int(value) => Value::Number(safe_integer(*value)?),
        Field::Flag(value) => Value::Bool(*value),
        Field::List(items) => Value::Array(
            items
                .iter()
                .map(field_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Field::Object(members) => {
            let mut object = Object::new();
            for (key, value) in members {
                insert(&mut object, key, field_value(value)?)?;
            }
            Value::Object(object)
        }
    })
}

fn safe_integer(value: u64) -> Result<Number, AuthorityError> {
    if value > MAX_SAFE_INTEGER {
        return Err(AuthorityError::Invariant("an audit integer exceeds 2^53-1"));
    }
    i64::try_from(value)
        .ok()
        .and_then(Number::from_i64)
        .ok_or(AuthorityError::Invariant(
            "an audit integer is not representable",
        ))
}

fn insert(object: &mut Object, key: &str, value: Value) -> Result<(), AuthorityError> {
    object
        .insert(key.to_owned(), value)
        .map_err(|_| AuthorityError::Invariant("an audit record repeats a key"))
}

/// The record without its hash, as a JSON object.
fn unsigned_record(
    seq: u64,
    prev: &Sha256Hash,
    ts_ms: u64,
    event: AuditEvent,
    fields: Fields,
) -> Result<Object, AuthorityError> {
    let mut object = Object::new();
    insert(
        &mut object,
        "v",
        Value::Number(safe_integer(AUDIT_FORMAT_VERSION)?),
    )?;
    insert(&mut object, "seq", Value::Number(safe_integer(seq)?))?;
    insert(&mut object, "prev", Value::String(prev.to_hex()))?;
    insert(&mut object, "ts_ms", Value::Number(safe_integer(ts_ms)?))?;
    insert(
        &mut object,
        "event",
        Value::String(event.as_str().to_owned()),
    )?;
    for (key, field) in fields.0 {
        if RESERVED_KEYS.contains(&key) {
            return Err(AuthorityError::Invariant(
                "an audit event reuses a reserved key",
            ));
        }
        insert(&mut object, key, field_value(&field)?)?;
    }
    Ok(object)
}

/// `H_n` from `H_{n-1}` and `C_n`.
fn chain_hash(prev: &Sha256Hash, canonical_without_hash: &[u8]) -> Sha256Hash {
    DomainHash::new(digest::AUDIT_RECORD)
        .bytes(prev.as_bytes())
        .bytes(canonical_without_hash)
        .finish()
}

/// Append one record to the outbox, **inside the caller's transaction**.
///
/// Returns the record's sequence number. The caller must commit the
/// transaction and then flush through that number before it returns any
/// authority the record describes.
pub(crate) fn append(
    tx: &Connection,
    ts_ms: u64,
    event: AuditEvent,
    fields: Fields,
) -> Result<u64, AuditAppendError> {
    let (head_seq, head_hash): (i64, String) = tx.query_row(
        "SELECT seq, hash FROM audit_head WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let prev = Sha256Hash::from_hex(&head_hash).ok_or(AuthorityError::Invariant(
        "the audit head hash is malformed",
    ))?;
    let seq = u64::try_from(head_seq)
        .ok()
        .and_then(|seq| seq.checked_add(1))
        .ok_or(AuthorityError::Invariant(
            "the audit head sequence is malformed",
        ))?;

    let mut record = unsigned_record(seq, &prev, ts_ms, event, fields)?;
    let hash = chain_hash(
        &prev,
        &json::to_canonical_bytes(&Value::Object(record.clone())),
    );
    insert(&mut record, "hash", Value::String(hash.to_hex()))?;
    let line = json::to_canonical_bytes(&Value::Object(record));
    if line.len() > MAX_RECORD_BYTES {
        return Err(AuthorityError::Invariant("an audit record exceeds its bound").into());
    }

    let sql_seq =
        i64::try_from(seq).map_err(|_| AuthorityError::Invariant("audit sequence overflow"))?;
    tx.execute(
        "INSERT INTO audit_chain (seq, prev, hash, record) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![sql_seq, prev.to_hex(), hash.to_hex(), line],
    )?;
    tx.execute(
        "UPDATE audit_head SET seq = ?1, hash = ?2 WHERE singleton = 1",
        rusqlite::params![sql_seq, hash.to_hex()],
    )?;
    Ok(seq)
}

/// Why an append failed: SQLite, or an invariant of the record itself.
#[derive(Debug)]
pub(crate) enum AuditAppendError {
    Sqlite(rusqlite::Error),
    Authority(AuthorityError),
}

impl From<rusqlite::Error> for AuditAppendError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<AuthorityError> for AuditAppendError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

// ---------------------------------------------------------------------------
// Reading and verifying records.
// ---------------------------------------------------------------------------

/// What is wrong with one line of `audit.log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFault {
    /// Not a JSON object under the strict profile.
    NotJson,
    /// Valid JSON, but not the canonical (RFC 8785) bytes of itself — a
    /// record was re-serialised, re-ordered or padded.
    NotCanonical,
    /// A required envelope field is absent or of the wrong type.
    MissingField(&'static str),
    /// A format version this build does not verify.
    UnsupportedVersion(u64),
    /// The record's `seq` is not the next one: a deletion, a duplicate, or a
    /// reordering.
    Sequence {
        /// What the position required.
        expected: u64,
        /// What the record says.
        found: u64,
    },
    /// `prev` is not the previous record's hash.
    PrevMismatch,
    /// Recomputing `H_n` does not give the record's `hash`: the record was
    /// modified.
    HashMismatch,
    /// Longer than [`MAX_RECORD_BYTES`].
    Oversized,
}

impl fmt::Display for RecordFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson => f.write_str("not a JSON object"),
            Self::NotCanonical => f.write_str("not in canonical form"),
            Self::MissingField(name) => write!(f, "missing or mistyped field `{name}`"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported record version {v}"),
            Self::Sequence { expected, found } => {
                write!(f, "sequence {found} where {expected} was expected")
            }
            Self::PrevMismatch => f.write_str("prev does not match the previous record's hash"),
            Self::HashMismatch => f.write_str("the recomputed hash does not match"),
            Self::Oversized => write!(f, "longer than {MAX_RECORD_BYTES} bytes"),
        }
    }
}

/// A verified record's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) seq: u64,
    pub(crate) hash: Sha256Hash,
}

fn uint(object: &Object, key: &'static str) -> Result<u64, RecordFault> {
    match object.get(key) {
        Some(Value::Number(Number::Int(value))) => {
            u64::try_from(*value).map_err(|_| RecordFault::MissingField(key))
        }
        _ => Err(RecordFault::MissingField(key)),
    }
}

fn hash_field(object: &Object, key: &'static str) -> Result<Sha256Hash, RecordFault> {
    match object.get(key) {
        Some(Value::String(text)) => {
            Sha256Hash::from_hex(text).ok_or(RecordFault::MissingField(key))
        }
        _ => Err(RecordFault::MissingField(key)),
    }
}

/// Verify one line (without its newline) as record `expected_seq`, chained to
/// `expected_prev`. Every hash is **recomputed**; nothing stored is believed.
pub(crate) fn verify_line(
    line: &[u8],
    expected_seq: u64,
    expected_prev: &Sha256Hash,
) -> Result<Verified, RecordFault> {
    if line.len() > MAX_RECORD_BYTES {
        return Err(RecordFault::Oversized);
    }
    let Ok(Value::Object(mut object)) = json::parse(line, ParseOptions::dwkp()) else {
        return Err(RecordFault::NotJson);
    };
    if json::to_canonical_bytes(&Value::Object(object.clone())) != line {
        return Err(RecordFault::NotCanonical);
    }
    let version = uint(&object, "v")?;
    if version != AUDIT_FORMAT_VERSION {
        return Err(RecordFault::UnsupportedVersion(version));
    }
    let seq = uint(&object, "seq")?;
    if seq != expected_seq {
        return Err(RecordFault::Sequence {
            expected: expected_seq,
            found: seq,
        });
    }
    if &hash_field(&object, "prev")? != expected_prev {
        return Err(RecordFault::PrevMismatch);
    }
    uint(&object, "ts_ms")?;
    if !matches!(object.get("event"), Some(Value::String(_))) {
        return Err(RecordFault::MissingField("event"));
    }
    let claimed = hash_field(&object, "hash")?;
    object.remove("hash");
    let recomputed = chain_hash(
        expected_prev,
        &json::to_canonical_bytes(&Value::Object(object)),
    );
    if recomputed != claimed {
        return Err(RecordFault::HashMismatch);
    }
    Ok(Verified { seq, hash: claimed })
}

/// One piece of `audit.log`.
#[derive(Debug)]
enum Chunk {
    /// A complete line, without its newline, and the offset it starts at.
    Line(Vec<u8>),
    /// Bytes after the last newline — an incomplete final record.
    Tail(Vec<u8>),
    /// A line with no newline within the bound.
    Oversized,
}

/// Streams `audit.log` a line at a time, never buffering more than one record.
struct LogReader {
    reader: BufReader<File>,
    offset: u64,
}

impl LogReader {
    fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(File::open(path)?),
            offset: 0,
        })
    }

    /// The next chunk and the offset it started at, or `None` at the end.
    fn read_chunk(&mut self) -> std::io::Result<Option<(u64, Chunk)>> {
        let start = self.offset;
        let mut buffer = Vec::new();
        let limit = u64::try_from(MAX_RECORD_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let read = (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut buffer)?;
        if read == 0 {
            return Ok(None);
        }
        self.offset = self
            .offset
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
            return Ok(Some((start, Chunk::Line(buffer))));
        }
        if buffer.len() > MAX_RECORD_BYTES {
            return Ok(Some((start, Chunk::Oversized)));
        }
        Ok(Some((start, Chunk::Tail(buffer))))
    }
}

/// What a clean `audit.log` contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLogSummary {
    /// How many records.
    pub records: u64,
    /// The hash of the last one (`H_0`, all zeroes, for an empty log).
    pub head: Sha256Hash,
}

/// Why `audit.log` failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLogFault {
    /// The file could not be read.
    Io(String),
    /// A complete record is wrong. `line` counts from 1 and is the record's
    /// position, which for a sound log is also its `seq`.
    Record {
        /// Which line.
        line: u64,
        /// What is wrong with it.
        fault: RecordFault,
    },
    /// The file ends in bytes that are not a complete record.
    TornTail {
        /// How many complete records precede them.
        after_records: u64,
        /// How many bytes they are.
        bytes: u64,
    },
}

impl fmt::Display for AuditLogFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(why) => write!(f, "audit.log could not be read: {why}"),
            Self::Record { line, fault } => write!(f, "audit.log line {line}: {fault}"),
            Self::TornTail {
                after_records,
                bytes,
            } => write!(
                f,
                "audit.log ends with {bytes} bytes of an incomplete record after record {after_records}"
            ),
        }
    }
}

impl std::error::Error for AuditLogFault {}

/// Verify `audit.log` on its own: syntax, canonical form, sequence continuity,
/// `prev` linkage and every hash, recomputed.
///
/// Read-only. It opens the file for reading and nothing else, so it can be
/// pointed at a live log.
///
/// # Errors
///
/// The first fault, with its position. A torn tail is reported as a fault here
/// because a verifier on its own cannot tell a crash's partial write from
/// damage; [`verify_audit_against_store`] can, and so can startup recovery.
pub fn verify_audit_log(path: &Path) -> Result<AuditLogSummary, AuditLogFault> {
    let mut reader = LogReader::open(path).map_err(|e| AuditLogFault::Io(e.to_string()))?;
    let mut records = 0u64;
    let mut head = Sha256Hash::ZERO;
    while let Some((_, chunk)) = reader
        .read_chunk()
        .map_err(|e| AuditLogFault::Io(e.to_string()))?
    {
        let line = records.saturating_add(1);
        match chunk {
            Chunk::Line(bytes) => {
                let verified = verify_line(&bytes, line, &head)
                    .map_err(|fault| AuditLogFault::Record { line, fault })?;
                head = verified.hash;
                records = verified.seq;
            }
            Chunk::Tail(bytes) => {
                return Err(AuditLogFault::TornTail {
                    after_records: records,
                    bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                });
            }
            Chunk::Oversized => {
                return Err(AuditLogFault::Record {
                    line,
                    fault: RecordFault::Oversized,
                });
            }
        }
    }
    Ok(AuditLogSummary { records, head })
}

/// One record of `audit.log`, returned only after the whole log verified.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    seq: u64,
    event: String,
    object: Object,
}

impl AuditRecord {
    /// The record's sequence number.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The event kind, as spelled in the record (`transport.peer_refused`).
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }

    /// A text field, if the record has one under `key`.
    #[must_use]
    pub fn text(&self, key: &str) -> Option<&str> {
        match self.object.get(key) {
            Some(Value::String(value)) => Some(value),
            _ => None,
        }
    }

    /// A non-negative integer field, if the record has one under `key`.
    #[must_use]
    pub fn int(&self, key: &str) -> Option<u64> {
        match self.object.get(key) {
            Some(Value::Number(Number::Int(value))) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    /// A boolean field, if the record has one under `key`.
    #[must_use]
    pub fn flag(&self, key: &str) -> Option<bool> {
        match self.object.get(key) {
            Some(Value::Bool(value)) => Some(*value),
            _ => None,
        }
    }
}

/// Verify `audit.log` exactly as [`verify_audit_log`] does and, only if every
/// record verifies, return the records. Read-only.
///
/// For operators, tests and evaluations that must assert **which** events the
/// authority recorded: they read the chain through the verifier instead of
/// parsing the file themselves, so an assertion about a record is never made
/// about a record the chain does not vouch for. It holds every record in
/// memory, so it is a tool for inspecting a log, not for serving one.
///
/// # Errors
///
/// As [`verify_audit_log`].
pub fn read_audit_log(path: &Path) -> Result<Vec<AuditRecord>, AuditLogFault> {
    let mut reader = LogReader::open(path).map_err(|e| AuditLogFault::Io(e.to_string()))?;
    let mut head = Sha256Hash::ZERO;
    let mut records = Vec::new();
    let mut count = 0u64;
    while let Some((_, chunk)) = reader
        .read_chunk()
        .map_err(|e| AuditLogFault::Io(e.to_string()))?
    {
        let line = count.saturating_add(1);
        match chunk {
            Chunk::Line(bytes) => {
                let verified = verify_line(&bytes, line, &head)
                    .map_err(|fault| AuditLogFault::Record { line, fault })?;
                let Ok(Value::Object(object)) = json::parse(&bytes, ParseOptions::dwkp()) else {
                    return Err(AuditLogFault::Record {
                        line,
                        fault: RecordFault::NotJson,
                    });
                };
                let event = match object.get("event") {
                    Some(Value::String(event)) => event.clone(),
                    _ => {
                        return Err(AuditLogFault::Record {
                            line,
                            fault: RecordFault::MissingField("event"),
                        });
                    }
                };
                head = verified.hash;
                count = verified.seq;
                records.push(AuditRecord {
                    seq: verified.seq,
                    event,
                    object,
                });
            }
            Chunk::Tail(bytes) => {
                return Err(AuditLogFault::TornTail {
                    after_records: count,
                    bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                });
            }
            Chunk::Oversized => {
                return Err(AuditLogFault::Record {
                    line,
                    fault: RecordFault::Oversized,
                });
            }
        }
    }
    Ok(records)
}

/// How `audit.log` compares with `kernel.db`'s record of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreComparison {
    /// Complete, verified records in `audit.log`.
    pub log_records: u64,
    /// `kernel.db`'s audit head: every record ever committed.
    pub store_head: u64,
    /// `kernel.db`'s flushed mark: every record acknowledged as durable in
    /// `audit.log`.
    pub store_flushed: u64,
    /// Whether the log ends in a partial write of the next pending record —
    /// the crash-window-D state recovery repairs.
    pub pending_torn_tail: bool,
}

impl StoreComparison {
    /// Records committed in `kernel.db` that `audit.log` does not yet hold:
    /// the crash windows C–E. Recovery appends them.
    #[must_use]
    pub const fn pending(&self) -> u64 {
        self.store_head.saturating_sub(self.log_records)
    }
}

/// Why `audit.log` and `kernel.db` disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreAuditFault {
    /// `audit.log` itself failed verification.
    Log(AuditLogFault),
    /// `kernel.db` could not be read.
    Store(String),
    /// `audit.log` ends before records `kernel.db` recorded as durably flushed:
    /// acknowledged records were removed.
    Truncated {
        /// Records in the log.
        log_records: u64,
        /// Records acknowledged as flushed.
        flushed: u64,
    },
    /// `audit.log` holds records `kernel.db` never committed.
    AheadOfStore {
        /// Records in the log.
        log_records: u64,
        /// Records in the store.
        store_head: u64,
    },
    /// Record `seq` differs between the two.
    Diverged {
        /// Which record.
        seq: u64,
    },
    /// The log ends in bytes that are not a prefix of the pending record.
    ForeignTail,
}

impl fmt::Display for StoreAuditFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(fault) => fault.fmt(f),
            Self::Store(why) => write!(f, "kernel.db could not be read: {why}"),
            Self::Truncated {
                log_records,
                flushed,
            } => write!(
                f,
                "audit.log holds {log_records} records but kernel.db recorded {flushed} as durable: \
                 acknowledged records are missing"
            ),
            Self::AheadOfStore {
                log_records,
                store_head,
            } => write!(
                f,
                "audit.log holds {log_records} records but kernel.db committed only {store_head}"
            ),
            Self::Diverged { seq } => {
                write!(f, "record {seq} differs between audit.log and kernel.db")
            }
            Self::ForeignTail => f.write_str(
                "audit.log ends in bytes that are not a partial write of the pending record",
            ),
        }
    }
}

impl std::error::Error for StoreAuditFault {}

/// The store's view: head, flushed mark, and a way to read record `n`.
struct StoreChain<'c> {
    conn: &'c Connection,
    head: u64,
    flushed: u64,
}

impl<'c> StoreChain<'c> {
    fn read(conn: &'c Connection) -> rusqlite::Result<Self> {
        let head: i64 = conn.query_row(
            "SELECT seq FROM audit_head WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let flushed: i64 = conn.query_row(
            "SELECT flushed_seq FROM audit_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Self {
            conn,
            head: u64::try_from(head).unwrap_or(0),
            flushed: u64::try_from(flushed).unwrap_or(0),
        })
    }

    fn record(&self, seq: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(None);
        };
        let mut statement = self
            .conn
            .prepare("SELECT record FROM audit_chain WHERE seq = ?1")?;
        let mut rows = statement.query([seq])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }
}

/// Walk `audit.log` against the store. Shared by the read-only verifier and by
/// startup recovery, so the two cannot disagree about what is sound.
/// What [`compare`] found: the comparison, a partial final record (its offset
/// and bytes) if there is one, and the hash of the last complete record.
struct Compared {
    comparison: StoreComparison,
    tail: Option<(u64, Vec<u8>)>,
    head: Sha256Hash,
}

fn compare(path: &Path, chain: &StoreChain<'_>) -> Result<Compared, StoreAuditFault> {
    let store = |e: rusqlite::Error| StoreAuditFault::Store(e.to_string());
    let mut reader = LogReader::open(path)
        .map_err(|e| StoreAuditFault::Log(AuditLogFault::Io(e.to_string())))?;
    let mut records = 0u64;
    let mut head = Sha256Hash::ZERO;
    let mut tail = None;
    while let Some((offset, chunk)) = reader
        .read_chunk()
        .map_err(|e| StoreAuditFault::Log(AuditLogFault::Io(e.to_string())))?
    {
        let line = records.saturating_add(1);
        match chunk {
            Chunk::Line(bytes) => {
                if line > chain.head {
                    return Err(StoreAuditFault::AheadOfStore {
                        log_records: line,
                        store_head: chain.head,
                    });
                }
                let verified = verify_line(&bytes, line, &head)
                    .map_err(|fault| StoreAuditFault::Log(AuditLogFault::Record { line, fault }))?;
                if chain.record(line).map_err(store)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(StoreAuditFault::Diverged { seq: line });
                }
                head = verified.hash;
                records = line;
            }
            Chunk::Tail(bytes) => {
                tail = Some((offset, bytes));
                break;
            }
            Chunk::Oversized => {
                return Err(StoreAuditFault::Log(AuditLogFault::Record {
                    line,
                    fault: RecordFault::Oversized,
                }));
            }
        }
    }
    if records < chain.flushed {
        return Err(StoreAuditFault::Truncated {
            log_records: records,
            flushed: chain.flushed,
        });
    }
    let mut pending_torn_tail = false;
    if let Some((_, bytes)) = &tail {
        let next = records.saturating_add(1);
        let expected = if next <= chain.head {
            chain.record(next).map_err(store)?
        } else {
            None
        };
        let Some(mut expected) = expected else {
            return Err(StoreAuditFault::ForeignTail);
        };
        expected.push(b'\n');
        if bytes.len() >= expected.len() || !expected.starts_with(bytes) {
            return Err(StoreAuditFault::ForeignTail);
        }
        pending_torn_tail = true;
    }
    Ok(Compared {
        comparison: StoreComparison {
            log_records: records,
            store_head: chain.head,
            store_flushed: chain.flushed,
            pending_torn_tail,
        },
        tail,
        head,
    })
}

/// Verify `audit.log` against `kernel.db` in `state_dir`, read-only.
///
/// Every check [`verify_audit_log`] makes, plus: each record is byte-identical
/// to `kernel.db`'s copy, no record the store acknowledged as durable is
/// missing, no record the store never committed is present, and a partial
/// final record, if any, is a prefix of the next pending one.
///
/// Opens `kernel.db` read-only and `audit.log` for reading. Mutates neither.
///
/// # Errors
///
/// The first disagreement.
pub fn verify_audit_against_store(state_dir: &Path) -> Result<StoreComparison, StoreAuditFault> {
    // The same resolution the authority uses: a symlinked state directory is
    // refused, and SQLite is handed a path with no symlink in any component.
    let resolved = super::files::resolve_directory(state_dir)
        .map_err(|e| StoreAuditFault::Store(e.to_string()))?;
    let paths = super::files::StatePaths::new(&resolved);
    let conn =
        super::db::open_read_only(&paths.db).map_err(|e| StoreAuditFault::Store(e.to_string()))?;
    let chain = StoreChain::read(&conn).map_err(|e| StoreAuditFault::Store(e.to_string()))?;
    compare(&paths.audit, &chain).map(|found| found.comparison)
}

/// What startup recovery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recovered {
    /// The last record now durable in `audit.log`.
    pub(crate) durable_seq: u64,
    /// Its hash.
    pub(crate) durable_hash: Sha256Hash,
    /// Records found already in `audit.log` above the flushed mark (window F):
    /// reconciled, **not** appended again.
    pub(crate) reconciled: u64,
    /// Records appended from the outbox (windows C, D and E).
    pub(crate) appended: u64,
    /// Bytes of a partial final record that were removed (window D).
    pub(crate) torn_tail_bytes: u64,
}

/// Why recovery refused.
#[derive(Debug)]
pub(crate) enum RecoveryError {
    Io(String),
    Sqlite(rusqlite::Error),
    Diverged(StoreAuditFault),
}

/// Make `audit.log` hold exactly `kernel.db`'s chain, or refuse.
///
/// * Complete records must verify and match `kernel.db` byte for byte.
/// * Records above the flushed mark that are already present (window F) are
///   **reconciled, never appended twice**.
/// * A partial final record is removed only if it is a strict prefix of the
///   pending record at that position (window D). Anything else in that
///   position is not a crash artefact, and the store is refused.
/// * Records committed but not yet in the log (windows C, E after power loss)
///   are appended from the outbox and synced.
/// * A log shorter than the flushed mark, or longer than the head, is not a
///   crash window at all, and the store is refused.
pub(crate) fn recover(conn: &Connection, path: &Path) -> Result<Recovered, RecoveryError> {
    let chain = StoreChain::read(conn).map_err(RecoveryError::Sqlite)?;
    let Compared {
        comparison,
        tail,
        mut head,
    } = compare(path, &chain).map_err(|fault| match fault {
        StoreAuditFault::Store(why) | StoreAuditFault::Log(AuditLogFault::Io(why)) => {
            RecoveryError::Io(why)
        }
        other => RecoveryError::Diverged(other),
    })?;
    let io = |e: std::io::Error| RecoveryError::Io(e.to_string());

    let mut report = Recovered {
        durable_seq: 0,
        durable_hash: Sha256Hash::ZERO,
        reconciled: comparison
            .log_records
            .saturating_sub(comparison.store_flushed),
        appended: 0,
        torn_tail_bytes: 0,
    };

    let mut file = OpenOptions::new().write(true).open(path).map_err(io)?;
    if let Some((offset, bytes)) = tail {
        file.set_len(offset).map_err(io)?;
        file.sync_all().map_err(io)?;
        report.torn_tail_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    }
    file.seek(SeekFrom::End(0)).map_err(io)?;

    let mut seq = comparison.log_records;
    while seq < chain.head {
        let next = seq.saturating_add(1);
        let Some(record) = chain.record(next).map_err(RecoveryError::Sqlite)? else {
            return Err(RecoveryError::Diverged(StoreAuditFault::Diverged {
                seq: next,
            }));
        };
        let verified = verify_line(&record, next, &head).map_err(|fault| {
            RecoveryError::Diverged(StoreAuditFault::Log(AuditLogFault::Record {
                line: next,
                fault,
            }))
        })?;
        file.write_all(&record).map_err(io)?;
        file.write_all(b"\n").map_err(io)?;
        head = verified.hash;
        seq = next;
        report.appended = report.appended.saturating_add(1);
    }
    file.sync_all().map_err(io)?;

    let flushed_seq =
        i64::try_from(seq).map_err(|_| RecoveryError::Io("audit sequence overflow".to_owned()))?;
    conn.execute(
        "UPDATE audit_state SET flushed_seq = ?1, flushed_hash = ?2 WHERE singleton = 1",
        rusqlite::params![flushed_seq, head.to_hex()],
    )
    .map_err(RecoveryError::Sqlite)?;
    report.durable_seq = seq;
    report.durable_hash = head;
    Ok(report)
}

// ---------------------------------------------------------------------------
// The writer.
// ---------------------------------------------------------------------------

/// The one appender of `audit.log` in this process. Shared by every handle
/// behind a mutex, so records reach the file in sequence order whichever
/// handle committed them.
#[derive(Debug)]
pub(crate) struct AuditWriter {
    file: File,
    durable_seq: u64,
    durable_hash: Sha256Hash,
}

/// Why a flush failed.
#[derive(Debug)]
pub(crate) enum FlushFailure {
    /// `audit.log` could not be written or synced.
    Io,
    /// `kernel.db` could not be read or marked.
    Sqlite(rusqlite::Error),
    /// A crash hook stopped the flush.
    Stopped(AuthorityError),
    /// The outbox does not extend the durable chain.
    Diverged(String),
}

impl AuditWriter {
    /// Open for appending, after [`recover`] has made the log exact.
    pub(crate) fn open(path: &Path, recovered: &Recovered) -> std::io::Result<Self> {
        Ok(Self {
            file: OpenOptions::new().append(true).open(path)?,
            durable_seq: recovered.durable_seq,
            durable_hash: recovered.durable_hash,
        })
    }

    /// Append and sync every pending record, so that at least `target` is
    /// durable; then record the flush in `kernel.db`.
    ///
    /// `crash` is consulted at each window and may stop the flush.
    pub(crate) fn flush_through(
        &mut self,
        conn: &Connection,
        target: u64,
        crash: &mut dyn FnMut(CrashPoint) -> Result<(), AuthorityError>,
    ) -> Result<(), FlushFailure> {
        if self.durable_seq >= target {
            return Ok(());
        }
        crash(CrashPoint::AfterCommitBeforeAudit).map_err(FlushFailure::Stopped)?;

        let from = i64::try_from(self.durable_seq)
            .map_err(|_| FlushFailure::Diverged("audit sequence overflow".to_owned()))?;
        let pending: Vec<(i64, String, String, Vec<u8>)> = {
            let mut statement = conn
                .prepare(
                    "SELECT seq, prev, hash, record FROM audit_chain WHERE seq > ?1 ORDER BY seq",
                )
                .map_err(FlushFailure::Sqlite)?;
            let rows = statement
                .query_map([from], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(FlushFailure::Sqlite)?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(FlushFailure::Sqlite)?
        };

        let mut seq = self.durable_seq;
        let mut hash = self.durable_hash;
        for (row_seq, prev, row_hash, mut line) in pending {
            let next = seq.saturating_add(1);
            if u64::try_from(row_seq).ok() != Some(next) || prev != hash.to_hex() {
                return Err(FlushFailure::Diverged(format!(
                    "the outbox does not extend the durable chain at record {next}"
                )));
            }
            line.push(b'\n');
            let (first, second) = line.split_at(line.len() >> 1);
            self.file.write_all(first).map_err(|_| FlushFailure::Io)?;
            crash(CrashPoint::MidAuditRecord).map_err(FlushFailure::Stopped)?;
            self.file.write_all(second).map_err(|_| FlushFailure::Io)?;
            seq = next;
            hash = Sha256Hash::from_hex(&row_hash).ok_or_else(|| {
                FlushFailure::Diverged(format!("record {next} has a malformed hash"))
            })?;
        }
        if seq < target {
            return Err(FlushFailure::Diverged(format!(
                "record {target} is not in the outbox"
            )));
        }

        crash(CrashPoint::AfterAuditWriteBeforeSync).map_err(FlushFailure::Stopped)?;
        self.file.sync_all().map_err(|_| FlushFailure::Io)?;
        // Durable now, whatever happens next. Advancing the in-memory mark
        // *before* telling kernel.db is what makes a failed mark harmless: the
        // next flush marks through a later record and never appends these
        // again. The stored mark is a lower bound, and recovery treats it so.
        self.durable_seq = seq;
        self.durable_hash = hash;
        crash(CrashPoint::AfterAuditSyncBeforeMark).map_err(FlushFailure::Stopped)?;

        let sql_seq = i64::try_from(seq)
            .map_err(|_| FlushFailure::Diverged("audit sequence overflow".to_owned()))?;
        conn.execute(
            "UPDATE audit_state SET flushed_seq = ?1, flushed_hash = ?2 \
             WHERE singleton = 1 AND flushed_seq < ?1",
            rusqlite::params![sql_seq, hash.to_hex()],
        )
        .map_err(FlushFailure::Sqlite)?;
        crash(CrashPoint::AfterAuditMark).map_err(FlushFailure::Stopped)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditEvent, Fields, RESERVED_KEYS, RecordFault, Sha256Hash, chain_hash, unsigned_record,
        verify_line,
    };
    use dwk_proto::json::{self, Value};

    fn line(seq: u64, prev: &Sha256Hash, fields: &Fields) -> (Vec<u8>, Sha256Hash) {
        let Ok(mut record) =
            unsigned_record(seq, prev, 1_000, AuditEvent::LeaseAcquired, fields.clone())
        else {
            unreachable!("valid fields")
        };
        let hash = chain_hash(
            prev,
            &json::to_canonical_bytes(&Value::Object(record.clone())),
        );
        assert!(
            record
                .insert("hash".to_owned(), Value::String(hash.to_hex()))
                .is_ok()
        );
        (json::to_canonical_bytes(&Value::Object(record)), hash)
    }

    #[test]
    fn a_record_verifies_and_every_single_byte_change_is_detected() {
        let fields = Fields::new().text("session_id", "ses_x").int("epoch", 3);
        let (bytes, hash) = line(1, &Sha256Hash::ZERO, &fields);
        let Ok(verified) = verify_line(&bytes, 1, &Sha256Hash::ZERO) else {
            unreachable!("a fresh record verifies")
        };
        assert_eq!(verified.hash, hash);
        // Flip every byte in turn. Each must fail -- and never as a pass.
        for index in 0..bytes.len() {
            let mut flipped = bytes.clone();
            if let Some(byte) = flipped.get_mut(index) {
                *byte ^= 0x01;
            }
            assert!(
                verify_line(&flipped, 1, &Sha256Hash::ZERO).is_err(),
                "a flip at byte {index} went undetected"
            );
        }
    }

    #[test]
    fn a_record_is_bound_to_its_position_and_its_predecessor() {
        let fields = Fields::new().int("epoch", 1);
        let (first, first_hash) = line(1, &Sha256Hash::ZERO, &fields);
        let (second, _) = line(2, &first_hash, &fields);
        assert!(verify_line(&second, 2, &first_hash).is_ok());
        assert_eq!(
            verify_line(&second, 3, &first_hash),
            Err(RecordFault::Sequence {
                expected: 3,
                found: 2
            }),
            "a deletion before it shows as a sequence gap"
        );
        assert_eq!(
            verify_line(&second, 2, &Sha256Hash::ZERO),
            Err(RecordFault::PrevMismatch),
            "a different predecessor is detected"
        );
        assert!(verify_line(&first, 2, &first_hash).is_err(), "a duplicate");
    }

    #[test]
    fn a_non_canonical_rendering_of_a_valid_record_is_refused() {
        let (bytes, _) = line(1, &Sha256Hash::ZERO, &Fields::new());
        let mut padded = b" ".to_vec();
        padded.extend_from_slice(&bytes);
        assert_eq!(
            verify_line(&padded, 1, &Sha256Hash::ZERO),
            Err(RecordFault::NotCanonical)
        );
    }

    #[test]
    fn an_event_may_not_reuse_an_envelope_key() {
        for key in RESERVED_KEYS {
            let fields = Fields::new().text(key, "x");
            assert!(
                unsigned_record(1, &Sha256Hash::ZERO, 0, AuditEvent::StoreOpened, fields).is_err(),
                "`{key}` was accepted as an event field"
            );
        }
    }

    #[test]
    fn event_names_are_distinct() {
        let mut names: Vec<&str> = AuditEvent::ALL.iter().map(|e| e.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AuditEvent::ALL.len());
    }
}
