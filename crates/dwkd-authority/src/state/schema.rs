//! The `kernel.db` schema, its version, and how a store proves it has the
//! schema it claims.
//!
//! # One version source
//!
//! `PRAGMA user_version`, set inside the transaction that creates or migrates
//! the schema, so the version and the tables it describes commit together or
//! not at all. `PRAGMA application_id` marks the file as a DireWolf kernel
//! store, so a SQLite file that is something else — `runtime.db`, a user's
//! database, a store from another program — is refused rather than migrated.
//! There is no second version table to disagree with.
//!
//! # Opening a store
//!
//! | found | outcome |
//! |---|---|
//! | empty database, no id, no version, no objects | create the current schema |
//! | DireWolf id, version below current | migrate, in one transaction |
//! | DireWolf id, current version | verify |
//! | DireWolf id, version above current | **refuse**: a newer build wrote it |
//! | DireWolf id, version 0, or no id with objects | **refuse**: malformed or foreign |
//!
//! # Verification is exact
//!
//! A store claiming the current version must contain **exactly** the objects
//! this build's DDL creates — every table, index and trigger, with the same SQL
//! text — and nothing else. The expected set is not a hand-maintained list: it
//! is read back from a scratch in-memory database built from the same DDL, so
//! it cannot drift from the schema it describes. A dropped append-only trigger,
//! a missing table or an extra object is a malformed store, and it is refused.
//! A missing table is **never** recreated: that would be starting over on top
//! of whatever removed it.
//!
//! # Append-only is enforced by the database
//!
//! Security history — the audit chain's local copy, policy revisions and their
//! sources, configuration revisions, admissions, grants, withheld requests,
//! idempotency records — is guarded by `BEFORE UPDATE` and `BEFORE DELETE`
//! triggers that abort. Current state — leases, a run's lifecycle state, a
//! run's taint — changes, and its triggers constrain *how*: an epoch never
//! decreases, a new lease tenure always takes a new epoch, a released run never
//! becomes active, taint never falls. Those are properties this module's Rust
//! maintains; the triggers are the second, independent statement of them.
//!
//! Every table is `STRICT`: a column accepts only its declared type, which is
//! the database half of M3c's "no coercion".

use rusqlite::Connection;

/// `PRAGMA application_id` of a DireWolf kernel store: ASCII `DWKD`.
pub(super) const APPLICATION_ID: i64 = 0x4457_4B44;

/// The schema version this build creates and understands.
pub(super) const CURRENT_VERSION: i64 = 3;

/// Schema version 1, the first. Static text: nothing in it is assembled from a
/// value, and every value the authority stores is bound as a parameter.
pub(super) const SCHEMA_V1: &str = r"
CREATE TABLE store_meta (
    singleton    INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_id     TEXT    NOT NULL CHECK (length(store_id) = 64),
    created_ms   INTEGER NOT NULL CHECK (created_ms >= 0),
    incarnation  INTEGER NOT NULL CHECK (incarnation >= 0),
    id_counter   INTEGER NOT NULL CHECK (id_counter >= 0 AND id_counter <= 4398046511103)
) STRICT;
CREATE TRIGGER store_meta_no_delete BEFORE DELETE ON store_meta
BEGIN SELECT RAISE(ABORT, 'store_meta is permanent'); END;
CREATE TRIGGER store_meta_identity_fixed BEFORE UPDATE OF singleton, store_id, created_ms ON store_meta
BEGIN SELECT RAISE(ABORT, 'the store identity is fixed'); END;
CREATE TRIGGER store_meta_counters_monotonic BEFORE UPDATE OF incarnation, id_counter ON store_meta
WHEN NEW.incarnation < OLD.incarnation OR NEW.id_counter < OLD.id_counter
BEGIN SELECT RAISE(ABORT, 'store counters never decrease'); END;

CREATE TABLE audit_head (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    seq        INTEGER NOT NULL CHECK (seq >= 0),
    hash       TEXT    NOT NULL CHECK (length(hash) = 64)
) STRICT;
CREATE TRIGGER audit_head_no_delete BEFORE DELETE ON audit_head
BEGIN SELECT RAISE(ABORT, 'audit_head is permanent'); END;
CREATE TRIGGER audit_head_advances_by_one BEFORE UPDATE ON audit_head
WHEN NEW.singleton != OLD.singleton OR NEW.seq != OLD.seq + 1
BEGIN SELECT RAISE(ABORT, 'the audit head advances one record at a time'); END;

CREATE TABLE audit_state (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    flushed_seq   INTEGER NOT NULL CHECK (flushed_seq >= 0),
    flushed_hash  TEXT    NOT NULL CHECK (length(flushed_hash) = 64)
) STRICT;
CREATE TRIGGER audit_state_no_delete BEFORE DELETE ON audit_state
BEGIN SELECT RAISE(ABORT, 'audit_state is permanent'); END;
CREATE TRIGGER audit_state_forward_only BEFORE UPDATE ON audit_state
WHEN NEW.singleton != OLD.singleton
  OR NEW.flushed_seq < OLD.flushed_seq
  OR NEW.flushed_seq > (SELECT seq FROM audit_head WHERE singleton = 1)
BEGIN SELECT RAISE(ABORT, 'the flushed mark only moves forward, and never past the head'); END;

CREATE TABLE audit_chain (
    seq     INTEGER PRIMARY KEY CHECK (seq >= 1),
    prev    TEXT    NOT NULL CHECK (length(prev) = 64),
    hash    TEXT    NOT NULL UNIQUE CHECK (length(hash) = 64),
    record  BLOB    NOT NULL
) STRICT;
CREATE TRIGGER audit_chain_no_update BEFORE UPDATE ON audit_chain
BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
CREATE TRIGGER audit_chain_no_delete BEFORE DELETE ON audit_chain
BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
CREATE TRIGGER audit_chain_extends_the_head BEFORE INSERT ON audit_chain
WHEN NEW.seq != (SELECT seq FROM audit_head WHERE singleton = 1) + 1
  OR NEW.prev != (SELECT hash FROM audit_head WHERE singleton = 1)
BEGIN SELECT RAISE(ABORT, 'an audit record must extend the head'); END;

CREATE TABLE policy_revision (
    revision        TEXT    PRIMARY KEY CHECK (length(revision) = 64),
    schema_version  INTEGER NOT NULL CHECK (schema_version >= 1),
    profile         TEXT    NOT NULL,
    source_count    INTEGER NOT NULL CHECK (source_count >= 1),
    installed_ms    INTEGER NOT NULL
) STRICT;
CREATE TRIGGER policy_revision_no_update BEFORE UPDATE ON policy_revision
BEGIN SELECT RAISE(ABORT, 'a policy revision is immutable'); END;
CREATE TRIGGER policy_revision_no_delete BEFORE DELETE ON policy_revision
BEGIN SELECT RAISE(ABORT, 'a policy revision is never deleted'); END;

CREATE TABLE policy_source (
    revision  TEXT    NOT NULL REFERENCES policy_revision(revision) ON DELETE RESTRICT,
    ordinal   INTEGER NOT NULL CHECK (ordinal >= 0),
    name      TEXT    NOT NULL,
    text      BLOB    NOT NULL,
    PRIMARY KEY (revision, ordinal),
    UNIQUE (revision, name)
) STRICT;
CREATE TRIGGER policy_source_no_update BEFORE UPDATE ON policy_source
BEGIN SELECT RAISE(ABORT, 'a policy source snapshot is immutable'); END;
CREATE TRIGGER policy_source_no_delete BEFORE DELETE ON policy_source
BEGIN SELECT RAISE(ABORT, 'a policy source snapshot is never deleted'); END;

CREATE TABLE activation (
    id                    INTEGER PRIMARY KEY CHECK (id >= 1),
    policy_revision       TEXT    NOT NULL REFERENCES policy_revision(revision) ON DELETE RESTRICT,
    mode                  TEXT    NOT NULL CHECK (mode IN ('SAFE', 'BALANCED', 'POWER')),
    allow_host_execution  INTEGER NOT NULL CHECK (allow_host_execution IN (0, 1)),
    ceiling_digest        TEXT    NOT NULL CHECK (length(ceiling_digest) = 64),
    activated_ms          INTEGER NOT NULL
) STRICT;
CREATE TRIGGER activation_no_update BEFORE UPDATE ON activation
BEGIN SELECT RAISE(ABORT, 'an activation is immutable'); END;
CREATE TRIGGER activation_no_delete BEFORE DELETE ON activation
BEGIN SELECT RAISE(ABORT, 'an activation is never deleted'); END;

CREATE TABLE activation_ceiling (
    activation_id  INTEGER NOT NULL REFERENCES activation(id) ON DELETE RESTRICT,
    ordinal        INTEGER NOT NULL CHECK (ordinal >= 0),
    capability     TEXT    NOT NULL,
    PRIMARY KEY (activation_id, ordinal)
) STRICT;
CREATE TRIGGER activation_ceiling_no_update BEFORE UPDATE ON activation_ceiling
BEGIN SELECT RAISE(ABORT, 'a ceiling is immutable'); END;
CREATE TRIGGER activation_ceiling_no_delete BEFORE DELETE ON activation_ceiling
BEGIN SELECT RAISE(ABORT, 'a ceiling is never deleted'); END;

CREATE TABLE agent_profile (
    name             TEXT    NOT NULL,
    revision         INTEGER NOT NULL CHECK (revision >= 1),
    digest           TEXT    NOT NULL CHECK (length(digest) = 64),
    privacy_default  TEXT    NOT NULL CHECK (privacy_default IN ('LOCAL_ONLY', 'VENDOR_OK', 'ANY')),
    installed_ms     INTEGER NOT NULL,
    PRIMARY KEY (name, revision)
) STRICT;
CREATE TRIGGER agent_profile_no_update BEFORE UPDATE ON agent_profile
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is immutable'); END;
CREATE TRIGGER agent_profile_no_delete BEFORE DELETE ON agent_profile
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is never deleted'); END;

CREATE TABLE agent_profile_capability (
    name        TEXT    NOT NULL,
    revision    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL CHECK (ordinal >= 0),
    capability  TEXT    NOT NULL,
    PRIMARY KEY (name, revision, ordinal),
    FOREIGN KEY (name, revision) REFERENCES agent_profile(name, revision) ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER agent_profile_capability_no_update BEFORE UPDATE ON agent_profile_capability
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is immutable'); END;
CREATE TRIGGER agent_profile_capability_no_delete BEFORE DELETE ON agent_profile_capability
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is never deleted'); END;

CREATE TABLE agent_profile_skill (
    name      TEXT    NOT NULL,
    revision  INTEGER NOT NULL,
    ordinal   INTEGER NOT NULL CHECK (ordinal >= 0),
    skill     TEXT    NOT NULL,
    PRIMARY KEY (name, revision, ordinal),
    UNIQUE (name, revision, skill),
    FOREIGN KEY (name, revision) REFERENCES agent_profile(name, revision) ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER agent_profile_skill_no_update BEFORE UPDATE ON agent_profile_skill
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is immutable'); END;
CREATE TRIGGER agent_profile_skill_no_delete BEFORE DELETE ON agent_profile_skill
BEGIN SELECT RAISE(ABORT, 'an agent profile revision is never deleted'); END;

CREATE TABLE skill (
    name          TEXT    NOT NULL,
    revision      INTEGER NOT NULL CHECK (revision >= 1),
    digest        TEXT    NOT NULL CHECK (length(digest) = 64),
    trust         TEXT    NOT NULL CHECK (trust IN ('SYSTEM_TRUSTED', 'USER_TRUSTED',
                      'COMMUNITY_UNVERIFIED', 'GENERATED_UNTRUSTED', 'QUARANTINED')),
    installed_ms  INTEGER NOT NULL,
    PRIMARY KEY (name, revision)
) STRICT;
CREATE TRIGGER skill_no_update BEFORE UPDATE ON skill
BEGIN SELECT RAISE(ABORT, 'a skill revision is immutable'); END;
CREATE TRIGGER skill_no_delete BEFORE DELETE ON skill
BEGIN SELECT RAISE(ABORT, 'a skill revision is never deleted'); END;

CREATE TABLE skill_capability (
    name        TEXT    NOT NULL,
    revision    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL CHECK (ordinal >= 0),
    capability  TEXT    NOT NULL,
    PRIMARY KEY (name, revision, ordinal),
    FOREIGN KEY (name, revision) REFERENCES skill(name, revision) ON DELETE RESTRICT
) STRICT;
CREATE TRIGGER skill_capability_no_update BEFORE UPDATE ON skill_capability
BEGIN SELECT RAISE(ABORT, 'a skill revision is immutable'); END;
CREATE TRIGGER skill_capability_no_delete BEFORE DELETE ON skill_capability
BEGIN SELECT RAISE(ABORT, 'a skill revision is never deleted'); END;

CREATE TABLE workspace (
    workspace_id  TEXT    PRIMARY KEY,
    sensitivity   INTEGER NOT NULL CHECK (sensitivity IN (0, 1, 2)),
    installed_ms  INTEGER NOT NULL
) STRICT;
CREATE TRIGGER workspace_identity_fixed BEFORE UPDATE OF workspace_id, installed_ms ON workspace
BEGIN SELECT RAISE(ABORT, 'a workspace identity is fixed'); END;
CREATE TRIGGER workspace_sensitivity_only_rises BEFORE UPDATE OF sensitivity ON workspace
WHEN NEW.sensitivity < OLD.sensitivity
BEGIN SELECT RAISE(ABORT, 'workspace sensitivity only ever becomes stricter'); END;
CREATE TRIGGER workspace_no_delete BEFORE DELETE ON workspace
BEGIN SELECT RAISE(ABORT, 'a workspace record is never deleted'); END;

CREATE TABLE session_workspace (
    session_id    TEXT    PRIMARY KEY,
    workspace_id  TEXT    NOT NULL REFERENCES workspace(workspace_id) ON DELETE RESTRICT,
    bound_ms      INTEGER NOT NULL
) STRICT;
CREATE TRIGGER session_workspace_no_update BEFORE UPDATE ON session_workspace
BEGIN SELECT RAISE(ABORT, 'a session is bound to one workspace for life'); END;
CREATE TRIGGER session_workspace_no_delete BEFORE DELETE ON session_workspace
BEGIN SELECT RAISE(ABORT, 'a session binding is never deleted'); END;

CREATE TABLE session_lease (
    session_id               TEXT    PRIMARY KEY,
    epoch                    INTEGER NOT NULL CHECK (epoch >= 1 AND epoch <= 9007199254740991),
    state                    TEXT    NOT NULL CHECK (state IN ('HELD', 'RELEASED', 'INVALIDATED')),
    holder_subject           TEXT,
    holder_incarnation       INTEGER,
    holder_connection        INTEGER,
    expires_ms               INTEGER,
    last_holder_incarnation  INTEGER,
    last_holder_connection   INTEGER,
    CHECK ((state = 'HELD') = (holder_subject IS NOT NULL AND holder_incarnation IS NOT NULL
                               AND holder_connection IS NOT NULL AND expires_ms IS NOT NULL)),
    CHECK (state = 'HELD' OR (holder_subject IS NULL AND holder_incarnation IS NULL
                              AND holder_connection IS NULL AND expires_ms IS NULL))
) STRICT;
CREATE TRIGGER session_lease_epoch_never_decreases BEFORE UPDATE OF epoch ON session_lease
WHEN NEW.epoch < OLD.epoch
BEGIN SELECT RAISE(ABORT, 'a session epoch never decreases'); END;
CREATE TRIGGER session_lease_new_tenure_new_epoch BEFORE UPDATE ON session_lease
WHEN NEW.state = 'HELD'
  AND NOT (OLD.state = 'HELD'
           AND OLD.holder_incarnation IS NEW.holder_incarnation
           AND OLD.holder_connection IS NEW.holder_connection
           AND OLD.epoch = NEW.epoch)
  AND NEW.epoch <= OLD.epoch
BEGIN SELECT RAISE(ABORT, 'a new lease tenure requires a new epoch'); END;
CREATE TRIGGER session_lease_never_deleted BEFORE DELETE ON session_lease
BEGIN SELECT RAISE(ABORT, 'a session epoch counter is never deleted'); END;

CREATE TABLE run (
    run_id                  TEXT    PRIMARY KEY,
    session_id              TEXT    NOT NULL REFERENCES session_lease(session_id) ON DELETE RESTRICT,
    subject                 TEXT    NOT NULL,
    epoch                   INTEGER NOT NULL CHECK (epoch >= 1),
    agent_profile           TEXT    NOT NULL,
    agent_profile_revision  INTEGER NOT NULL,
    activation_id           INTEGER NOT NULL REFERENCES activation(id) ON DELETE RESTRICT,
    state                   TEXT    NOT NULL CHECK (state IN ('ACTIVE', 'RELEASED', 'REAPED')),
    admitted_ms             INTEGER NOT NULL,
    ended_ms                INTEGER,
    CHECK ((state = 'ACTIVE') = (ended_ms IS NULL)),
    FOREIGN KEY (agent_profile, agent_profile_revision)
        REFERENCES agent_profile(name, revision) ON DELETE RESTRICT
) STRICT;
CREATE INDEX run_by_session ON run(session_id, state);
CREATE TRIGGER run_never_resurrects BEFORE UPDATE OF state ON run
WHEN OLD.state != 'ACTIVE'
BEGIN SELECT RAISE(ABORT, 'a released run never becomes active again'); END;
CREATE TRIGGER run_admission_fixed BEFORE UPDATE OF run_id, session_id, subject, epoch,
    agent_profile, agent_profile_revision, activation_id, admitted_ms ON run
BEGIN SELECT RAISE(ABORT, 'an admission is immutable'); END;
CREATE TRIGGER run_never_deleted BEFORE DELETE ON run
BEGIN SELECT RAISE(ABORT, 'a run record is never deleted'); END;

CREATE TABLE run_skill (
    run_id          TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    ordinal         INTEGER NOT NULL CHECK (ordinal >= 0),
    skill           TEXT    NOT NULL,
    origin          TEXT    NOT NULL CHECK (origin IN ('BASELINE', 'REQUESTED')),
    skill_revision  INTEGER,
    trust           TEXT,
    PRIMARY KEY (run_id, ordinal),
    UNIQUE (run_id, skill),
    CHECK ((skill_revision IS NULL) = (trust IS NULL))
) STRICT;
CREATE TRIGGER run_skill_no_update BEFORE UPDATE ON run_skill
BEGIN SELECT RAISE(ABORT, 'a run''s skill set is fixed at admission'); END;
CREATE TRIGGER run_skill_no_delete BEFORE DELETE ON run_skill
BEGIN SELECT RAISE(ABORT, 'a run''s skill set is never deleted'); END;

CREATE TABLE run_grant (
    cap_id      TEXT    PRIMARY KEY,
    run_id      TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    ordinal     INTEGER NOT NULL CHECK (ordinal >= 0),
    capability  TEXT    NOT NULL,
    UNIQUE (run_id, ordinal)
) STRICT;
CREATE TRIGGER run_grant_no_update BEFORE UPDATE ON run_grant
BEGIN SELECT RAISE(ABORT, 'a grant record is immutable'); END;
CREATE TRIGGER run_grant_no_delete BEFORE DELETE ON run_grant
BEGIN SELECT RAISE(ABORT, 'a grant record is never deleted'); END;

CREATE TABLE run_withheld (
    run_id      TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    ordinal     INTEGER NOT NULL CHECK (ordinal >= 0),
    capability  TEXT    NOT NULL,
    reason      TEXT    NOT NULL CHECK (reason IN ('NOT_IN_AGENT_PROFILE', 'NOT_IN_SKILL_SET',
                    'NOT_IN_PARENT_GRANT', 'ABOVE_PROFILE_CEILING',
                    'NEEDS_CANONICAL_PATH', 'NEEDS_EXECUTABLE_IDENTITY')),
    PRIMARY KEY (run_id, ordinal)
) STRICT;
CREATE TRIGGER run_withheld_no_update BEFORE UPDATE ON run_withheld
BEGIN SELECT RAISE(ABORT, 'a withheld record is immutable'); END;
CREATE TRIGGER run_withheld_no_delete BEFORE DELETE ON run_withheld
BEGIN SELECT RAISE(ABORT, 'a withheld record is never deleted'); END;

CREATE TABLE run_policy_input (
    run_id                 TEXT    PRIMARY KEY REFERENCES run(run_id) ON DELETE RESTRICT,
    origin                 TEXT    NOT NULL CHECK (origin IN ('interactive', 'scheduled',
                               'channel', 'subagent', 'api')),
    taint                  INTEGER NOT NULL CHECK (taint IN (0, 1, 2)),
    privacy                TEXT    NOT NULL CHECK (privacy IN ('LOCAL_ONLY', 'VENDOR_OK', 'ANY')),
    workspace_id           TEXT,
    workspace_sensitivity  INTEGER CHECK (workspace_sensitivity IN (0, 1, 2)),
    CHECK ((workspace_id IS NULL) = (workspace_sensitivity IS NULL))
) STRICT;
CREATE TRIGGER run_policy_input_taint_only_rises BEFORE UPDATE OF taint ON run_policy_input
WHEN NEW.taint < OLD.taint
BEGIN SELECT RAISE(ABORT, 'taint never decreases'); END;
CREATE TRIGGER run_policy_input_fixed BEFORE UPDATE OF run_id, origin, privacy,
    workspace_id, workspace_sensitivity ON run_policy_input
BEGIN SELECT RAISE(ABORT, 'origin, privacy and workspace are fixed at admission'); END;
CREATE TRIGGER run_policy_input_no_delete BEFORE DELETE ON run_policy_input
BEGIN SELECT RAISE(ABORT, 'a run''s policy inputs are never deleted'); END;

CREATE TABLE admission_idempotency (
    subject          TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    idempotency_key  TEXT    NOT NULL,
    request_digest   TEXT    NOT NULL CHECK (length(request_digest) = 64),
    run_id           TEXT    NOT NULL UNIQUE REFERENCES run(run_id) ON DELETE RESTRICT,
    grant_digest     TEXT    NOT NULL CHECK (length(grant_digest) = 64),
    recorded_ms      INTEGER NOT NULL,
    PRIMARY KEY (subject, session_id, idempotency_key)
) STRICT;
CREATE TRIGGER admission_idempotency_no_update BEFORE UPDATE ON admission_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is immutable'); END;
CREATE TRIGGER admission_idempotency_no_delete BEFORE DELETE ON admission_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is never deleted'); END;
";

/// Schema version 2 (M4a, ADR-0042 §8): a workspace's filesystem root.
///
/// One row per workspace that has one, written once by the operator and never
/// changed: the host path the root was opened through, and the identity the
/// directory had when it was measured — device and inode as decimal text, so
/// the whole `u64` range survives SQLite's signed integers, and the birth time
/// where the filesystem reports one. Binding a different root is a new
/// workspace, never an edit, so a live run's workspace can never be re-pointed
/// by a configuration change.
pub(super) const SCHEMA_V2: &str = r"
CREATE TABLE workspace_root (
    workspace_id  TEXT    PRIMARY KEY REFERENCES workspace(workspace_id) ON DELETE RESTRICT,
    host_path     TEXT    NOT NULL CHECK (length(CAST(host_path AS BLOB)) BETWEEN 1 AND 4096
                                          AND substr(host_path, 1, 1) = '/'),
    root_device   TEXT    NOT NULL CHECK (length(root_device) BETWEEN 1 AND 20
                                          AND root_device NOT GLOB '*[^0-9]*'),
    root_inode    TEXT    NOT NULL CHECK (length(root_inode) BETWEEN 1 AND 20
                                          AND root_inode NOT GLOB '*[^0-9]*'),
    birth_sec     INTEGER,
    birth_nsec    INTEGER CHECK (birth_nsec IS NULL OR (birth_nsec >= 0 AND birth_nsec < 1000000000)),
    installed_ms  INTEGER NOT NULL,
    CHECK ((birth_sec IS NULL) = (birth_nsec IS NULL))
) STRICT;
CREATE TRIGGER workspace_root_no_update BEFORE UPDATE ON workspace_root
BEGIN SELECT RAISE(ABORT, 'a workspace root binding is immutable; bind another root as a new workspace'); END;
CREATE TRIGGER workspace_root_no_delete BEFORE DELETE ON workspace_root
BEGIN SELECT RAISE(ABORT, 'a workspace root binding is never deleted'); END;
";

/// Schema version 3 (M4b, ADR-0043 §7): one row per tool invocation the
/// authority authorised.
///
/// The row is written in the transaction that records the intent — after the
/// path resolved and both gates allowed the action, **before the object is
/// opened for reading** and before the broker is told anything — and ended
/// exactly once: `FAILED` (`OBJECT_CHANGED`, `OBJECT_UNREADABLE`) when the
/// object can then not be opened and proved, `COMPLETED` or `FAILED` in the
/// transaction that records the broker's outcome, or `INTERRUPTED` by the next
/// incarnation's start when the process died in between. What was authorised
/// (the run, the canonical path, the byte bound, the object's device and
/// inode) is fixed at insert; how it ended is written once. So a crash between
/// intent and outcome is never silent: the next start finds the open row and
/// records that its result was never delivered.
pub(super) const SCHEMA_V3: &str = r"
CREATE TABLE tool_invocation (
    invocation_id   TEXT    PRIMARY KEY CHECK (length(invocation_id) = 30
                                               AND substr(invocation_id, 1, 4) = 'inv_'),
    run_id          TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    tool            TEXT    NOT NULL CHECK (tool = 'fs.read'),
    canonical_path  TEXT    NOT NULL CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 10 AND 4096
                                            AND substr(canonical_path, 1, 10) = '/workspace'),
    byte_count      INTEGER NOT NULL CHECK (byte_count BETWEEN 1 AND 262144),
    object_device   TEXT    NOT NULL CHECK (length(object_device) BETWEEN 1 AND 20
                                            AND object_device NOT GLOB '*[^0-9]*'),
    object_inode    TEXT    NOT NULL CHECK (length(object_inode) BETWEEN 1 AND 20
                                            AND object_inode NOT GLOB '*[^0-9]*'),
    incarnation     INTEGER NOT NULL CHECK (incarnation >= 1),
    state           TEXT    NOT NULL CHECK (state IN ('INTENT', 'COMPLETED', 'FAILED', 'INTERRUPTED')),
    failure         TEXT    CHECK (failure IS NULL OR failure IN ('OBJECT_CHANGED',
                                   'OBJECT_UNREADABLE', 'BROKER_UNAVAILABLE',
                                   'BROKER_PROTOCOL_ERROR', 'BROKER_EXECUTION_ERROR')),
    bytes_returned  INTEGER CHECK (bytes_returned IS NULL OR bytes_returned BETWEEN 0 AND byte_count),
    intent_ms       INTEGER NOT NULL,
    ended_ms        INTEGER,
    CHECK ((state = 'INTENT') = (ended_ms IS NULL)),
    CHECK ((state = 'FAILED') = (failure IS NOT NULL)),
    CHECK ((state = 'COMPLETED') = (bytes_returned IS NOT NULL))
) STRICT;
CREATE INDEX tool_invocation_by_state ON tool_invocation(state);
CREATE TRIGGER tool_invocation_intent_fixed BEFORE UPDATE OF invocation_id, run_id, tool,
    canonical_path, byte_count, object_device, object_inode, incarnation, intent_ms
    ON tool_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation''s intent is immutable'); END;
CREATE TRIGGER tool_invocation_ends_once BEFORE UPDATE OF state, failure, bytes_returned,
    ended_ms ON tool_invocation
WHEN OLD.state != 'INTENT'
BEGIN SELECT RAISE(ABORT, 'an invocation ends once'); END;
CREATE TRIGGER tool_invocation_no_delete BEFORE DELETE ON tool_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation record is never deleted'); END;
";

/// One step from a version to the next.
#[derive(Debug, Clone, Copy)]
pub(super) struct Migration {
    /// The version this step produces.
    pub(super) to: i64,
    /// Its DDL. Static text.
    pub(super) sql: &'static str,
}

/// Every migration this build knows, in order. Version 0 is "no schema".
pub(super) const MIGRATIONS: &[Migration] = &[
    Migration {
        to: 1,
        sql: SCHEMA_V1,
    },
    Migration {
        to: 2,
        sql: SCHEMA_V2,
    },
    Migration {
        to: 3,
        sql: SCHEMA_V3,
    },
];

/// What an opened file turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape {
    /// An empty database: no id, no version, no objects.
    Empty,
    /// A DireWolf store at an older version.
    Older(i64),
    /// A DireWolf store at this build's version.
    Current,
}

/// Why a file cannot be used as this build's store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ShapeError {
    /// Not a DireWolf store.
    Foreign,
    /// Written by a newer build.
    Future(i64),
    /// A DireWolf id with a version that no build ever wrote.
    Malformed(String),
}

/// Read the id, the version and the object count, and decide.
pub(super) fn classify(conn: &Connection) -> rusqlite::Result<Result<Shape, ShapeError>> {
    let id: i64 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let objects: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        [],
        |row| row.get(0),
    )?;
    Ok(decide(id, version, objects))
}

fn decide(id: i64, version: i64, objects: i64) -> Result<Shape, ShapeError> {
    if id == 0 && version == 0 {
        return if objects == 0 {
            Ok(Shape::Empty)
        } else {
            Err(ShapeError::Foreign)
        };
    }
    if id != APPLICATION_ID {
        return Err(ShapeError::Foreign);
    }
    if version > CURRENT_VERSION {
        return Err(ShapeError::Future(version));
    }
    if version == CURRENT_VERSION {
        return Ok(Shape::Current);
    }
    if version < 1 {
        return Err(ShapeError::Malformed(format!(
            "a DireWolf application id with schema version {version}"
        )));
    }
    Ok(Shape::Older(version))
}

/// Apply every migration after `from`, inside the caller's transaction, and
/// stamp the result. The caller commits or, on any error, rolls back — so a
/// failed migration leaves the store exactly as it was.
pub(super) fn migrate(
    tx: &Connection,
    from: i64,
    migrations: &[Migration],
) -> rusqlite::Result<i64> {
    let mut version = from;
    for step in migrations.iter().filter(|m| m.to > from) {
        tx.execute_batch(step.sql)?;
        version = step.to;
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", version)?;
    Ok(version)
}

/// A schema object: `(type, name, tbl_name, sql)`.
type Object = (String, String, String, Option<String>);

fn objects(conn: &Connection) -> rusqlite::Result<Vec<Object>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema \
         WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    rows.collect()
}

/// Compare a store's schema with the one this build's DDL produces, object by
/// object and byte by byte. Returns a description of the first difference.
pub(super) fn verify_exact(conn: &Connection) -> rusqlite::Result<Result<(), String>> {
    let reference = Connection::open_in_memory()?;
    for step in MIGRATIONS {
        reference.execute_batch(step.sql)?;
    }
    let expected = objects(&reference)?;
    let found = objects(conn)?;
    for object in &expected {
        if !found.contains(object) {
            return Ok(Err(format!(
                "the {} `{}` is missing or differs from this build's definition",
                object.0, object.1
            )));
        }
    }
    for object in &found {
        if !expected.contains(object) {
            return Ok(Err(format!(
                "the {} `{}` is not part of this build's schema",
                object.0, object.1
            )));
        }
    }
    Ok(Ok(()))
}

/// `PRAGMA quick_check`: `Ok(Ok(()))` when SQLite reports exactly `ok`.
pub(super) fn quick_check(conn: &Connection) -> rusqlite::Result<Result<(), String>> {
    let mut statement = conn.prepare("PRAGMA quick_check")?;
    let rows: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if rows.len() == 1 && rows.first().map(String::as_str) == Some("ok") {
        Ok(Ok(()))
    } else {
        Ok(Err(rows.join("; ")))
    }
}

/// `PRAGMA foreign_key_check`: `Ok(Ok(()))` when no row violates a foreign key.
pub(super) fn foreign_key_check(conn: &Connection) -> rusqlite::Result<Result<(), String>> {
    let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
    let violations: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    if violations.is_empty() {
        Ok(Ok(()))
    } else {
        Ok(Err(format!(
            "foreign key violations in: {}",
            violations.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APPLICATION_ID, CURRENT_VERSION, MIGRATIONS, Migration, SCHEMA_V1, SCHEMA_V2, SCHEMA_V3,
        Shape, ShapeError, decide, migrate, verify_exact,
    };
    use rusqlite::Connection;

    #[test]
    fn every_shape_of_file_is_decided_and_only_an_empty_one_is_created() {
        assert_eq!(decide(0, 0, 0), Ok(Shape::Empty));
        assert_eq!(
            decide(0, 0, 3),
            Err(ShapeError::Foreign),
            "someone's tables"
        );
        assert_eq!(
            decide(7, 1, 3),
            Err(ShapeError::Foreign),
            "another program's id"
        );
        assert_eq!(
            decide(APPLICATION_ID, CURRENT_VERSION, 30),
            Ok(Shape::Current)
        );
        assert_eq!(
            decide(APPLICATION_ID, CURRENT_VERSION + 1, 30),
            Err(ShapeError::Future(CURRENT_VERSION + 1))
        );
        assert!(matches!(
            decide(APPLICATION_ID, 0, 30),
            Err(ShapeError::Malformed(_))
        ));
        assert!(matches!(
            decide(APPLICATION_ID, -1, 30),
            Err(ShapeError::Malformed(_))
        ));
    }

    #[test]
    fn the_schema_is_strict_and_verifies_against_itself() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        let Ok(tx) = conn.unchecked_transaction() else {
            unreachable!("a transaction")
        };
        assert_eq!(migrate(&tx, 0, MIGRATIONS).ok(), Some(CURRENT_VERSION));
        assert!(tx.commit().is_ok());
        assert_eq!(verify_exact(&conn).ok(), Some(Ok(())));
        // STRICT: a text in an integer column is refused, not coerced.
        let refused = conn.execute(
            "INSERT INTO workspace (workspace_id, sensitivity, installed_ms) VALUES ('w', 'high', 0)",
            [],
        );
        assert!(refused.is_err(), "STRICT tables must refuse a coercion");
    }

    #[test]
    fn a_dropped_trigger_is_a_malformed_store() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        assert!(conn.execute_batch(SCHEMA_V1).is_ok());
        assert!(conn.execute_batch(SCHEMA_V2).is_ok());
        assert!(conn.execute_batch(SCHEMA_V3).is_ok());
        assert!(
            conn.execute_batch("DROP TRIGGER run_never_resurrects")
                .is_ok()
        );
        let Ok(Err(why)) = verify_exact(&conn) else {
            unreachable!("a dropped trigger must be detected")
        };
        assert!(why.contains("run_never_resurrects"), "{why}");
    }

    #[test]
    fn an_extra_object_is_a_malformed_store() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        assert!(conn.execute_batch(SCHEMA_V1).is_ok());
        assert!(conn.execute_batch(SCHEMA_V2).is_ok());
        assert!(conn.execute_batch(SCHEMA_V3).is_ok());
        assert!(
            conn.execute_batch("CREATE TABLE backdoor (x INTEGER)")
                .is_ok()
        );
        let Ok(Err(why)) = verify_exact(&conn) else {
            unreachable!("an extra table must be detected")
        };
        assert!(why.contains("backdoor"), "{why}");
    }

    #[test]
    fn a_failed_migration_rolls_back_completely() {
        // A future step that fails half way: the schema, the version and the
        // application id must all be exactly what they were before it began.
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert!(migrate(&tx, 0, MIGRATIONS).is_ok());
            assert!(tx.commit().is_ok());
        }
        let mut failing = MIGRATIONS.to_vec();
        failing.push(Migration {
            to: CURRENT_VERSION + 1,
            sql: "CREATE TABLE added_by_the_future (x INTEGER) STRICT; \
                  THIS IS NOT SQL;",
        });
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert!(
                migrate(&tx, CURRENT_VERSION, &failing).is_err(),
                "the step must fail"
            );
            // Dropped without commit: rolled back.
        }
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap_or(-1);
        assert_eq!(version, CURRENT_VERSION, "the version did not move");
        assert_eq!(
            verify_exact(&conn).ok(),
            Some(Ok(())),
            "no half-applied table"
        );
    }

    #[test]
    fn a_version_one_store_migrates_to_the_current_schema_exactly() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        let Some(first) = MIGRATIONS.first() else {
            unreachable!("version 1 exists")
        };
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert_eq!(migrate(&tx, 0, &[*first]).ok(), Some(1));
            assert!(tx.commit().is_ok());
        }
        assert!(
            matches!(verify_exact(&conn), Ok(Err(_))),
            "a v1 store is not a v2 store"
        );
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert_eq!(migrate(&tx, 1, MIGRATIONS).ok(), Some(CURRENT_VERSION));
            assert!(tx.commit().is_ok());
        }
        assert_eq!(verify_exact(&conn).ok(), Some(Ok(())));
    }

    #[test]
    fn an_invocation_intent_is_fixed_and_ends_exactly_once() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        let Ok(tx) = conn.unchecked_transaction() else {
            unreachable!("a transaction")
        };
        assert!(migrate(&tx, 0, MIGRATIONS).is_ok());
        assert!(tx.commit().is_ok());
        // The row below names a run that does not exist. Foreign keys are the
        // store's configuration (`db::configure` turns them on), not what this
        // test measures, so they are off here and the column rules are alone.
        assert!(conn.pragma_update(None, "foreign_keys", false).is_ok());
        let insert = |id: &str, path: &str, count: i64, state: &str| {
            conn.execute(
                "INSERT INTO tool_invocation (invocation_id, run_id, tool, canonical_path, \
                 byte_count, object_device, object_inode, incarnation, state, failure, \
                 bytes_returned, intent_ms, ended_ms) \
                 VALUES (?1, 'run_x', 'fs.read', ?2, ?3, '2049', '12', 1, ?4, NULL, NULL, 0, NULL)",
                rusqlite::params![id, path, count, state],
            )
        };
        let id = "inv_01M24BB8G3E0A851TRWE3M8FZF";
        assert!(insert(id, "/workspace/a", 4, "INTENT").is_ok());
        for (bad_id, path, count, state) in [
            ("inv_short", "/workspace/a", 4, "INTENT"),
            (
                "cap_01M24BB8G3E0A851TRWE3M8FZG",
                "/workspace/a",
                4,
                "INTENT",
            ),
            ("inv_01M24BB8G3E0A851TRWE3M8FZG", "/etc/passwd", 4, "INTENT"),
            (
                "inv_01M24BB8G3E0A851TRWE3M8FZG",
                "/workspace/a",
                0,
                "INTENT",
            ),
            (
                "inv_01M24BB8G3E0A851TRWE3M8FZG",
                "/workspace/a",
                262_145,
                "INTENT",
            ),
            (
                "inv_01M24BB8G3E0A851TRWE3M8FZG",
                "/workspace/a",
                4,
                "COMPLETED",
            ),
        ] {
            assert!(
                insert(bad_id, path, count, state).is_err(),
                "{bad_id} {path} {count} {state}"
            );
        }
        let ended = |sql: &str| conn.execute(sql, []);
        assert!(ended("UPDATE tool_invocation SET canonical_path = '/workspace/b'").is_err());
        assert!(ended("UPDATE tool_invocation SET object_inode = '13'").is_err());
        assert!(
            ended(
                "UPDATE tool_invocation SET state = 'COMPLETED', bytes_returned = 5, ended_ms = 1"
            )
            .is_err(),
            "more bytes than the bound"
        );
        assert!(
            ended(
                "UPDATE tool_invocation SET state = 'COMPLETED', bytes_returned = 4, ended_ms = 1"
            )
            .is_ok()
        );
        assert!(
            ended("UPDATE tool_invocation SET state = 'INTERRUPTED', bytes_returned = NULL, ended_ms = 2")
                .is_err(),
            "an ended invocation ends once"
        );
        assert!(ended("DELETE FROM tool_invocation").is_err());
    }

    #[test]
    fn a_workspace_root_binding_is_immutable_and_bounded() {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        assert!(conn.execute_batch(SCHEMA_V1).is_ok());
        assert!(conn.execute_batch(SCHEMA_V2).is_ok());
        assert!(
            conn.execute(
                "INSERT INTO workspace (workspace_id, sensitivity, installed_ms) VALUES ('w', 0, 0)",
                [],
            )
            .is_ok()
        );
        let insert = |path: &str, device: &str, inode: &str| {
            conn.execute(
                "INSERT INTO workspace_root (workspace_id, host_path, root_device, root_inode, \
                 birth_sec, birth_nsec, installed_ms) VALUES ('w', ?1, ?2, ?3, NULL, NULL, 0)",
                rusqlite::params![path, device, inode],
            )
        };
        assert!(insert("relative", "1", "2").is_err(), "not absolute");
        assert!(insert("/srv/w", "-1", "2").is_err(), "not a decimal u64");
        assert!(insert("/srv/w", "1", "18446744073709551615").is_ok());
        assert!(
            conn.execute("UPDATE workspace_root SET host_path = '/elsewhere'", [])
                .is_err(),
            "a binding is never re-pointed"
        );
        assert!(
            conn.execute("DELETE FROM workspace_root", []).is_err(),
            "a binding is never removed"
        );
    }
}
