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
pub(super) const CURRENT_VERSION: i64 = 5;

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

/// Schema version 4 (M4c, ADR-0044 §7): every filesystem tool, its retry
/// class, and an outcome that may be **unknown**.
///
/// `tool_invocation` is rebuilt — SQLite cannot change a `CHECK` in place —
/// inside the migration's one transaction: the version-3 table is renamed
/// aside, the version-4 table created, every row copied (a version-3 row is an
/// `fs.read`: `RETRY_SAFE`, an existing object, completed as `READ` with the
/// bytes it returned), and the old table dropped with its triggers and index.
/// A failure anywhere rolls the whole step back (`migrate`).
///
/// What changes:
///
/// * **Eight tools, each with its fixed retry class**: `fs.move` and
///   `fs.delete` are `NON_RETRYABLE`, every other `RETRY_SAFE`. A `CHECK`
///   ties the class to the tool, so no row can claim a move is safe to repeat.
/// * **A target may be vacant** (a creating `fs.write`): then its identity
///   columns hold its parent directory's. A move's destination has its own
///   columns — the destination's canonical path and its parent's identity.
/// * **Two ambiguous endings, kept apart.** `INTERRUPTED` — the process ended
///   between intent and outcome — is only for a tool without effect (the read
///   family), where nothing can be in doubt. `UNKNOWN` — the broker may have
///   changed something and nothing proves what — is only for a tool with an
///   effect. Start-up ends an open intent `INTERRUPTED` or `UNKNOWN` by that
///   rule and **never performs it** (ADR-0044 §10).
/// * **A completion**, fixed per tool (`CREATED` or `REPLACED` for a write,
///   `APPLIED` or `ALREADY_APPLIED` for a patch, …), and the content bytes it
///   moved, which never exceed the bound decided on.
///
/// `tool_idempotency` binds a version-2 invocation's idempotency key, scoped
/// to its caller and session like `admission_idempotency`, to the one
/// invocation minted for it — in the transaction that records the intent. A
/// key names one invocation, ever: it is never deleted and never re-bound.
///
/// `tool_staging` records, **with the intent**, the one staging directory a
/// write, a patch or a delete may make (ADR-0044 §10): where it will be — the
/// checked parent directory's canonical path and identity — and the name and
/// object it concerns, so that a directory a crash leaves behind is never
/// untracked. It starts `EXPECTED` and settles once: `CLEARED` when the
/// broker's answer proves nothing is left (or nothing was sent), `REMOVED`
/// when a reclamation found it disposable and removed it, `RETAINED` — with
/// what it holds, and the held object's identity — when it may hold a
/// workspace object or is the evidence of an effect, and `FOREIGN` when the
/// name is not the broker's. A row is never deleted.
pub(super) const SCHEMA_V4: &str = r"
ALTER TABLE tool_invocation RENAME TO tool_invocation_v3;
CREATE TABLE tool_invocation (
    invocation_id       TEXT    PRIMARY KEY CHECK (length(invocation_id) = 30
                                                   AND substr(invocation_id, 1, 4) = 'inv_'),
    run_id              TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    tool                TEXT    NOT NULL CHECK (tool IN ('fs.read', 'fs.list', 'fs.search',
                                    'fs.stat', 'fs.write', 'fs.patch', 'fs.move', 'fs.delete')),
    retry_class         TEXT    NOT NULL CHECK (retry_class IN ('RETRY_SAFE', 'NON_RETRYABLE')),
    canonical_path      TEXT    NOT NULL CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 10 AND 4096
                                                AND substr(canonical_path, 1, 10) = '/workspace'),
    object_state        TEXT    NOT NULL CHECK (object_state IN ('EXISTING', 'VACANT')),
    object_device       TEXT    NOT NULL CHECK (length(object_device) BETWEEN 1 AND 20
                                                AND object_device NOT GLOB '*[^0-9]*'),
    object_inode        TEXT    NOT NULL CHECK (length(object_inode) BETWEEN 1 AND 20
                                                AND object_inode NOT GLOB '*[^0-9]*'),
    destination_path    TEXT    CHECK (destination_path IS NULL
                                       OR (length(CAST(destination_path AS BLOB)) BETWEEN 11 AND 4096
                                           AND substr(destination_path, 1, 11) = '/workspace/')),
    destination_device  TEXT    CHECK (destination_device IS NULL
                                       OR (length(destination_device) BETWEEN 1 AND 20
                                           AND destination_device NOT GLOB '*[^0-9]*')),
    destination_inode   TEXT    CHECK (destination_inode IS NULL
                                       OR (length(destination_inode) BETWEEN 1 AND 20
                                           AND destination_inode NOT GLOB '*[^0-9]*')),
    byte_count          INTEGER NOT NULL CHECK (byte_count BETWEEN 0 AND 16777216),
    incarnation         INTEGER NOT NULL CHECK (incarnation >= 1),
    state               TEXT    NOT NULL CHECK (state IN ('INTENT', 'COMPLETED', 'FAILED',
                                                          'INTERRUPTED', 'UNKNOWN')),
    failure             TEXT    CHECK (failure IS NULL OR failure IN ('OBJECT_CHANGED',
                                       'OBJECT_UNREADABLE', 'TARGET_OCCUPIED', 'CONFLICT',
                                       'DIRECTORY_NOT_EMPTY', 'WRITE_DENIED',
                                       'ATTRIBUTES_NOT_PRESERVED', 'SHARED_DIRECTORY',
                                       'BROKER_UNAVAILABLE',
                                       'BROKER_PROTOCOL_ERROR', 'BROKER_EXECUTION_ERROR')),
    completion          TEXT,
    content_bytes       INTEGER CHECK (content_bytes IS NULL OR content_bytes BETWEEN 0 AND byte_count),
    intent_ms           INTEGER NOT NULL,
    ended_ms            INTEGER,
    CHECK ((retry_class = 'NON_RETRYABLE') = (tool IN ('fs.move', 'fs.delete'))),
    CHECK (object_state = 'EXISTING' OR tool = 'fs.write'),
    CHECK (tool != 'fs.read' OR byte_count BETWEEN 1 AND 262144),
    CHECK ((tool = 'fs.move') = (destination_path IS NOT NULL)),
    CHECK ((destination_path IS NULL) = (destination_device IS NULL)),
    CHECK ((destination_path IS NULL) = (destination_inode IS NULL)),
    CHECK ((state = 'INTENT') = (ended_ms IS NULL)),
    CHECK ((state = 'FAILED') = (failure IS NOT NULL)),
    CHECK ((state = 'COMPLETED') = (completion IS NOT NULL)),
    CHECK ((completion IS NULL) = (content_bytes IS NULL)),
    CHECK (state != 'INTERRUPTED' OR tool IN ('fs.read', 'fs.list', 'fs.search', 'fs.stat')),
    CHECK (state != 'UNKNOWN' OR tool IN ('fs.write', 'fs.patch', 'fs.move', 'fs.delete')),
    CHECK (completion IS NULL
           OR (tool = 'fs.read' AND completion = 'READ')
           OR (tool = 'fs.list' AND completion = 'LISTED')
           OR (tool = 'fs.search' AND completion = 'SEARCHED')
           OR (tool = 'fs.stat' AND completion = 'STATED')
           OR (tool = 'fs.write' AND completion IN ('CREATED', 'REPLACED'))
           OR (tool = 'fs.patch' AND completion IN ('APPLIED', 'ALREADY_APPLIED'))
           OR (tool = 'fs.move' AND completion = 'MOVED')
           OR (tool = 'fs.delete' AND completion = 'DELETED'))
) STRICT;
INSERT INTO tool_invocation (invocation_id, run_id, tool, retry_class, canonical_path,
    object_state, object_device, object_inode, destination_path, destination_device,
    destination_inode, byte_count, incarnation, state, failure, completion, content_bytes,
    intent_ms, ended_ms)
SELECT invocation_id, run_id, tool, 'RETRY_SAFE', canonical_path, 'EXISTING', object_device,
    object_inode, NULL, NULL, NULL, byte_count, incarnation, state, failure,
    CASE WHEN state = 'COMPLETED' THEN 'READ' END, bytes_returned, intent_ms, ended_ms
FROM tool_invocation_v3;
DROP TABLE tool_invocation_v3;
CREATE INDEX tool_invocation_by_state ON tool_invocation(state);
CREATE TRIGGER tool_invocation_intent_fixed BEFORE UPDATE OF invocation_id, run_id, tool,
    retry_class, canonical_path, object_state, object_device, object_inode, destination_path,
    destination_device, destination_inode, byte_count, incarnation, intent_ms
    ON tool_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation''s intent is immutable'); END;
CREATE TRIGGER tool_invocation_ends_once BEFORE UPDATE OF state, failure, completion,
    content_bytes, ended_ms ON tool_invocation
WHEN OLD.state != 'INTENT'
BEGIN SELECT RAISE(ABORT, 'an invocation ends once'); END;
CREATE TRIGGER tool_invocation_no_delete BEFORE DELETE ON tool_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation record is never deleted'); END;

CREATE TABLE tool_idempotency (
    subject          TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    idempotency_key  TEXT    NOT NULL,
    request_digest   TEXT    NOT NULL CHECK (length(request_digest) = 64
                                             AND request_digest NOT GLOB '*[^0-9a-f]*'),
    invocation_id    TEXT    NOT NULL UNIQUE REFERENCES tool_invocation(invocation_id)
                                             ON DELETE RESTRICT,
    recorded_ms      INTEGER NOT NULL,
    PRIMARY KEY (subject, session_id, idempotency_key)
) STRICT;
CREATE TRIGGER tool_idempotency_no_update BEFORE UPDATE ON tool_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is immutable'); END;
CREATE TRIGGER tool_idempotency_no_delete BEFORE DELETE ON tool_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is never deleted'); END;

CREATE TABLE tool_staging (
    invocation_id   TEXT    PRIMARY KEY REFERENCES tool_invocation(invocation_id)
                                        ON DELETE RESTRICT,
    operation       TEXT    NOT NULL CHECK (operation IN ('REPLACE', 'CREATE', 'DELETE')),
    parent_path     TEXT    NOT NULL CHECK (length(CAST(parent_path AS BLOB)) BETWEEN 10 AND 4096
                                            AND substr(parent_path, 1, 10) = '/workspace'),
    parent_device   TEXT    NOT NULL CHECK (length(parent_device) BETWEEN 1 AND 20
                                            AND parent_device NOT GLOB '*[^0-9]*'),
    parent_inode    TEXT    NOT NULL CHECK (length(parent_inode) BETWEEN 1 AND 20
                                            AND parent_inode NOT GLOB '*[^0-9]*'),
    leaf            TEXT    NOT NULL CHECK (length(CAST(leaf AS BLOB)) BETWEEN 1 AND 255),
    target_device   TEXT    CHECK (target_device IS NULL
                                   OR (length(target_device) BETWEEN 1 AND 20
                                       AND target_device NOT GLOB '*[^0-9]*')),
    target_inode    TEXT    CHECK (target_inode IS NULL
                                   OR (length(target_inode) BETWEEN 1 AND 20
                                       AND target_inode NOT GLOB '*[^0-9]*')),
    state           TEXT    NOT NULL CHECK (state IN ('EXPECTED', 'CLEARED', 'REMOVED',
                                                      'RETAINED', 'FOREIGN')),
    holds           TEXT    CHECK (holds IS NULL
                                   OR holds IN ('DISPLACED', 'TAKEN', 'EVIDENCE', 'UNEXPECTED')),
    held_device     TEXT    CHECK (held_device IS NULL
                                   OR (length(held_device) BETWEEN 1 AND 20
                                       AND held_device NOT GLOB '*[^0-9]*')),
    held_inode      TEXT    CHECK (held_inode IS NULL
                                   OR (length(held_inode) BETWEEN 1 AND 20
                                       AND held_inode NOT GLOB '*[^0-9]*')),
    recorded_ms     INTEGER NOT NULL,
    settled_ms      INTEGER,
    CHECK ((operation = 'CREATE') = (target_device IS NULL)),
    CHECK ((target_device IS NULL) = (target_inode IS NULL)),
    CHECK ((state = 'EXPECTED') = (settled_ms IS NULL)),
    CHECK ((state = 'RETAINED') = (holds IS NOT NULL)),
    CHECK ((held_device IS NULL) = (held_inode IS NULL)),
    CHECK (held_device IS NULL OR state = 'RETAINED')
) STRICT;
CREATE INDEX tool_staging_by_state ON tool_staging(state);
CREATE TRIGGER tool_staging_only_for_names BEFORE INSERT ON tool_staging
WHEN (SELECT tool FROM tool_invocation WHERE invocation_id = NEW.invocation_id)
     NOT IN ('fs.write', 'fs.patch', 'fs.delete')
BEGIN SELECT RAISE(ABORT, 'only a write, a patch or a delete stages'); END;
CREATE TRIGGER tool_staging_fixed BEFORE UPDATE OF invocation_id, operation, parent_path,
    parent_device, parent_inode, leaf, target_device, target_inode, recorded_ms ON tool_staging
BEGIN SELECT RAISE(ABORT, 'a staging record''s location is immutable'); END;
CREATE TRIGGER tool_staging_settles_once BEFORE UPDATE OF state, holds, held_device,
    held_inode, settled_ms ON tool_staging
WHEN OLD.state != 'EXPECTED'
BEGIN SELECT RAISE(ABORT, 'a staging record settles once'); END;
CREATE TRIGGER tool_staging_no_delete BEFORE DELETE ON tool_staging
BEGIN SELECT RAISE(ABORT, 'a staging record is never deleted'); END;
";

/// Schema version 5 (M4d, ADR-0045 §16): the process tools' own ledger, the
/// processes the authority launched, and one idempotency namespace across
/// both ledgers.
///
/// **The filesystem ledger is not touched.** `tool_invocation`,
/// `tool_idempotency` and `tool_staging` keep their version-4 definitions
/// byte for byte: rebuilding a table other tables reference would make the
/// migrated schema's text depend on how SQLite rewrites references, and the
/// store's schema is verified exactly. The process tools get their own tables
/// instead.
///
/// * `process_invocation` — one row per `process.exec`, `process.status` or
///   `process.kill` whose plan was allowed, written with the **intent**,
///   before any descriptor that could launch or signal exists. Its rules are
///   the filesystem ledger's: the intent is fixed, it ends once, and the two
///   ambiguous endings are kept apart — `INTERRUPTED` only for
///   `process.status`, which has no effect; `UNKNOWN` only for `process.exec`
///   and `process.kill`, which do. `process.exec` and `process.kill` are
///   `NON_RETRYABLE`, `process.status` `RETRY_SAFE`, and a `CHECK` ties the
///   class to the tool.
/// * `tool_process` — one row per launch, written in the launch intent's
///   transaction (`LAUNCHING`): the stored executable identity (canonical
///   path, digest, device, inode), the working directory, the argument count
///   and digest — never the arguments themselves — the argv classification,
///   the environment profile and the output bound. The identity is immutable;
///   the broker generation is written once, when a launch is confirmed; the
///   state moves only forward (`LAUNCHING` to `RUNNING`, `EXITED`,
///   `SIGNALED`, `FAILED` or `UNKNOWN`; `RUNNING` to `EXITED`, `SIGNALED` or
///   `UNOBSERVABLE`); nothing is deleted. A status or a kill may name only a
///   process of its own run, and a launch only a process id nobody holds.
/// * `process_idempotency` — a version-3 process invocation's key, as
///   `tool_idempotency` binds a filesystem invocation's. A key is one
///   namespace across both: a trigger on each table refuses a key the other
///   already holds, so a key names one invocation, ever, whichever ledger it
///   is in.
pub(super) const SCHEMA_V5: &str = r"
CREATE TABLE process_invocation (
    invocation_id   TEXT    PRIMARY KEY CHECK (length(invocation_id) = 30
                                               AND substr(invocation_id, 1, 4) = 'inv_'),
    run_id          TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    tool            TEXT    NOT NULL CHECK (tool IN ('process.exec', 'process.status',
                                                     'process.kill')),
    retry_class     TEXT    NOT NULL CHECK (retry_class IN ('RETRY_SAFE', 'NON_RETRYABLE')),
    process_id      TEXT    NOT NULL CHECK (length(process_id) = 30
                                            AND substr(process_id, 1, 4) = 'prc_'),
    incarnation     INTEGER NOT NULL CHECK (incarnation >= 1),
    state           TEXT    NOT NULL CHECK (state IN ('INTENT', 'COMPLETED', 'FAILED',
                                                      'INTERRUPTED', 'UNKNOWN')),
    failure         TEXT    CHECK (failure IS NULL OR failure IN ('EXECUTABLE_CHANGED',
                                   'EXEC_FAILED', 'PROCESS_TABLE_FULL',
                                   'BROKER_ENVIRONMENT_UNSAFE', 'PROCESS_UNOBSERVABLE',
                                   'OBJECT_CHANGED', 'OBJECT_UNREADABLE', 'BROKER_UNAVAILABLE',
                                   'BROKER_PROTOCOL_ERROR', 'BROKER_EXECUTION_ERROR')),
    completion      TEXT,
    output_bytes    INTEGER CHECK (output_bytes IS NULL OR output_bytes BETWEEN 0 AND 262144),
    intent_ms       INTEGER NOT NULL,
    ended_ms        INTEGER,
    CHECK ((retry_class = 'NON_RETRYABLE') = (tool IN ('process.exec', 'process.kill'))),
    CHECK ((state = 'INTENT') = (ended_ms IS NULL)),
    CHECK ((state = 'FAILED') = (failure IS NOT NULL)),
    CHECK ((state = 'COMPLETED') = (completion IS NOT NULL)),
    CHECK ((completion IS NULL) = (output_bytes IS NULL)),
    CHECK (output_bytes IS NULL OR output_bytes = 0 OR tool = 'process.status'),
    CHECK (state != 'INTERRUPTED' OR tool = 'process.status'),
    CHECK (state != 'UNKNOWN' OR tool IN ('process.exec', 'process.kill')),
    CHECK (completion IS NULL
           OR (tool = 'process.exec' AND completion = 'LAUNCHED')
           OR (tool = 'process.status' AND completion = 'OBSERVED')
           OR (tool = 'process.kill' AND completion IN ('SIGNALED', 'ALREADY_EXITED')))
) STRICT;
CREATE INDEX process_invocation_by_state ON process_invocation(state);
CREATE TRIGGER process_invocation_intent_fixed BEFORE UPDATE OF invocation_id, run_id, tool,
    retry_class, process_id, incarnation, intent_ms ON process_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation''s intent is immutable'); END;
CREATE TRIGGER process_invocation_ends_once BEFORE UPDATE OF state, failure, completion,
    output_bytes, ended_ms ON process_invocation
WHEN OLD.state != 'INTENT'
BEGIN SELECT RAISE(ABORT, 'an invocation ends once'); END;
CREATE TRIGGER process_invocation_no_delete BEFORE DELETE ON process_invocation
BEGIN SELECT RAISE(ABORT, 'an invocation record is never deleted'); END;
CREATE TRIGGER process_invocation_launches_a_new_process BEFORE INSERT ON process_invocation
WHEN NEW.tool = 'process.exec'
     AND EXISTS (SELECT 1 FROM process_invocation WHERE process_id = NEW.process_id)
BEGIN SELECT RAISE(ABORT, 'a launch names a process nobody holds'); END;
CREATE TRIGGER process_invocation_names_its_runs_process BEFORE INSERT ON process_invocation
WHEN NEW.tool != 'process.exec'
     AND NOT EXISTS (SELECT 1 FROM tool_process
                     WHERE process_id = NEW.process_id AND run_id = NEW.run_id)
BEGIN SELECT RAISE(ABORT, 'a status or a kill names a process of its own run'); END;

CREATE TABLE tool_process (
    process_id           TEXT    PRIMARY KEY CHECK (length(process_id) = 30
                                                    AND substr(process_id, 1, 4) = 'prc_'),
    launch_invocation_id TEXT    NOT NULL UNIQUE REFERENCES process_invocation(invocation_id)
                                                 ON DELETE RESTRICT,
    run_id               TEXT    NOT NULL REFERENCES run(run_id) ON DELETE RESTRICT,
    executable_path      TEXT    NOT NULL CHECK (length(CAST(executable_path AS BLOB))
                                                 BETWEEN 2 AND 4096
                                                 AND substr(executable_path, 1, 1) = '/'),
    executable_sha256    TEXT    NOT NULL CHECK (length(executable_sha256) = 64
                                                 AND executable_sha256 NOT GLOB '*[^0-9a-f]*'),
    executable_device    TEXT    NOT NULL CHECK (length(executable_device) BETWEEN 1 AND 20
                                                 AND executable_device NOT GLOB '*[^0-9]*'),
    executable_inode     TEXT    NOT NULL CHECK (length(executable_inode) BETWEEN 1 AND 20
                                                 AND executable_inode NOT GLOB '*[^0-9]*'),
    cwd_path             TEXT    NOT NULL CHECK (length(CAST(cwd_path AS BLOB)) BETWEEN 10 AND 4096
                                                 AND substr(cwd_path, 1, 10) = '/workspace'),
    arg_count            INTEGER NOT NULL CHECK (arg_count BETWEEN 0 AND 128),
    argv_sha256          TEXT    NOT NULL CHECK (length(argv_sha256) = 64
                                                 AND argv_sha256 NOT GLOB '*[^0-9a-f]*'),
    argv_safety          TEXT    NOT NULL CHECK (argv_safety IN ('SAFE', 'REINTERPRETING')),
    environment          TEXT    NOT NULL CHECK (environment = 'BASE'),
    stream_limit         INTEGER NOT NULL CHECK (stream_limit BETWEEN 1 AND 131072),
    broker_generation    TEXT    CHECK (broker_generation IS NULL
                                        OR (length(broker_generation) = 32
                                            AND broker_generation NOT GLOB '*[^0-9a-f]*')),
    state                TEXT    NOT NULL CHECK (state IN ('LAUNCHING', 'FAILED', 'UNKNOWN',
                                                           'RUNNING', 'EXITED', 'SIGNALED',
                                                           'UNOBSERVABLE')),
    exit_code            INTEGER CHECK (exit_code IS NULL OR exit_code BETWEEN 0 AND 255),
    signal               INTEGER CHECK (signal IS NULL OR signal BETWEEN 1 AND 64),
    timed_out            INTEGER NOT NULL CHECK (timed_out IN (0, 1)),
    created_ms           INTEGER NOT NULL,
    updated_ms           INTEGER NOT NULL,
    CHECK ((state IN ('LAUNCHING', 'FAILED', 'UNKNOWN')) = (broker_generation IS NULL)),
    CHECK ((state = 'EXITED') = (exit_code IS NOT NULL)),
    CHECK ((state = 'SIGNALED') = (signal IS NOT NULL)),
    CHECK (timed_out = 0 OR state = 'SIGNALED')
) STRICT;
CREATE INDEX tool_process_by_run ON tool_process(run_id);
CREATE TRIGGER tool_process_is_a_launch BEFORE INSERT ON tool_process
WHEN NEW.state != 'LAUNCHING'
     OR NOT EXISTS (SELECT 1 FROM process_invocation
                    WHERE invocation_id = NEW.launch_invocation_id AND tool = 'process.exec'
                      AND run_id = NEW.run_id AND process_id = NEW.process_id
                      AND state = 'INTENT')
BEGIN SELECT RAISE(ABORT, 'a process is recorded by its own launch intent'); END;
CREATE TRIGGER tool_process_identity_fixed BEFORE UPDATE OF process_id, launch_invocation_id,
    run_id, executable_path, executable_sha256, executable_device, executable_inode, cwd_path,
    arg_count, argv_sha256, argv_safety, environment, stream_limit, created_ms ON tool_process
BEGIN SELECT RAISE(ABORT, 'a process''s identity is immutable'); END;
CREATE TRIGGER tool_process_generation_once BEFORE UPDATE OF broker_generation ON tool_process
WHEN OLD.broker_generation IS NOT NULL AND NEW.broker_generation IS NOT OLD.broker_generation
BEGIN SELECT RAISE(ABORT, 'a process''s broker generation is written once'); END;
CREATE TRIGGER tool_process_moves_forward BEFORE UPDATE OF state ON tool_process
WHEN NOT ((OLD.state = 'LAUNCHING' AND NEW.state IN ('RUNNING', 'EXITED', 'SIGNALED',
                                                      'FAILED', 'UNKNOWN'))
          OR (OLD.state = 'RUNNING' AND NEW.state IN ('RUNNING', 'EXITED', 'SIGNALED',
                                                      'UNOBSERVABLE'))
          OR (OLD.state = NEW.state AND OLD.state IN ('EXITED', 'SIGNALED', 'UNOBSERVABLE')))
BEGIN SELECT RAISE(ABORT, 'a process''s state moves only forward'); END;
CREATE TRIGGER tool_process_ending_fixed BEFORE UPDATE OF exit_code, signal, timed_out
    ON tool_process
WHEN OLD.state IN ('EXITED', 'SIGNALED')
     AND (NEW.exit_code IS NOT OLD.exit_code OR NEW.signal IS NOT OLD.signal
          OR NEW.timed_out IS NOT OLD.timed_out)
BEGIN SELECT RAISE(ABORT, 'a process ends once'); END;
CREATE TRIGGER tool_process_no_delete BEFORE DELETE ON tool_process
BEGIN SELECT RAISE(ABORT, 'a process record is never deleted'); END;

CREATE TABLE process_idempotency (
    subject          TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    idempotency_key  TEXT    NOT NULL,
    request_digest   TEXT    NOT NULL CHECK (length(request_digest) = 64
                                             AND request_digest NOT GLOB '*[^0-9a-f]*'),
    invocation_id    TEXT    NOT NULL UNIQUE REFERENCES process_invocation(invocation_id)
                                             ON DELETE RESTRICT,
    recorded_ms      INTEGER NOT NULL,
    PRIMARY KEY (subject, session_id, idempotency_key)
) STRICT;
CREATE TRIGGER process_idempotency_no_update BEFORE UPDATE ON process_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is immutable'); END;
CREATE TRIGGER process_idempotency_no_delete BEFORE DELETE ON process_idempotency
BEGIN SELECT RAISE(ABORT, 'an idempotency record is never deleted'); END;
CREATE TRIGGER process_idempotency_one_namespace BEFORE INSERT ON process_idempotency
WHEN EXISTS (SELECT 1 FROM tool_idempotency WHERE subject = NEW.subject
             AND session_id = NEW.session_id AND idempotency_key = NEW.idempotency_key)
BEGIN SELECT RAISE(ABORT, 'an idempotency key names one invocation'); END;
CREATE TRIGGER tool_idempotency_one_namespace BEFORE INSERT ON tool_idempotency
WHEN EXISTS (SELECT 1 FROM process_idempotency WHERE subject = NEW.subject
             AND session_id = NEW.session_id AND idempotency_key = NEW.idempotency_key)
BEGIN SELECT RAISE(ABORT, 'an idempotency key names one invocation'); END;
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
    Migration {
        to: 4,
        sql: SCHEMA_V4,
    },
    Migration {
        to: 5,
        sql: SCHEMA_V5,
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
        SCHEMA_V4, SCHEMA_V5, Shape, ShapeError, decide, migrate, verify_exact,
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
        assert!(conn.execute_batch(SCHEMA_V4).is_ok());
        assert!(conn.execute_batch(SCHEMA_V5).is_ok());
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
        assert!(conn.execute_batch(SCHEMA_V4).is_ok());
        assert!(conn.execute_batch(SCHEMA_V5).is_ok());
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

    /// A store at exactly `version`, foreign keys off: the rows these tests
    /// insert name runs that do not exist. Foreign keys are the store's
    /// configuration (`db::configure` turns them on), not what they measure.
    fn store_at(version: i64) -> Connection {
        let Ok(conn) = Connection::open_in_memory() else {
            unreachable!("in-memory SQLite")
        };
        let steps: Vec<Migration> = MIGRATIONS
            .iter()
            .copied()
            .filter(|m| m.to <= version)
            .collect();
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert_eq!(migrate(&tx, 0, &steps).ok(), Some(version));
            assert!(tx.commit().is_ok());
        }
        assert!(conn.pragma_update(None, "foreign_keys", false).is_ok());
        conn
    }

    #[test]
    fn an_invocation_intent_is_fixed_and_ends_exactly_once() {
        // The version-3 rules, which the version-4 table keeps.
        let conn = store_at(3);
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

    /// A version-3 invocation: `(n, state, failure, bytes returned, ended)`.
    type V3Row<'a> = (u8, &'a str, Option<&'a str>, Option<i64>, Option<i64>);

    /// An invocation id, the `n`th.
    fn inv(n: u8) -> String {
        format!("inv_01M24BB8G3E0A851TRWE3M8FZ{}", char::from(b'A' + n))
    }

    /// Every version-4 invocation row, spelled out.
    fn v4_rows(conn: &Connection) -> Vec<String> {
        let Ok(mut statement) = conn.prepare(
            "SELECT invocation_id, tool, retry_class, object_state, state, failure, completion, \
             content_bytes, ended_ms FROM tool_invocation ORDER BY invocation_id",
        ) else {
            unreachable!("the version-4 table")
        };
        let Ok(rows) = statement
            .query_map([], |row| {
                let text = |i| row.get::<_, String>(i);
                Ok(format!(
                    "{} {} {} {} {} {:?} {:?} {:?} {:?}",
                    text(0)?,
                    text(1)?,
                    text(2)?,
                    text(3)?,
                    text(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })
            .and_then(Iterator::collect::<rusqlite::Result<Vec<String>>>)
        else {
            unreachable!("the rows read back")
        };
        rows
    }

    #[test]
    fn a_version_three_store_migrates_with_every_invocation_it_holds() {
        let conn = store_at(3);
        let rows: [V3Row<'_>; 4] = [
            (0, "INTENT", None, None, None),
            (1, "COMPLETED", None, Some(3), Some(1)),
            (2, "FAILED", Some("OBJECT_CHANGED"), None, Some(1)),
            (3, "INTERRUPTED", None, None, Some(2)),
        ];
        for (n, state, failure, bytes, ended) in rows {
            let inserted = conn.execute(
                "INSERT INTO tool_invocation (invocation_id, run_id, tool, canonical_path, \
                 byte_count, object_device, object_inode, incarnation, state, failure, \
                 bytes_returned, intent_ms, ended_ms) VALUES (?1, 'run_x', 'fs.read', \
                 '/workspace/a', 4, '2049', '12', 1, ?2, ?3, ?4, 0, ?5)",
                rusqlite::params![inv(n), state, failure, bytes, ended],
            );
            assert!(inserted.is_ok(), "{n}");
        }
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            let four: Vec<Migration> = MIGRATIONS.iter().copied().filter(|m| m.to <= 4).collect();
            assert_eq!(migrate(&tx, 3, &four).ok(), Some(4));
            assert!(tx.commit().is_ok());
        }
        let head = |n: u8| format!("{} fs.read RETRY_SAFE EXISTING", inv(n));
        assert_eq!(
            v4_rows(&conn),
            [
                format!("{} INTENT None None None None", head(0)),
                format!("{} COMPLETED None Some(\"READ\") Some(3) Some(1)", head(1)),
                format!(
                    "{} FAILED Some(\"OBJECT_CHANGED\") None None Some(1)",
                    head(2)
                ),
                format!("{} INTERRUPTED None None None Some(2)", head(3)),
            ]
        );
        // The old table, its index and its triggers are gone, and the new
        // triggers hold.
        let old: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE sql LIKE '%tool_invocation_v3%'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(old, 0);
        let end = |state: &str| {
            conn.execute(
                "UPDATE tool_invocation SET state = ?2, ended_ms = 3 WHERE invocation_id = ?1",
                [inv(0), state.to_owned()],
            )
        };
        assert!(end("UNKNOWN").is_err(), "a read is never UNKNOWN");
        assert!(end("INTERRUPTED").is_ok());
        assert!(conn.execute("DELETE FROM tool_invocation", []).is_err());
    }

    /// Insert an open version-4 invocation.
    fn v4_insert(
        conn: &Connection,
        n: u8,
        (tool, class, object): (&str, &str, &str),
        destination: Option<&str>,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO tool_invocation (invocation_id, run_id, tool, retry_class, \
             canonical_path, object_state, object_device, object_inode, destination_path, \
             destination_device, destination_inode, byte_count, incarnation, state, failure, \
             completion, content_bytes, intent_ms, ended_ms) VALUES (?1, 'run_x', ?2, ?3, \
             '/workspace/a', ?4, '2049', '12', ?5, ?6, ?6, 4, 1, 'INTENT', NULL, NULL, NULL, \
             0, NULL)",
            rusqlite::params![
                inv(n),
                tool,
                class,
                object,
                destination,
                destination.map(|_| "7")
            ],
        )
    }

    /// A version-4 store holding an open write (vacant), move, delete and
    /// patch: invocations 0 to 3.
    fn v4_with_four() -> Connection {
        let conn = store_at(4);
        let dest = Some("/workspace/b");
        for (n, row, destination) in [
            (0, ("fs.write", "RETRY_SAFE", "VACANT"), None),
            (1, ("fs.move", "NON_RETRYABLE", "EXISTING"), dest),
            (2, ("fs.delete", "NON_RETRYABLE", "EXISTING"), None),
            (3, ("fs.patch", "RETRY_SAFE", "EXISTING"), None),
        ] {
            assert!(v4_insert(&conn, n, row, destination).is_ok(), "{n}");
        }
        conn
    }

    #[test]
    fn the_retry_class_and_the_target_are_bound_to_the_tool() {
        let conn = v4_with_four();
        let dest = Some("/workspace/b");
        for (n, row, destination, why) in [
            (
                4,
                ("fs.move", "RETRY_SAFE", "EXISTING"),
                dest,
                "a move is never retry-safe",
            ),
            (
                5,
                ("fs.delete", "RETRY_SAFE", "EXISTING"),
                None,
                "a delete is never retry-safe",
            ),
            (
                6,
                ("fs.write", "NON_RETRYABLE", "EXISTING"),
                None,
                "a write is retry-safe",
            ),
            (
                7,
                ("fs.delete", "NON_RETRYABLE", "VACANT"),
                None,
                "only a write creates",
            ),
            (
                8,
                ("fs.move", "NON_RETRYABLE", "EXISTING"),
                None,
                "a move has a destination",
            ),
            (
                9,
                ("fs.write", "RETRY_SAFE", "EXISTING"),
                dest,
                "only a move has one",
            ),
            (
                10,
                ("fs.move", "NON_RETRYABLE", "EXISTING"),
                Some("/workspace"),
                "never the root",
            ),
            (
                11,
                ("fs.mkdir", "RETRY_SAFE", "EXISTING"),
                None,
                "no such tool",
            ),
        ] {
            assert!(v4_insert(&conn, n, row, destination).is_err(), "{why}");
        }
    }

    #[test]
    fn an_ending_is_bound_to_the_tool_and_written_once() {
        let conn = v4_with_four();
        // `(state, failure, completion, content_bytes)`, all bound: the SQL is
        // static (TX006).
        let end = |n: u8,
                   (state, failure, completion, bytes): (
            &str,
            Option<&str>,
            Option<&str>,
            Option<i64>,
        )| {
            conn.execute(
                "UPDATE tool_invocation SET state = ?2, failure = ?3, completion = ?4,                  content_bytes = ?5, ended_ms = 1 WHERE invocation_id = ?1",
                rusqlite::params![inv(n), state, failure, completion, bytes],
            )
        };
        let completed = |class, bytes| ("COMPLETED", None, Some(class), Some(bytes));
        let failed = |why| ("FAILED", Some(why), None, None);
        assert!(
            end(3, ("INTERRUPTED", None, None, None)).is_err(),
            "a patch has an effect"
        );
        assert!(
            end(3, completed("MOVED", 4)).is_err(),
            "not a patch's completion"
        );
        assert!(end(3, completed("APPLIED", 5)).is_err(), "over the bound");
        assert!(end(3, completed("ALREADY_APPLIED", 0)).is_ok());
        assert!(end(1, ("UNKNOWN", None, None, None)).is_ok());
        assert!(
            end(1, completed("MOVED", 0)).is_err(),
            "an unknown outcome is never rewritten"
        );
        assert!(end(2, failed("DIRECTORY_NOT_EMPTY")).is_ok());
        assert!(
            end(0, failed("OUTCOME_UNKNOWN")).is_err(),
            "unknown is a state, not a failure"
        );
    }

    #[test]
    fn a_tool_key_names_one_invocation_for_ever() {
        let conn = v4_with_four();
        let key = |key: &str, n: u8| {
            conn.execute(
                "INSERT INTO tool_idempotency (subject, session_id, idempotency_key, \
                 request_digest, invocation_id, recorded_ms) VALUES ('uid:1000', 'ses_x', ?1, \
                 ?2, ?3, 0)",
                rusqlite::params![key, "ab".repeat(32), inv(n)],
            )
        };
        assert!(key("k1", 0).is_ok());
        assert!(key("k1", 1).is_err(), "a key names one invocation");
        assert!(key("k2", 0).is_err(), "an invocation has one key");
        assert!(
            conn.execute("UPDATE tool_idempotency SET idempotency_key = 'k3'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM tool_idempotency", []).is_err());
    }

    /// A version-5 store holding one launch intent — `process.exec`,
    /// invocation 0, process `prc(0)` — and its `LAUNCHING` process row.
    fn prc(n: u8) -> String {
        format!("prc_01M24BB8G3E0A851TRWE3M8FZ{}", char::from(b'A' + n))
    }

    fn process_intent(
        conn: &Connection,
        n: u8,
        (tool, class, process): (&str, &str, &str),
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO process_invocation (invocation_id, run_id, tool, retry_class, \
             process_id, incarnation, state, failure, completion, output_bytes, intent_ms, \
             ended_ms) VALUES (?1, 'run_x', ?2, ?3, ?4, 1, 'INTENT', NULL, NULL, NULL, 0, NULL)",
            rusqlite::params![inv(n), tool, class, process],
        )
    }

    fn process_row(conn: &Connection, n: u8, run: &str, state: &str) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO tool_process (process_id, launch_invocation_id, run_id, \
             executable_path, executable_sha256, executable_device, executable_inode, cwd_path, \
             arg_count, argv_sha256, argv_safety, environment, stream_limit, broker_generation, \
             state, exit_code, signal, timed_out, created_ms, updated_ms) VALUES (?1, ?2, ?3, \
             '/usr/bin/git', ?4, '2049', '77', '/workspace', 1, ?4, 'SAFE', 'BASE', 131072, NULL, \
             ?5, NULL, NULL, 0, 0, 0)",
            rusqlite::params![prc(n), inv(n), run, "ab".repeat(32), state],
        )
    }

    fn v5_with_a_launch() -> Connection {
        let conn = store_at(5);
        assert!(process_intent(&conn, 0, ("process.exec", "NON_RETRYABLE", &prc(0))).is_ok());
        assert!(process_row(&conn, 0, "run_x", "LAUNCHING").is_ok());
        conn
    }

    #[test]
    fn a_version_four_store_migrates_to_five_and_keeps_its_filesystem_ledger() {
        let conn = v4_with_four();
        let before = v4_rows(&conn);
        {
            let Ok(tx) = conn.unchecked_transaction() else {
                unreachable!("a transaction")
            };
            assert_eq!(migrate(&tx, 4, MIGRATIONS).ok(), Some(5));
            assert!(tx.commit().is_ok());
        }
        assert_eq!(verify_exact(&conn).ok(), Some(Ok(())), "exactly version 5");
        assert_eq!(v4_rows(&conn), before, "the filesystem ledger is untouched");
    }

    #[test]
    fn a_process_intent_binds_its_class_its_process_and_its_run() {
        let conn = v5_with_a_launch();
        for (n, row, why) in [
            (
                1,
                ("process.exec", "RETRY_SAFE", prc(1)),
                "a launch is never retry-safe",
            ),
            (
                2,
                ("process.kill", "RETRY_SAFE", prc(0)),
                "a kill is never retry-safe",
            ),
            (
                3,
                ("process.status", "NON_RETRYABLE", prc(0)),
                "a status is retry-safe",
            ),
            (
                4,
                ("process.spawn", "NON_RETRYABLE", prc(4)),
                "no such tool",
            ),
            (
                5,
                ("process.exec", "NON_RETRYABLE", prc(0)),
                "a launch names a new process",
            ),
            (
                6,
                ("process.status", "RETRY_SAFE", prc(6)),
                "a status names a known process",
            ),
            (
                7,
                ("process.kill", "NON_RETRYABLE", "pid_1234".to_owned()),
                "a handle, never a pid",
            ),
        ] {
            assert!(
                process_intent(&conn, n, (row.0, row.1, &row.2)).is_err(),
                "{why}"
            );
        }
        assert!(process_intent(&conn, 8, ("process.status", "RETRY_SAFE", &prc(0))).is_ok());
        assert!(process_intent(&conn, 9, ("process.kill", "NON_RETRYABLE", &prc(0))).is_ok());
        // Another run's process is not this run's to observe.
        let other = conn.execute(
            "INSERT INTO process_invocation (invocation_id, run_id, tool, retry_class, \
             process_id, incarnation, state, intent_ms) VALUES (?1, 'run_y', 'process.status', \
             'RETRY_SAFE', ?2, 1, 'INTENT', 0)",
            rusqlite::params![inv(10), prc(0)],
        );
        assert!(other.is_err(), "a status names a process of its own run");
    }

    #[test]
    fn a_process_is_recorded_by_its_own_launch_and_moves_only_forward() {
        let conn = v5_with_a_launch();
        assert!(
            process_row(&conn, 0, "run_x", "LAUNCHING").is_err(),
            "one process per launch"
        );
        assert!(process_intent(&conn, 1, ("process.status", "RETRY_SAFE", &prc(0))).is_ok());
        assert!(
            process_row(&conn, 1, "run_x", "LAUNCHING").is_err(),
            "a status intent records no process"
        );
        let update = |sql: &str| conn.execute(sql, []);
        assert!(update("UPDATE tool_process SET executable_sha256 = '00'").is_err());
        assert!(update("UPDATE tool_process SET argv_sha256 = argv_sha256").is_err());
        assert!(
            update("UPDATE tool_process SET state = 'RUNNING'").is_err(),
            "a running process has a generation"
        );
        let generation = "0123456789abcdef0123456789abcdef";
        assert!(
            conn.execute(
                "UPDATE tool_process SET state = 'RUNNING', broker_generation = ?1",
                [generation],
            )
            .is_ok()
        );
        assert!(
            update(
                "UPDATE tool_process SET broker_generation = 'ffffffffffffffffffffffffffffffff'"
            )
            .is_err(),
            "the generation is written once"
        );
        assert!(
            update("UPDATE tool_process SET state = 'LAUNCHING', broker_generation = NULL")
                .is_err()
        );
        assert!(update("UPDATE tool_process SET state = 'EXITED', exit_code = 3").is_ok());
        assert!(
            update("UPDATE tool_process SET exit_code = 4").is_err(),
            "it ends once"
        );
        assert!(update("UPDATE tool_process SET state = 'RUNNING', exit_code = NULL").is_err());
        assert!(update("DELETE FROM tool_process").is_err());
    }

    #[test]
    fn a_process_ending_is_bound_to_its_tool_and_written_once() {
        let conn = v5_with_a_launch();
        assert!(process_intent(&conn, 1, ("process.status", "RETRY_SAFE", &prc(0))).is_ok());
        let end = |n: u8,
                   (state, failure, completion, bytes): (
            &str,
            Option<&str>,
            Option<&str>,
            Option<i64>,
        )| {
            conn.execute(
                "UPDATE process_invocation SET state = ?2, failure = ?3, completion = ?4, \
                 output_bytes = ?5, ended_ms = 1 WHERE invocation_id = ?1",
                rusqlite::params![inv(n), state, failure, completion, bytes],
            )
        };
        assert!(
            end(0, ("INTERRUPTED", None, None, None)).is_err(),
            "a launch has an effect"
        );
        assert!(
            end(1, ("UNKNOWN", None, None, None)).is_err(),
            "a status has none"
        );
        assert!(end(0, ("COMPLETED", None, Some("OBSERVED"), Some(0))).is_err());
        assert!(
            end(0, ("COMPLETED", None, Some("LAUNCHED"), Some(7))).is_err(),
            "no output"
        );
        assert!(end(1, ("COMPLETED", None, Some("OBSERVED"), Some(262_145))).is_err());
        assert!(end(1, ("COMPLETED", None, Some("OBSERVED"), Some(262_144))).is_ok());
        assert!(end(0, ("FAILED", Some("EXEC_FAILED"), None, None)).is_ok());
        assert!(
            end(0, ("UNKNOWN", None, None, None)).is_err(),
            "an ending is never rewritten"
        );
        assert!(conn.execute("DELETE FROM process_invocation", []).is_err());
    }

    #[test]
    fn an_idempotency_key_is_one_namespace_across_both_ledgers() {
        let conn = v5_with_a_launch();
        assert!(v4_insert(&conn, 5, ("fs.delete", "NON_RETRYABLE", "EXISTING"), None).is_ok());
        let bind = |table: &str, key: &str, n: u8| {
            let sql = match table {
                "tool" => {
                    "INSERT INTO tool_idempotency (subject, session_id, idempotency_key, \
                     request_digest, invocation_id, recorded_ms) VALUES ('uid:1000', 'ses_x', \
                     ?1, ?2, ?3, 0)"
                }
                _ => {
                    "INSERT INTO process_idempotency (subject, session_id, idempotency_key, \
                     request_digest, invocation_id, recorded_ms) VALUES ('uid:1000', 'ses_x', \
                     ?1, ?2, ?3, 0)"
                }
            };
            conn.execute(sql, rusqlite::params![key, "ab".repeat(32), inv(n)])
        };
        assert!(bind("process", "k1", 0).is_ok());
        assert!(
            bind("tool", "k1", 5).is_err(),
            "a process key is not free for a file"
        );
        assert!(bind("tool", "k2", 5).is_ok());
        assert!(bind("process", "k2", 0).is_err(), "and the reverse");
        assert!(
            conn.execute("UPDATE process_idempotency SET idempotency_key = 'k9'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM process_idempotency", []).is_err());
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
