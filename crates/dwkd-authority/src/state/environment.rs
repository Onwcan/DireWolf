//! Execution environments' durable lifecycle (M5a, ADR-0047 §§11–13): the
//! intent before the effect, exactly one outcome, and reconciliation by label.
//!
//! # The order
//!
//! | step | where | a container may exist? |
//! |---|---|---|
//! | 1. the run is active, has a pinned workspace, and no live environment | transaction | no |
//! | 2. the environment's id and whole specification, `PREPARING`, audited | commit | no |
//! | 3. the runtime client resolved and hashed; the workspace re-pinned | no transaction | no |
//! | 4. the broker prepares, measures, keeps it only if clean | the broker | yes |
//! | 5. the authority judges the measurement; `READY`, `REFUSED` or `UNKNOWN` | transaction | recorded |
//!
//! Destruction is the same shape: `DESTROYING` durable first, then the
//! broker, then `DESTROYED` — and a destruction whose answer is lost stays
//! `DESTROYING`, because removing a container by its labels is safe to
//! repeat.
//!
//! # Crash windows (ADR-0047 §12)
//!
//! | window | durable state | on restart | semantics |
//! |---|---|---|---|
//! | W1 before the intent commits | nothing | nothing | RETRY-SAFE |
//! | W2 intent durable, nothing sent | `PREPARING` | `UNKNOWN`; reconciliation finds no label: `LOST` | NON-RETRYABLE for that id; a new environment may be prepared |
//! | W3 the broker mid-preparation | `PREPARING` | `UNKNOWN`; a labelled container is reaped: `DESTROYED` | UNKNOWN |
//! | W4 answered, outcome not durable | `PREPARING` | as W3 | UNKNOWN |
//! | W5 outcome durable | `READY` / `REFUSED` | `READY` is measured again: clean stays, drift is destroyed | — |
//! | W6 destruction intent durable, nothing sent | `DESTROYING` | removed by label, or found gone: `DESTROYED` | RETRY-SAFE |
//! | W7 the broker removed it, answer lost | `DESTROYING` | found gone: `DESTROYED` | RETRY-SAFE |
//!
//! An environment id is never prepared twice: a `PREPARING` row a previous
//! incarnation left becomes `UNKNOWN` at start ([`reconcile_open`]), and
//! only reconciliation — which removes by label, exactly — ends it.

use dwk_proto::brokerp::OwnedEnvironment;
use dwk_proto::brokerp::sandbox::{AssuranceLevel, ContainerRef, NetworkTopology};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
use rusqlite::OptionalExtension as _;

use crate::sandbox::{EnvironmentKind, Judgement, SandboxConfig};

use super::Work;
use super::audit::{AuditEvent, Field, Fields};
use super::config::RootBinding;
use super::error::AuthorityError;
use super::resolution::{self, ResolutionRefused};

/// Where an environment is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentState {
    /// The intent is durable; the broker may be preparing it.
    Preparing,
    /// Prepared and measured clean.
    Ready,
    /// Refused; provably none of it remains. Final.
    Refused,
    /// Its destruction is durable and pending.
    Destroying,
    /// Gone. Final.
    Destroyed,
    /// Found gone by reconciliation, not by the authority's hand. Final.
    Lost,
    /// It may exist and nothing proves whether.
    Unknown,
}

impl EnvironmentState {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "PREPARING",
            Self::Ready => "READY",
            Self::Refused => "REFUSED",
            Self::Destroying => "DESTROYING",
            Self::Destroyed => "DESTROYED",
            Self::Lost => "LOST",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// The state a stored spelling names.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "PREPARING" => Self::Preparing,
            "READY" => Self::Ready,
            "REFUSED" => Self::Refused,
            "DESTROYING" => Self::Destroying,
            "DESTROYED" => Self::Destroyed,
            "LOST" => Self::Lost,
            "UNKNOWN" => Self::Unknown,
            _ => return None,
        })
    }

    /// Whether nothing more happens to it.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Refused | Self::Destroyed | Self::Lost)
    }
}

/// A preparation both checks allowed, whose intent is durable.
#[derive(Debug, Clone)]
pub(super) struct Intent {
    pub(super) environment: EnvironmentId,
    pub(super) invocation: InvocationId,
    pub(super) binding: RootBinding,
}

/// What starting a preparation decided.
#[derive(Debug)]
pub(super) enum Begun {
    /// Nothing was recorded: why.
    Refused(&'static str),
    /// The intent is durable.
    Intent(Box<Intent>),
}

const fn resolution_class(refused: &ResolutionRefused) -> &'static str {
    match refused {
        ResolutionRefused::UnknownRun => "UNKNOWN_RUN",
        ResolutionRefused::RunNotActive => "RUN_NOT_ACTIVE",
        ResolutionRefused::NoWorkspace => "NO_WORKSPACE",
        ResolutionRefused::NoWorkspaceRoot => "NO_WORKSPACE_ROOT",
        ResolutionRefused::Root(_)
        | ResolutionRefused::Resolve(_)
        | ResolutionRefused::Authority(_) => "WORKSPACE_UNAVAILABLE",
    }
}

fn level(level: AssuranceLevel) -> &'static str {
    level.as_str()
}

/// Steps 1–2: check, then record the intent.
pub(super) fn begin_prepare(
    work: &mut Work<'_>,
    run: &RunId,
    config: &SandboxConfig,
) -> Result<Begun, AuthorityError> {
    let binding = match resolution::run_root(work, run.as_str())? {
        Ok(binding) => binding,
        Err(refused) => return Ok(Begun::Refused(resolution_class(&refused))),
    };
    let live: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT environment_id FROM environment WHERE run_id = ?1 \
             AND state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN')",
            [run.as_str()],
            |row| row.get(0),
        )
        .optional())?;
    if live.is_some() {
        return Ok(Begun::Refused("ENVIRONMENT_EXISTS"));
    }
    let environment = work.environment_id()?;
    let invocation = work.invocation_id()?;
    let kind = EnvironmentKind::Oci;
    let incarnation = i64::try_from(work.incarnation())
        .map_err(|_| AuthorityError::Invariant("the incarnation does not fit"))?;
    let now =
        i64::try_from(work.now).map_err(|_| AuthorityError::Invariant("the clock does not fit"))?;
    work.db(work.tx.execute(
        "INSERT INTO environment (environment_id, run_id, profile, network, image, \
         probe_sha256, declared, measured, effective, container, state, failure, incarnation, \
         intent_ms, ended_ms) \
         VALUES (?1, ?2, 'OCI_STRICT', ?3, ?4, ?5, ?6, NULL, NULL, NULL, 'PREPARING', \
         NULL, ?7, ?8, NULL)",
        rusqlite::params![
            environment.as_str(),
            run.as_str(),
            config.topology().as_str(),
            config.image().as_str(),
            config.probe_sha256().as_str(),
            level(kind.declared().0),
            incarnation,
            now,
        ],
    ))?;
    work.audit(
        AuditEvent::EnvironmentIntentRecorded,
        Fields::new()
            .text("environment_id", environment.as_str())
            .text("run_id", run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("kind", "oci")
            .text("profile", "oci-strict")
            .text("network", config.topology().as_str())
            .text("image", config.image().as_str())
            .text("probe_sha256", config.probe_sha256().as_str())
            .text("declared", level(kind.declared().0)),
    )?;
    Ok(Begun::Intent(Box::new(Intent {
        environment,
        invocation,
        binding,
    })))
}

/// How a preparation ended, before it is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Prepared {
    /// Measured clean, and kept.
    Ready {
        container: ContainerRef,
        judgement: Judgement,
    },
    /// Provably none of it remains.
    Refused {
        reason: &'static str,
        judgement: Option<Judgement>,
    },
    /// It may exist.
    Unknown {
        container: Option<ContainerRef>,
        reason: &'static str,
    },
    /// Kept by the broker, but not usable here: it is destroyed next.
    Unusable {
        container: ContainerRef,
        reason: &'static str,
        judgement: Judgement,
    },
}

fn invariants(list: &[dwk_proto::brokerp::sandbox::SandboxInvariant]) -> Vec<Field> {
    list.iter()
        .map(|i| Field::Text(i.as_str().to_owned()))
        .collect()
}

fn judged(fields: Fields, judgement: &Judgement) -> Fields {
    fields
        .text("declared", level(judgement.declared.0))
        .text("measured", level(judgement.measured.0))
        .text("effective", level(judgement.effective.0))
        .list("failed", invariants(&judgement.failed))
        .list("unobservable", invariants(&judgement.unobservable))
}

/// Step 5: record how the preparation ended.
pub(super) fn record_prepared(
    work: &mut Work<'_>,
    environment: &EnvironmentId,
    run: &RunId,
    prepared: &Prepared,
    timing: Fields,
) -> Result<(), AuthorityError> {
    let now =
        i64::try_from(work.now).map_err(|_| AuthorityError::Invariant("the clock does not fit"))?;
    let base = Fields::new()
        .text("environment_id", environment.as_str())
        .text("run_id", run.as_str());
    let changed = match prepared {
        Prepared::Ready {
            container,
            judgement,
        } => {
            let changed = work.db(work.tx.execute(
                "UPDATE environment SET state = 'READY', container = ?2, measured = ?3, \
                 effective = ?4 WHERE environment_id = ?1 AND state = 'PREPARING'",
                rusqlite::params![
                    environment.as_str(),
                    container.as_str(),
                    level(judgement.measured.0),
                    level(judgement.effective.0)
                ],
            ))?;
            let mut fields = judged(base.text("container", container.as_str()), judgement);
            fields.extend(timing);
            work.audit(AuditEvent::EnvironmentReady, fields)?;
            changed
        }
        Prepared::Refused { reason, judgement } => {
            let changed = work.db(work.tx.execute(
                "UPDATE environment SET state = 'REFUSED', failure = ?2, measured = ?3, \
                 effective = ?4, ended_ms = ?5 WHERE environment_id = ?1 AND state = 'PREPARING'",
                rusqlite::params![
                    environment.as_str(),
                    reason,
                    judgement.as_ref().map(|j| level(j.measured.0)),
                    judgement.as_ref().map(|j| level(j.effective.0)),
                    now
                ],
            ))?;
            let mut fields = base.text("reason", *reason);
            if let Some(judgement) = judgement {
                fields = judged(fields, judgement);
            }
            fields.extend(timing);
            work.audit(AuditEvent::EnvironmentRefused, fields)?;
            changed
        }
        Prepared::Unknown { container, reason } => {
            let changed = work.db(work.tx.execute(
                "UPDATE environment SET state = 'UNKNOWN', container = ?2, failure = ?3 \
                 WHERE environment_id = ?1 AND state = 'PREPARING'",
                rusqlite::params![
                    environment.as_str(),
                    container.as_ref().map(ContainerRef::as_str),
                    reason
                ],
            ))?;
            work.audit(
                AuditEvent::EnvironmentOutcomeUnknown,
                base.text("reason", *reason),
            )?;
            changed
        }
        Prepared::Unusable {
            container,
            reason,
            judgement,
        } => {
            let changed = work.db(work.tx.execute(
                "UPDATE environment SET state = 'DESTROYING', container = ?2, failure = ?3, \
                 measured = ?4, effective = ?5 WHERE environment_id = ?1 AND state = 'PREPARING'",
                rusqlite::params![
                    environment.as_str(),
                    container.as_str(),
                    reason,
                    level(judgement.measured.0),
                    level(judgement.effective.0)
                ],
            ))?;
            let fields = judged(
                base.text("container", container.as_str())
                    .text("reason", *reason),
                judgement,
            );
            work.audit(AuditEvent::EnvironmentRefused, fields)?;
            changed
        }
    };
    if changed != 1 {
        return Err(AuthorityError::Invariant(
            "a preparation's outcome found no preparing record",
        ));
    }
    Ok(())
}

/// One environment record, as reconciliation and destruction read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRecord {
    /// The environment.
    pub environment: EnvironmentId,
    /// Its run.
    pub run: RunId,
    /// Where it is.
    pub state: EnvironmentState,
    /// Its container, once known.
    pub container: Option<ContainerRef>,
    /// Its topology.
    pub network: NetworkTopology,
    /// The incarnation that recorded its intent.
    pub incarnation: u64,
    /// Its failure class, if it has one.
    pub failure: Option<String>,
}

type RecordRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    Option<String>,
);

fn record_of(row: RecordRow) -> Result<EnvironmentRecord, AuthorityError> {
    let malformed = || AuthorityError::Invariant("a stored environment is malformed");
    let (environment, run, state, container, network, incarnation, failure) = row;
    Ok(EnvironmentRecord {
        environment: EnvironmentId::parse(&environment).ok_or_else(malformed)?,
        run: RunId::parse(&run).ok_or_else(malformed)?,
        state: EnvironmentState::parse(&state).ok_or_else(malformed)?,
        container: match container {
            Some(c) => Some(ContainerRef::new(c).ok_or_else(malformed)?),
            None => None,
        },
        network: NetworkTopology::ALL
            .iter()
            .copied()
            .find(|n| n.as_str() == network)
            .ok_or_else(malformed)?,
        incarnation: u64::try_from(incarnation).map_err(|_| malformed())?,
        failure,
    })
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

/// One environment's record.
pub(super) fn record(
    work: &Work<'_>,
    environment: &EnvironmentId,
) -> Result<Option<EnvironmentRecord>, AuthorityError> {
    let row: Option<RecordRow> = work.db(work
        .tx
        .query_row(
            "SELECT environment_id, run_id, state, container, network, incarnation, failure \
             FROM environment WHERE environment_id = ?1",
            [environment.as_str()],
            read_row,
        )
        .optional())?;
    row.map(record_of).transpose()
}

/// Every record that is not final.
pub(super) fn live(work: &Work<'_>) -> Result<Vec<EnvironmentRecord>, AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "SELECT environment_id, run_id, state, container, network, incarnation, failure \
         FROM environment WHERE state IN ('PREPARING', 'READY', 'DESTROYING', 'UNKNOWN') \
         ORDER BY environment_id",
    ))?;
    let rows = work.db(statement.query_map([], read_row))?;
    let mut found = Vec::new();
    for row in rows {
        found.push(record_of(work.db(row)?)?);
    }
    Ok(found)
}

/// What starting a destruction decided.
#[derive(Debug)]
pub(super) enum DestroyBegun {
    /// Nothing to destroy: why.
    Refused(&'static str),
    /// The destruction is durable and pending.
    Pending {
        record: EnvironmentRecord,
        invocation: InvocationId,
    },
}

/// Record that `environment` is to be destroyed, for `reason`.
pub(super) fn begin_destroy(
    work: &mut Work<'_>,
    environment: &EnvironmentId,
    reason: &'static str,
) -> Result<DestroyBegun, AuthorityError> {
    let Some(record) = record(work, environment)? else {
        return Ok(DestroyBegun::Refused("UNKNOWN_ENVIRONMENT"));
    };
    match record.state {
        EnvironmentState::Refused | EnvironmentState::Destroyed | EnvironmentState::Lost => {
            return Ok(DestroyBegun::Refused("ENVIRONMENT_ENDED"));
        }
        // A preparation in flight is not destroyed under it: reconciliation
        // decides once it has ended.
        EnvironmentState::Preparing => return Ok(DestroyBegun::Refused("ENVIRONMENT_PREPARING")),
        EnvironmentState::Ready | EnvironmentState::Unknown | EnvironmentState::Destroying => {}
    }
    let invocation = work.invocation_id()?;
    work.db(work.tx.execute(
        "UPDATE environment SET state = 'DESTROYING', failure = COALESCE(failure, ?2) \
         WHERE environment_id = ?1",
        rusqlite::params![environment.as_str(), reason],
    ))?;
    work.audit(
        AuditEvent::EnvironmentDestroyIntent,
        Fields::new()
            .text("environment_id", environment.as_str())
            .text("run_id", record.run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("reason", reason)
            .text("from", record.state.as_str()),
    )?;
    Ok(DestroyBegun::Pending { record, invocation })
}

/// How a destruction ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DestroyEnding {
    /// It is gone: removed now, or already.
    Gone {
        container: Option<ContainerRef>,
        already: bool,
    },
    /// It could not be completed, and stays pending.
    Pending { reason: &'static str },
}

/// Record how a destruction ended.
pub(super) fn record_destroyed(
    work: &mut Work<'_>,
    record: &EnvironmentRecord,
    ending: &DestroyEnding,
    timing: Fields,
) -> Result<(), AuthorityError> {
    let now =
        i64::try_from(work.now).map_err(|_| AuthorityError::Invariant("the clock does not fit"))?;
    let base = Fields::new()
        .text("environment_id", record.environment.as_str())
        .text("run_id", record.run.as_str());
    match ending {
        DestroyEnding::Gone { container, already } => {
            let container = container.as_ref().or(record.container.as_ref());
            work.db(work.tx.execute(
                "UPDATE environment SET state = 'DESTROYED', container = COALESCE(container, ?2), \
                 ended_ms = ?3 WHERE environment_id = ?1 AND state = 'DESTROYING'",
                rusqlite::params![
                    record.environment.as_str(),
                    container.map(ContainerRef::as_str),
                    now
                ],
            ))?;
            let mut fields = base.flag("already_gone", *already);
            if let Some(container) = container {
                fields = fields.text("container", container.as_str());
            }
            fields.extend(timing);
            work.audit(AuditEvent::EnvironmentDestroyed, fields)
        }
        DestroyEnding::Pending { reason } => work.audit(
            AuditEvent::EnvironmentDestroyFailed,
            base.text("reason", *reason),
        ),
    }
}

/// Record a measurement of a `READY` environment that is still clean.
pub(super) fn record_measured(
    work: &mut Work<'_>,
    record: &EnvironmentRecord,
    judgement: &Judgement,
    timing: Fields,
) -> Result<(), AuthorityError> {
    let mut fields = judged(
        Fields::new()
            .text("environment_id", record.environment.as_str())
            .text("run_id", record.run.as_str()),
        judgement,
    );
    fields.extend(timing);
    work.audit(AuditEvent::EnvironmentMeasured, fields)
}

/// Record that a `READY` environment no longer measures clean.
pub(super) fn record_drifted(
    work: &mut Work<'_>,
    record: &EnvironmentRecord,
    reason: &'static str,
    judgement: Option<&Judgement>,
) -> Result<(), AuthorityError> {
    let mut fields = Fields::new()
        .text("environment_id", record.environment.as_str())
        .text("run_id", record.run.as_str())
        .text("reason", reason);
    if let Some(judgement) = judgement {
        fields = judged(fields, judgement);
    }
    work.audit(AuditEvent::EnvironmentDrifted, fields)
}

/// Record that reconciliation found a recorded environment gone.
pub(super) fn record_lost(
    work: &mut Work<'_>,
    record: &EnvironmentRecord,
) -> Result<(), AuthorityError> {
    let now =
        i64::try_from(work.now).map_err(|_| AuthorityError::Invariant("the clock does not fit"))?;
    // A pending destruction that finds nothing has finished.
    let (state, event) = if record.state == EnvironmentState::Destroying {
        ("DESTROYED", AuditEvent::EnvironmentDestroyed)
    } else {
        ("LOST", AuditEvent::EnvironmentLost)
    };
    work.db(work.tx.execute(
        "UPDATE environment SET state = ?2, failure = COALESCE(failure, 'MISSING'), \
         ended_ms = ?3 WHERE environment_id = ?1",
        rusqlite::params![record.environment.as_str(), state, now],
    ))?;
    work.audit(
        event,
        Fields::new()
            .text("environment_id", record.environment.as_str())
            .text("run_id", record.run.as_str())
            .text("was", record.state.as_str())
            .text("class", "MISSING"),
    )
}

/// A `PREPARING` record a previous incarnation left: it may exist.
/// `UNKNOWN`, audited, and never prepared again.
///
/// Called only while a new incarnation begins, before it has prepared
/// anything: every `PREPARING` row is a previous incarnation's. (The
/// incarnation counter is not consulted: the new one is stored only after
/// this transaction commits.)
pub(super) fn reconcile_open(work: &mut Work<'_>) -> Result<u64, AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "UPDATE environment SET state = 'UNKNOWN', failure = 'INTERRUPTED' \
         WHERE state = 'PREPARING' RETURNING environment_id, run_id",
    ))?;
    let rows = work.db(statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }))?;
    let mut found = Vec::new();
    for row in rows {
        found.push(work.db(row)?);
    }
    drop(statement);
    for (environment, run) in &found {
        work.audit(
            AuditEvent::EnvironmentOutcomeUnknown,
            Fields::new()
                .text("environment_id", environment.as_str())
                .text("run_id", run.as_str())
                .text("reason", "INTERRUPTED"),
        )?;
    }
    Ok(u64::try_from(found.len()).unwrap_or(u64::MAX))
}

/// What reconciliation found for one container or one record (ADR-0047
/// §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileClass {
    /// A `READY` record's container, running: measured again.
    StillRunning(EnvironmentRecord),
    /// A live record's container exists and is not running: destroyed.
    Stopped(EnvironmentRecord),
    /// A live record with no container: `LOST` (or, if it was being
    /// destroyed, `DESTROYED`).
    Missing(EnvironmentRecord),
    /// A record the runtime still has, which only a destruction ends
    /// (`UNKNOWN`, `DESTROYING`): destroyed.
    Pending(EnvironmentRecord),
    /// More than one container claims one environment, or a container claims
    /// a `READY` environment that recorded another: untouched.
    Ambiguous(EnvironmentId),
    /// Not this store's to touch: labels that are not exactly this store's,
    /// an environment id this store never recorded — every environment it
    /// makes is recorded before the runtime is told, so a label naming an
    /// unrecorded one was copied — or a run label that is not the recorded
    /// run's. Untouched.
    Foreign(ContainerRef),
    /// Exactly labelled as an environment this store recorded and ended
    /// (`REFUSED`, `DESTROYED`, `LOST`), whose container nonetheless exists:
    /// removed, exactly.
    Orphan(OwnedEnvironment),
}

/// Compare the records with the runtime's listing. Pure: the caller acts.
///
/// `records` holds every live record and the record — whatever its state —
/// of every environment a listed container names. `current` is this
/// incarnation: a `PREPARING` record it made is an operation in flight on
/// another handle, and is left alone.
#[must_use]
pub fn classify(
    records: &[EnvironmentRecord],
    listed: &[OwnedEnvironment],
    current: u64,
) -> Vec<ReconcileClass> {
    let mut classes = Vec::new();
    let mut claimed: Vec<&EnvironmentId> = Vec::new();
    for owned in listed {
        let Some(environment) = owned.environment_id.as_ref().filter(|_| owned.labels_exact) else {
            classes.push(ReconcileClass::Foreign(owned.container.clone()));
            continue;
        };
        let Some(record) = records.iter().find(|r| &r.environment == environment) else {
            // Never recorded by this store, so never made by it.
            classes.push(ReconcileClass::Foreign(owned.container.clone()));
            continue;
        };
        if owned.run_id.as_ref() != Some(&record.run) {
            classes.push(ReconcileClass::Foreign(owned.container.clone()));
            continue;
        }
        // Twins: more than one container carrying exactly this environment's
        // labels, its run's included. A copy naming another run was
        // already set aside as foreign and does not make the genuine one
        // ambiguous.
        let twins = listed
            .iter()
            .filter(|o| {
                o.labels_exact
                    && o.environment_id.as_ref() == Some(environment)
                    && o.run_id.as_ref() == Some(&record.run)
            })
            .count();
        if twins > 1 {
            if !claimed.contains(&environment) {
                classes.push(ReconcileClass::Ambiguous(environment.clone()));
                claimed.push(environment);
            }
            continue;
        }
        claimed.push(environment);
        match record.state {
            EnvironmentState::Preparing if record.incarnation >= current => {
                // In flight on another handle of this incarnation.
            }
            EnvironmentState::Ready => {
                if record.container.as_ref() != Some(&owned.container) {
                    classes.push(ReconcileClass::Ambiguous(environment.clone()));
                } else if owned.state == dwk_proto::brokerp::ContainerState::Running {
                    classes.push(ReconcileClass::StillRunning(record.clone()));
                } else {
                    classes.push(ReconcileClass::Stopped(record.clone()));
                }
            }
            EnvironmentState::Refused | EnvironmentState::Destroyed | EnvironmentState::Lost => {
                classes.push(ReconcileClass::Orphan(owned.clone()));
            }
            EnvironmentState::Preparing
            | EnvironmentState::Unknown
            | EnvironmentState::Destroying => {
                classes.push(ReconcileClass::Pending(record.clone()));
            }
        }
    }
    for record in records {
        let in_flight =
            record.state == EnvironmentState::Preparing && record.incarnation >= current;
        if !record.state.is_final() && !in_flight && !claimed.contains(&&record.environment) {
            classes.push(ReconcileClass::Missing(record.clone()));
        }
    }
    classes
}

/// What one reconciliation did, by class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// The runtime could not be listed, or not completely: nothing changed.
    pub unobservable: bool,
    /// `READY` and running, measured clean again.
    pub still_running: u64,
    /// `READY` and running, no longer clean: destroyed.
    pub drifted: u64,
    /// Present and not running: destroyed.
    pub stopped: u64,
    /// Recorded, and gone.
    pub missing: u64,
    /// Pending records whose container was removed.
    pub pending_destroyed: u64,
    /// Environments more than one container claims: untouched.
    pub ambiguous: u64,
    /// Containers labelled as this store's, malformed: untouched.
    pub foreign: u64,
    /// Orphans removed.
    pub orphans_reaped: u64,
    /// Actions that could not be completed: they stay pending.
    pub incomplete: u64,
}

impl ReconcileReport {
    /// The audit record's fields.
    pub(super) fn fields(&self) -> Fields {
        Fields::new()
            .flag("unobservable", self.unobservable)
            .int("still_running", self.still_running)
            .int("drifted", self.drifted)
            .int("stopped", self.stopped)
            .int("missing", self.missing)
            .int("pending_destroyed", self.pending_destroyed)
            .int("ambiguous", self.ambiguous)
            .int("foreign", self.foreign)
            .int("orphans_reaped", self.orphans_reaped)
            .int("incomplete", self.incomplete)
    }
}

/// Record an orphan's removal.
pub(super) fn record_orphan(
    work: &mut Work<'_>,
    owned: &OwnedEnvironment,
    removed: bool,
) -> Result<(), AuthorityError> {
    let mut fields = Fields::new()
        .text("container", owned.container.as_str())
        .flag("removed", removed);
    if let Some(environment) = &owned.environment_id {
        fields = fields.text("environment_id", environment.as_str());
    }
    if let Some(run) = &owned.run_id {
        fields = fields.text("run_id", run.as_str());
    }
    work.audit(AuditEvent::EnvironmentOrphanReaped, fields)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use dwk_proto::brokerp::sandbox::{ContainerRef, NetworkTopology};
    use dwk_proto::brokerp::{ContainerState, OwnedEnvironment};
    use dwk_proto::wire::id::{EnvironmentId, RunId};

    use super::{EnvironmentRecord, EnvironmentState, ReconcileClass, classify};

    fn env(n: char) -> EnvironmentId {
        EnvironmentId::parse(&format!("env_01M24BB8G3E0A851TRWE3M8FZ{n}")).unwrap()
    }

    fn container(n: char) -> ContainerRef {
        ContainerRef::new(n.to_string().repeat(64)).unwrap()
    }

    fn record(n: char, state: EnvironmentState, c: Option<char>) -> EnvironmentRecord {
        EnvironmentRecord {
            environment: env(n),
            run: RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
            state,
            container: c.map(container),
            network: NetworkTopology::NoNetwork,
            incarnation: 1,
            failure: None,
        }
    }

    fn owned(c: char, n: Option<char>, state: ContainerState, exact: bool) -> OwnedEnvironment {
        OwnedEnvironment {
            container: container(c),
            state,
            image: None,
            environment_id: n.map(env),
            run_id: RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF"),
            labels_exact: exact,
        }
    }

    #[test]
    fn every_class_is_found_and_nothing_foreign_is_ours() {
        use ContainerState::{Exited, Running};
        use EnvironmentState::{Destroyed, Destroying, Preparing, Ready, Refused, Unknown};
        let records = [
            record('A', Ready, Some('a')),      // still running
            record('B', Ready, Some('b')),      // stopped
            record('C', Ready, Some('c')),      // missing
            record('D', Unknown, None),         // pending: reaped by label
            record('E', Destroying, Some('e')), // missing while destroying
            record('F', Ready, Some('f')),      // a twin claims it
            record('G', Preparing, None),       // in flight this incarnation
            record('H', Destroyed, Some('8')),  // ended, yet its container exists
            record('J', Refused, None),         // ended, never started: absent
        ];
        let listed = [
            owned('a', Some('A'), Running, true),
            owned('b', Some('B'), Exited, true),
            owned('d', Some('D'), Running, true),
            owned('f', Some('F'), Running, true),
            owned('9', Some('F'), Running, true),
            owned('8', Some('H'), Running, true), // orphan: recorded and ended
            owned('7', None, Running, false),     // foreign: malformed labels
            owned('6', Some('A'), Running, false), // malformed: not a twin
            owned('5', Some('K'), Running, true), // foreign: never recorded
        ];
        let classes = classify(&records, &listed, 1);
        let has = |want: &ReconcileClass| classes.contains(want);
        assert!(has(&ReconcileClass::StillRunning(record(
            'A',
            Ready,
            Some('a')
        ))));
        assert!(has(&ReconcileClass::Stopped(record('B', Ready, Some('b')))));
        assert!(has(&ReconcileClass::Missing(record('C', Ready, Some('c')))));
        assert!(has(&ReconcileClass::Pending(record('D', Unknown, None))));
        assert!(has(&ReconcileClass::Missing(record(
            'E',
            Destroying,
            Some('e')
        ))));
        assert!(has(&ReconcileClass::Ambiguous(env('F'))));
        assert!(has(&ReconcileClass::Orphan(owned(
            '8',
            Some('H'),
            Running,
            true
        ))));
        assert!(has(&ReconcileClass::Foreign(container('7'))));
        assert!(has(&ReconcileClass::Foreign(container('6'))));
        assert!(has(&ReconcileClass::Foreign(container('5'))));
        // The in-flight preparation is neither missing nor anything else.
        assert!(!classes.iter().any(|c| matches!(c,
            ReconcileClass::Missing(r) | ReconcileClass::Pending(r)
            | ReconcileClass::StillRunning(r) | ReconcileClass::Stopped(r)
            if r.environment == env('G'))));
        // An ambiguous environment's record is not declared missing, and a
        // final record with no container is not missing either.
        assert!(!has(&ReconcileClass::Missing(record(
            'F',
            Ready,
            Some('f')
        ))));
        assert!(!has(&ReconcileClass::Missing(record('J', Refused, None))));
        assert_eq!(classes.len(), 10);
    }

    #[test]
    fn a_copied_label_is_never_reaped() {
        // A container carrying exactly this store's labels, naming an
        // environment this store never recorded: foreign, whatever else.
        let listed = [owned('1', Some('Z'), ContainerState::Running, true)];
        assert_eq!(
            classify(&[], &listed, 1),
            [ReconcileClass::Foreign(container('1'))]
        );
        // Naming a recorded, ended environment — but another run: foreign.
        let mut copied = owned('2', Some('H'), ContainerState::Running, true);
        copied.run_id = RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZG");
        let records = [record('H', EnvironmentState::Destroyed, Some('8'))];
        assert_eq!(
            classify(&records, &[copied.clone()], 1),
            [ReconcileClass::Foreign(container('2'))]
        );
        // Beside the genuine container of a pending environment, a copy
        // naming another run is foreign — and does not make the genuine one
        // ambiguous: it is still settled.
        let mut other = copied;
        other.environment_id = Some(env('D'));
        let pending = [record('D', EnvironmentState::Unknown, None)];
        let genuine = owned('d', Some('D'), ContainerState::Running, true);
        let classes = classify(&pending, &[genuine, other], 1);
        assert!(classes.contains(&ReconcileClass::Pending(record(
            'D',
            EnvironmentState::Unknown,
            None
        ))));
        assert!(classes.contains(&ReconcileClass::Foreign(container('2'))));
        assert_eq!(classes.len(), 2);
    }

    #[test]
    fn a_previous_incarnations_preparation_is_reconciled() {
        let records = [record('G', EnvironmentState::Preparing, None)];
        let classes = classify(&records, &[], 2);
        assert_eq!(
            classes,
            [ReconcileClass::Missing(record(
                'G',
                EnvironmentState::Preparing,
                None
            ))]
        );
    }

    #[test]
    fn a_ready_record_whose_label_names_another_container_is_ambiguous() {
        let records = [record('A', EnvironmentState::Ready, Some('a'))];
        let listed = [owned('0', Some('A'), ContainerState::Running, true)];
        assert_eq!(
            classify(&records, &listed, 1),
            [ReconcileClass::Ambiguous(env('A'))]
        );
    }
}
