//! Taint that follows the content a run receives (F-01, [ADR-0062],
//! Proposed).
//!
//! A run's taint is raised by what the kernel delivers to it, before the run
//! is answered. Until F-01 only `net.http` could make it
//! `EXTERNAL_UNTRUSTED`; content a sandboxed workload fetched reached the run
//! -- through its output, or through the files it left for a later read, in
//! the same run or another on the same workspace -- as `LOCAL_UNVERIFIED`.
//! Now:
//!
//! * **A workload's own reach** (R1). A workload whose broker report says an
//!   origin byte reached it, or whose settlement is uncertain while its
//!   authorisation allowed something, raises its run to
//!   `EXTERNAL_UNTRUSTED` with its outcome -- whatever it printed.
//! * **What a run receives from an exposed root** (R2). A workspace root is
//!   exposed when the store holds, for its identity, an ADR-0061 exposure
//!   (certain or uncertain), a tainted effect (below), or a workload on it
//!   that may reach an origin and has not settled. Anything delivered to a
//!   run from such a root -- a read-family result, a workload's outcome, a
//!   host process's output or ending -- raises the run to
//!   `EXTERNAL_UNTRUSTED`. A run's taint is only ever raised inside its own
//!   operation: nothing here reaches into another run's context, so a
//!   running workload's decided context never drifts because of it.
//! * **A run holding external content marks the root it changes** (R3): an
//!   fs mutation, a workload or a host process it launches, recorded before
//!   the effect. Such a workload is refused while another run's workload on
//!   the root may reach an origin and started pristine (R4): that workload's
//!   cells could not follow.
//! * **Evidence** (R7). Every rise is recorded with its cause, its basis and
//!   its sources; a run's taint rises only with that row
//!   (`run_policy_input_taint_has_evidence`). The basis keeps apart content
//!   received (`ORIGIN_BYTES`, `NETWORK_RESPONSE`), content a tainted run
//!   introduced (`EXTERNAL_RUN_EFFECT`), an uncertain settlement
//!   (`UNCERTAIN`), and a mere possibility (`IN_FLIGHT`: a workload that may
//!   reach an origin had not settled). A possibility is never taken for
//!   content: a run whose external taint rests only on workloads that later
//!   settled without reaching anything does not mark the roots it changes.
//!
//! Network permission alone never raises taint: an authorisation that
//! allowed destinations its workload never reached, a tunnel refused or
//! never dialled, bytes only sent upstream -- none of these is content
//! received.
//!
//! [ADR-0062]: ../../../../../docs/adr/0062-taint-follows-delivered-content.md

use dwk_proto::json::{self, Number, Object, Value};
use dwk_proto::wire::id::{InvocationId, RunId};
use rusqlite::OptionalExtension as _;

use crate::policy::TaintLevel;

use super::Work;
use super::admission::{taint_from_rank, taint_rank};
use super::audit::{AuditEvent, Fields};
use super::error::AuthorityError;
use super::lease::to_sql;
use super::query::TaintCause;

/// A workspace root's identity, as the store records it: device and inode.
pub(super) type Root = (String, String);

/// What a taint rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Basis {
    /// A `net.http` response head arrived.
    NetworkResponse,
    /// An origin byte reached a workload: its broker's report, or a certain
    /// exposure of the root.
    OriginBytes,
    /// A run holding external content changed the root.
    ExternalRunEffect,
    /// A settlement that cannot say what a workload's tunnels did.
    Uncertain,
    /// A workload on the root that may reach an origin had not settled: a
    /// possibility, not content received.
    InFlight,
    /// Workspace content, or a host process's output.
    LocalContent,
    /// The in-process trusted interface (`Authority::raise_taint`).
    TrustedCaller,
}

impl Basis {
    /// The stored spelling.
    #[must_use]
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkResponse => "NETWORK_RESPONSE",
            Self::OriginBytes => "ORIGIN_BYTES",
            Self::ExternalRunEffect => "EXTERNAL_RUN_EFFECT",
            Self::Uncertain => "UNCERTAIN",
            Self::InFlight => "IN_FLIGHT",
            Self::LocalContent => "LOCAL_CONTENT",
            Self::TrustedCaller => "TRUSTED_CALLER",
        }
    }
}

/// The root of `run`'s workspace, as the store records it.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn root_of(work: &Work<'_>, run: &str) -> Result<Option<Root>, AuthorityError> {
    work.db(work
        .tx
        .query_row(
            "SELECT r.root_device, r.root_inode FROM run_policy_input p \
             JOIN workspace_root r ON r.workspace_id = p.workspace_id WHERE p.run_id = ?1",
            [run],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())
}

/// `run`'s taint, as stored.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer or the run has no policy
/// inputs.
pub(super) fn run_taint(work: &Work<'_>, run: &str) -> Result<TaintLevel, AuthorityError> {
    let rank: i64 = work
        .db(work
            .tx
            .query_row(
                "SELECT taint FROM run_policy_input WHERE run_id = ?1",
                [run],
                |row| row.get(0),
            )
            .optional())?
        .ok_or(AuthorityError::Rejected(format!(
            "no run {run} has policy inputs"
        )))?;
    taint_from_rank(rank).ok_or(AuthorityError::Invariant("a stored taint is malformed"))
}

/// How many rows of one kind, and the earliest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Sources {
    count: u64,
    first: Option<String>,
}

impl Sources {
    fn value(&self) -> Result<Value, AuthorityError> {
        let mut object = Object::new();
        let count = Number::from_i64(i64::try_from(self.count).unwrap_or(i64::MAX))
            .ok_or(AuthorityError::Invariant("a count does not fit"))?;
        put(&mut object, "count", Value::Number(count))?;
        if let Some(first) = &self.first {
            put(&mut object, "first", Value::String(first.clone()))?;
        }
        Ok(Value::Object(object))
    }
}

fn put(object: &mut Object, key: &str, value: Value) -> Result<(), AuthorityError> {
    object
        .insert(key.to_owned(), value)
        .map_err(|_| AuthorityError::Invariant("a source is recorded twice"))
}

/// What the store holds now that makes a root exposed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Exposure {
    /// ADR-0061: an origin byte reached a workload on it.
    certain: Sources,
    /// ADR-0061: a settlement that could not say.
    uncertain: Sources,
    /// F-01: a run holding external content changed it.
    effects: Sources,
    /// Workloads on it that may reach an origin and have not settled.
    in_flight: Vec<String>,
}

impl Exposure {
    /// Whether anything makes the root exposed.
    #[must_use]
    pub(super) fn any(&self) -> bool {
        self.basis().is_some()
    }

    /// The best-evidenced reason it is exposed, if it is: content received
    /// before a tainted run's effect, before an uncertain settlement, before
    /// a possibility.
    #[must_use]
    pub(super) fn basis(&self) -> Option<Basis> {
        if self.certain.count > 0 {
            Some(Basis::OriginBytes)
        } else if self.effects.count > 0 {
            Some(Basis::ExternalRunEffect)
        } else if self.uncertain.count > 0 {
            Some(Basis::Uncertain)
        } else if !self.in_flight.is_empty() {
            Some(Basis::InFlight)
        } else {
            None
        }
    }

    fn sources(&self, own: Option<&InvocationId>) -> Result<Object, AuthorityError> {
        let mut object = Object::new();
        if let Some(own) = own {
            put(&mut object, "own", Value::String(own.as_str().to_owned()))?;
        }
        for (key, sources) in [
            ("origin_bytes", &self.certain),
            ("uncertain", &self.uncertain),
            ("external_run_effects", &self.effects),
        ] {
            if sources.count > 0 {
                put(&mut object, key, sources.value()?)?;
            }
        }
        if !self.in_flight.is_empty() {
            let flight = Sources {
                count: u64::try_from(self.in_flight.len()).unwrap_or(u64::MAX),
                first: self.in_flight.first().cloned(),
            };
            put(&mut object, "in_flight", flight.value()?)?;
        }
        Ok(object)
    }
}

fn sources_of(work: &Work<'_>, sql: &str, root: &Root) -> Result<Sources, AuthorityError> {
    work.db(work
        .tx
        .query_row(sql, rusqlite::params![root.0, root.1], |row| {
            let count: i64 = row.get(0)?;
            Ok(Sources {
                count: u64::try_from(count).unwrap_or(0),
                first: row.get(1)?,
            })
        }))
}

/// What makes `root` exposed now.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn exposure(work: &Work<'_>, root: &Root) -> Result<Exposure, AuthorityError> {
    let certain = sources_of(
        work,
        "SELECT count(*), (SELECT invocation_id FROM workspace_exposure \
                           WHERE root_device = ?1 AND root_inode = ?2 AND certain = 1 \
                           ORDER BY recorded_ms, invocation_id LIMIT 1) \
         FROM workspace_exposure WHERE root_device = ?1 AND root_inode = ?2 AND certain = 1",
        root,
    )?;
    let uncertain = sources_of(
        work,
        "SELECT count(*), (SELECT invocation_id FROM workspace_exposure \
                           WHERE root_device = ?1 AND root_inode = ?2 AND certain = 0 \
                           ORDER BY recorded_ms, invocation_id LIMIT 1) \
         FROM workspace_exposure WHERE root_device = ?1 AND root_inode = ?2 AND certain = 0",
        root,
    )?;
    let effects = sources_of(
        work,
        "SELECT count(*), (SELECT invocation_id FROM workspace_taint \
                           WHERE root_device = ?1 AND root_inode = ?2 \
                           ORDER BY recorded_ms, invocation_id LIMIT 1) \
         FROM workspace_taint WHERE root_device = ?1 AND root_inode = ?2",
        root,
    )?;
    let mut statement = work.db(work.tx.prepare(
        "SELECT e.invocation_id FROM workload_egress e \
         JOIN workload w ON w.invocation_id = e.invocation_id \
         WHERE e.root_device = ?1 AND e.root_inode = ?2 \
         AND e.allows_anything = 1 AND w.state = 'LAUNCHING' ORDER BY e.invocation_id",
    ))?;
    let in_flight: Vec<String> = work.db(statement
        .query_map(rusqlite::params![root.0, root.1], |row| row.get(0))
        .and_then(Iterator::collect))?;
    Ok(Exposure {
        certain,
        uncertain,
        effects,
        in_flight,
    })
}

/// Whether `root` is exposed now (ADR-0061's predicate, with F-01's marks).
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn exposed(work: &Work<'_>, root: &Root) -> Result<bool, AuthorityError> {
    Ok(exposure(work, root)?.any())
}

/// Why a run's taint is to rise, and from what.
#[derive(Debug, Clone)]
pub(super) struct Evidence<'a> {
    /// The taint the delivery carries.
    pub(super) level: TaintLevel,
    pub(super) cause: TaintCause,
    pub(super) basis: Basis,
    /// The invocation that delivered it, if any.
    pub(super) invocation: Option<&'a InvocationId>,
    /// The root it came from, if any.
    pub(super) root: Option<&'a Root>,
    /// Its sources, as recorded.
    pub(super) sources: Object,
    /// For an `IN_FLIGHT` basis: the workloads it rested on.
    pub(super) in_flight: &'a [String],
}

impl<'a> Evidence<'a> {
    /// A delivery whose evidence names nothing beyond itself.
    #[must_use]
    pub(super) fn plain(
        level: TaintLevel,
        (cause, basis): (TaintCause, Basis),
        invocation: Option<&'a InvocationId>,
    ) -> Self {
        Self {
            level,
            cause,
            basis,
            invocation,
            root: None,
            sources: Object::new(),
            in_flight: &[],
        }
    }
}

/// What a raise left: the run's taint, and the evidence row recorded, if one
/// was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Raised {
    pub(super) taint: TaintLevel,
    pub(super) seq: Option<i64>,
}

impl Raised {
    /// The fields a delivering record carries: the run's taint after it,
    /// and, when it was recorded, the evidence's basis and row.
    #[must_use]
    pub(super) fn fields(&self, basis: Basis) -> Fields {
        let fields = Fields::new().text("taint", self.taint.as_str());
        match self.seq {
            Some(seq) => fields
                .text("taint_basis", basis.as_str())
                .int("taint_evidence_seq", u64::try_from(seq).unwrap_or(0)),
            None => fields,
        }
    }
}

/// Whether some evidence of `run` says it holds external content: a row
/// whose basis is more than a possibility.
fn holds_more_than_possibility(work: &Work<'_>, run: &str) -> Result<bool, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM run_taint_evidence WHERE run_id = ?1 \
                        AND to_taint = 2 AND basis <> 'IN_FLIGHT')",
        [run],
        |row| row.get(0),
    ))
}

/// Whether every workload in `in_flight` is already a recorded source of a
/// possibility of `run`.
fn possibilities_known(
    work: &Work<'_>,
    run: &str,
    in_flight: &[String],
) -> Result<bool, AuthorityError> {
    for invocation in in_flight {
        let known: bool = work.db(work.tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM run_taint_in_flight \
                            WHERE run_id = ?1 AND invocation_id = ?2)",
            rusqlite::params![run, invocation],
            |row| row.get(0),
        ))?;
        if !known {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Raise `run`'s taint to at least `evidence.level`, recording why. Never
/// lowers it. A row is recorded for every rise, and for an external receipt
/// that adds to what a run's external taint rests on while that is still
/// only a possibility -- so that what it rests on can always be told.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot record it, or the run has no
/// policy inputs.
pub(super) fn raise(
    work: &mut Work<'_>,
    run: &RunId,
    evidence: &Evidence<'_>,
) -> Result<Raised, AuthorityError> {
    let current = run_taint(work, run.as_str())?;
    let raised = core::cmp::max(current, evidence.level);
    let rises = raised != current;
    let adds = !rises
        && evidence.level == TaintLevel::ExternalUntrusted
        && !holds_more_than_possibility(work, run.as_str())?
        && (evidence.basis != Basis::InFlight
            || !possibilities_known(work, run.as_str(), evidence.in_flight)?);
    if !rises && !adds {
        return Ok(Raised {
            taint: current,
            seq: None,
        });
    }
    let seq: i64 = work.db(work.tx.query_row(
        "SELECT COALESCE(max(seq), 0) + 1 FROM run_taint_evidence WHERE run_id = ?1",
        [run.as_str()],
        |row| row.get(0),
    ))?;
    let sources = json::to_canonical_string(&Value::Object(evidence.sources.clone()));
    work.db(work.tx.execute(
        "INSERT INTO run_taint_evidence (run_id, seq, from_taint, to_taint, cause, basis, \
         invocation_id, root_device, root_inode, sources, recorded_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            run.as_str(),
            seq,
            taint_rank(current),
            taint_rank(raised),
            evidence.cause.as_str(),
            evidence.basis.as_str(),
            evidence.invocation.map(InvocationId::as_str),
            evidence.root.map(|r| r.0.clone()),
            evidence.root.map(|r| r.1.clone()),
            sources,
            to_sql(work.now)?
        ],
    ))?;
    if evidence.basis == Basis::InFlight {
        for invocation in evidence.in_flight {
            work.db(work.tx.execute(
                "INSERT INTO run_taint_in_flight (run_id, seq, invocation_id) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![run.as_str(), seq, invocation],
            ))?;
        }
    }
    if rises {
        work.db(work.tx.execute(
            "UPDATE run_policy_input SET taint = ?2 WHERE run_id = ?1",
            rusqlite::params![run.as_str(), taint_rank(raised)],
        ))?;
        work.audit(
            AuditEvent::TaintRaised,
            Fields::new()
                .text("run_id", run.as_str())
                .text("from", current.as_str())
                .text("to", raised.as_str())
                .text("cause", evidence.cause.as_str())
                .text("basis", evidence.basis.as_str())
                .int("evidence_seq", u64::try_from(seq).unwrap_or(0))
                .maybe_text(
                    "invocation_id",
                    evidence.invocation.map(|i| i.as_str().to_owned()),
                )
                .maybe_text("root_device", evidence.root.map(|r| r.0.clone()))
                .maybe_text("root_inode", evidence.root.map(|r| r.1.clone()))
                .text("sources", sources),
        )?;
    }
    Ok(Raised {
        taint: raised,
        seq: Some(seq),
    })
}

/// What a workload's own tunnels did, as its egress settled (ADR-0061).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnReach {
    /// No authorisation, or nothing reached: nothing of its own.
    Nothing,
    /// Its broker's report says an origin byte reached it.
    Reached,
    /// Nothing says what its tunnels did, and it allowed something.
    Uncertain,
}

/// What `invocation`'s settled egress says of its own reach.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn own_reach(
    work: &Work<'_>,
    invocation: &InvocationId,
) -> Result<OwnReach, AuthorityError> {
    let settled: Option<(Option<String>, Option<i64>)> = work.db(work
        .tx
        .query_row(
            "SELECT settled, exposed FROM workload_egress WHERE invocation_id = ?1",
            [invocation.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    Ok(match settled {
        Some((Some(settled), Some(1))) if settled == "REPORTED" => OwnReach::Reached,
        Some((Some(settled), Some(1))) if settled == "UNCERTAIN" => OwnReach::Uncertain,
        Some(_) | None => OwnReach::Nothing,
    })
}

/// What a delivery to a run carries.
#[derive(Debug, Clone, Copy)]
pub(super) struct Delivery<'a> {
    /// The invocation that delivers it.
    pub(super) invocation: &'a InvocationId,
    /// Whether it carries content that is at least `LOCAL_UNVERIFIED` even
    /// from a pristine root (today's rule: a read-family result, output).
    pub(super) local: bool,
    /// Whether it can carry anything from the root at all (a result, an
    /// output, an ending; not a provable non-start).
    pub(super) from_root: bool,
    /// A workload's own reach (R1); [`OwnReach::Nothing`] otherwise.
    pub(super) own: OwnReach,
    /// Whether it is a restart's settling of an interrupted workload (R5):
    /// nothing reached the run, which the restart reaped, but its history
    /// says what it may have received.
    pub(super) interrupted: bool,
}

/// Record the taint `delivery` brings to `run` (R1, R2), before the run is
/// answered. The fields its record carries.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer or record it.
pub(super) fn deliver(
    work: &mut Work<'_>,
    run: &RunId,
    delivery: &Delivery<'_>,
) -> Result<Fields, AuthorityError> {
    let root = root_of(work, run.as_str())?;
    let exposure = match &root {
        Some(root) if delivery.from_root => exposure(work, root)?,
        _ => Exposure::default(),
    };
    let external = match delivery.own {
        OwnReach::Reached => Some((TaintCause::WorkloadReached, Basis::OriginBytes)),
        OwnReach::Uncertain => Some((TaintCause::WorkloadUncertain, Basis::Uncertain)),
        OwnReach::Nothing => exposure.basis().map(|b| (TaintCause::RootExposed, b)),
    };
    let (level, cause, basis) = match external {
        Some((_, basis)) if delivery.interrupted => (
            TaintLevel::ExternalUntrusted,
            TaintCause::WorkloadInterrupted,
            basis,
        ),
        Some((cause, basis)) => (TaintLevel::ExternalUntrusted, cause, basis),
        None if delivery.local => (
            TaintLevel::LocalUnverified,
            TaintCause::ToolResult,
            Basis::LocalContent,
        ),
        None => return Ok(Fields::new()),
    };
    let sources = if level == TaintLevel::ExternalUntrusted {
        exposure.sources((delivery.own != OwnReach::Nothing).then_some(delivery.invocation))?
    } else {
        Object::new()
    };
    let in_flight = if basis == Basis::InFlight {
        exposure.in_flight.as_slice()
    } else {
        &[]
    };
    let raised = raise(
        work,
        run,
        &Evidence {
            level,
            cause,
            basis,
            invocation: Some(delivery.invocation),
            root: root.as_ref(),
            sources,
            in_flight,
        },
    )?;
    Ok(raised.fields(basis))
}

/// Whether `run` holds external content (R3's condition): its taint is
/// `EXTERNAL_UNTRUSTED` and rests on more than a possibility -- or on a
/// possibility still open, or one that settled exposed.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn holds_external_content(work: &Work<'_>, run: &str) -> Result<bool, AuthorityError> {
    if run_taint(work, run)? != TaintLevel::ExternalUntrusted {
        return Ok(false);
    }
    if holds_more_than_possibility(work, run)? {
        return Ok(true);
    }
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM run_taint_in_flight f \
                        JOIN workload w ON w.invocation_id = f.invocation_id \
                        JOIN workload_egress e ON e.invocation_id = f.invocation_id \
                        WHERE f.run_id = ?1 AND (w.state = 'LAUNCHING' OR e.exposed = 1))",
        [run],
        |row| row.get(0),
    ))
}

/// What R3 recorded for an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Marked {
    /// The root is marked: the run holds external content.
    Marked,
    /// Nothing to mark.
    Clean,
}

/// R3: before an effect `tool` of `run`'s on its root, mark the root when
/// the run holds external content. In the effect's own transaction, before
/// the broker hears of it.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer or record it.
pub(super) fn mark_effect(
    work: &mut Work<'_>,
    run: &RunId,
    invocation: &InvocationId,
    tool: &'static str,
) -> Result<Marked, AuthorityError> {
    let Some(root) = root_of(work, run.as_str())? else {
        return Ok(Marked::Clean);
    };
    if !holds_external_content(work, run.as_str())? {
        return Ok(Marked::Clean);
    }
    work.db(work.tx.execute(
        "INSERT INTO workspace_taint (root_device, root_inode, invocation_id, run_id, tool, \
         recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            root.0,
            root.1,
            invocation.as_str(),
            run.as_str(),
            tool,
            to_sql(work.now)?
        ],
    ))?;
    work.audit(
        AuditEvent::WorkspaceTainted,
        Fields::new()
            .text("run_id", run.as_str())
            .text("invocation_id", invocation.as_str())
            .text("tool", tool)
            .text("root_device", root.0)
            .text("root_inode", root.1),
    )?;
    Ok(Marked::Marked)
}

/// R4: whether a workload of `run`, which would mark its root, must wait --
/// another run's workload on the root may reach an origin and started
/// pristine, and its cells could not follow the mark.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn exposure_pending(work: &Work<'_>, run: &RunId) -> Result<bool, AuthorityError> {
    let Some(root) = root_of(work, run.as_str())? else {
        return Ok(false);
    };
    if !holds_external_content(work, run.as_str())? {
        return Ok(false);
    }
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM workload_egress e \
                        JOIN workload w ON w.invocation_id = e.invocation_id \
                        WHERE e.root_device = ?1 AND e.root_inode = ?2 AND e.run_id <> ?3 \
                        AND e.allows_anything = 1 AND e.exposed_at_start = 0 \
                        AND w.state = 'LAUNCHING')",
        rusqlite::params![root.0, root.1, run.as_str()],
        |row| row.get(0),
    ))
}

/// The replay check (I-12): every run's stored taint is the highest its
/// evidence says, and its evidence rows chain from `NONE` in order. `Err`
/// names the first run that does not.
#[cfg(test)]
pub(super) fn history_holds(conn: &rusqlite::Connection) -> Result<(), String> {
    let runs: Vec<(String, i64)> = conn
        .prepare("SELECT run_id, taint FROM run_policy_input ORDER BY run_id")
        .and_then(|mut s| {
            s.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .map_err(|e| e.to_string())?;
    for (run, taint) in runs {
        let rows: Vec<(i64, i64, i64, String)> = conn
            .prepare(
                "SELECT seq, from_taint, to_taint, basis FROM run_taint_evidence \
                 WHERE run_id = ?1 ORDER BY seq",
            )
            .and_then(|mut s| {
                s.query_map([&run], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect()
            })
            .map_err(|e| e.to_string())?;
        let mut held = 0i64;
        for (n, (seq, from, to, basis)) in rows.iter().enumerate() {
            if *seq != i64::try_from(n).unwrap_or(0) + 1 {
                return Err(format!("{run}: evidence row {seq} out of order"));
            }
            if basis != "BEFORE_EVIDENCE" && *from != held {
                return Err(format!("{run}: row {seq} rises from {from}, held {held}"));
            }
            held = held.max(*to);
        }
        if held != taint {
            return Err(format!("{run}: taint {taint}, evidence says {held}"));
        }
    }
    Ok(())
}
