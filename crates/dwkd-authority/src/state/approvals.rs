//! M6.2: the kernel-owned approval registry ([ADR-0080], Proposed) --
//! durable requests, the approvals decided on them, and each use, spent in
//! the transaction that records its effect's intent.
//!
//! # What a registry row is, and is not
//!
//! A request records that a `REQUIRE_APPROVAL` decision was reached for one
//! canonical action, by its binding ([ADR-0079]). An approval records that an
//! authenticated approver granted one request, at an assurance level, for a
//! bounded life and use count. A use records that one use was spent, and on
//! which intent. None is authority by existing: a use is spent only when every
//! guard of [`consider`] holds inside the launch's own transaction, and the
//! database refuses a use that is not of an open, unexpired approval of its
//! own run, on its own intent.
//!
//! # Who may write
//!
//! | write | by | when |
//! |---|---|---|
//! | a request | [`request`] | a sandboxed launch denied `REQUIRE_APPROVAL`, at A1, exact action, with a `READY` environment |
//! | an approval or a denial | [`decide`] | **no production caller**: M6.3's approver operations; tests drive this state machine |
//! | a use | [`consume`] | the launch's intent transaction, after the intent |
//! | an end | [`expire`], [`revoke`], the use that exhausts it | an expiry observed; a revocation (M6.3's operator act; tests); the last use |
//!
//! No DWKP or approver-endpoint operation reaches [`decide`] or [`revoke`],
//! and the approver set they check against is attached only by tests in this
//! build ([`super::Authority::attach_approvers`]): in the shipped M6.2 build
//! the set is empty, so no approval can be granted and none can be spent.
//! TX062's exemption names this module alone; TX068 keeps every other module
//! from writing the registry's tables.
//!
//! # Assurance (ADR-0078)
//!
//! [`required`] classifies the canonical action: the host environment,
//! `secret.use`, `fs.delete` and a launch that injects a credential are A2,
//! everything else A1. No presence factor exists, so an A2 class has no
//! request at all -- its `REQUIRE_APPROVAL` stays `DENY` -- and an approval at
//! A2 is never decided. Every route but the sandboxed `process.exec` decides
//! in `Environment::Host`, so in M6.2 only a sandboxed launch with no
//! credential can be approvable.
//!
//! [ADR-0080]: ../../../../../docs/adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md
//! [ADR-0079]: ../../../../../docs/adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md

use dwk_proto::brokerp::sandbox::AssuranceLevel;
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::Epoch;
use rusqlite::OptionalExtension as _;

use crate::capability::ExecutableIdentity;
use crate::policy::{ApprovalScopeKind, CanonicalAction, Decision, Effect, Environment};
use crate::sandbox::{EffectiveAssurance, EnvironmentKind, Judgement, MeasuredAssurance};

use super::audit::{AuditEvent, Fields};
use super::binding::{
    ApprovalBinding, BindingInput, BoundArguments, BoundCredentials, BoundEnvironment,
    BoundResource, BoundScope, RunContext,
};
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;
use super::identity::AuthenticatedSubject;
use super::lease::to_sql;
use super::policy_state::ActiveAuthority;
use super::{Authority, CrashPoint, Work};

/// The most pending requests one run may hold: a run that asks for more is
/// denied, as it was before M6.2, and records nothing.
pub(crate) const MAX_PENDING_PER_RUN: i64 = 16;

/// The most pending requests a store holds across every run.
pub(crate) const MAX_PENDING: i64 = 1024;

/// How long a request waits for a decision: the rule's TTL, and never more
/// than this. No decision in the window is no execution (APPROVALS.md §8).
pub(crate) const MAX_REQUEST_WINDOW_MS: u64 = 10 * 60 * 1000;

/// The one channel a local approval arrives on (ADR-0077 OD-1).
const CHANNEL: &str = "APPROVER_ENDPOINT";

/// An assurance level (ADR-0077 §3). There is no A0: it is never enough,
/// so it is not a value a decision can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Assurance {
    /// A dedicated approver account answered.
    A1,
    /// A1 and a presence factor the authority verified. None exists in M6.
    A2,
}

impl Assurance {
    /// The stored spelling.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::A1 => "A1",
            Self::A2 => "A2",
        }
    }
}

/// The level an action needs (ADR-0078 §1): A2 for the host environment,
/// `secret.use`, `fs.delete` and a launch that injects a credential (whose
/// injection is a `secret.use`); A1 for everything else. A policy may only
/// raise it.
pub(crate) fn required(action: &CanonicalAction, injects_credential: bool) -> Assurance {
    let verb = action.capability().verb().to_string();
    if *action.environment() == Environment::Host
        || injects_credential
        || verb == "secret.use"
        || verb == "fs.delete"
    {
        Assurance::A2
    } else {
        Assurance::A1
    }
}

/// Who asks, as the public route authenticated them: the caller's subject,
/// session and lease tenure (its epoch and the holder's incarnation).
#[derive(Debug, Clone, Copy)]
pub(super) struct Tenure<'a> {
    pub(super) subject: &'a str,
    pub(super) session: &'a SessionId,
    pub(super) epoch: Epoch,
    pub(super) incarnation: u64,
}

/// A sandboxed launch's facts, as the workload route decided them.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked<'a> {
    pub(super) run: &'a RunId,
    pub(super) action: &'a CanonicalAction,
    pub(super) decision: &'a Decision,
    pub(super) capability_satisfied: bool,
    pub(super) obligations_kept: bool,
    pub(super) injects_credential: bool,
    pub(super) executable: &'a ExecutableIdentity,
    pub(super) args: &'a [String],
    pub(super) key: &'a str,
    /// The run's `READY` environment's measured, effective level, if it has
    /// one: the binding names the environment as measured.
    pub(super) environment: Option<AssuranceLevel>,
    pub(super) tenure: Option<Tenure<'a>>,
    pub(super) active: &'a ActiveAuthority,
}

/// An approval whose every guard held, in the launch's own transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Candidate {
    approval_id: String,
    request_id: String,
    approver: String,
    seq: i64,
    max_uses: i64,
}

/// What the registry found for one approvable launch.
#[derive(Debug, Clone)]
pub(super) struct Considered {
    binding: ApprovalBinding,
    run: RunId,
    subject: String,
    session: SessionId,
    epoch: u64,
    incarnation: u64,
    key: String,
    ttl_s: u32,
    max_uses: u32,
    rule_id: String,
    policy_revision: Sha256Hash,
    /// The approval this launch may spend, if one passes every guard.
    pub(super) spendable: Option<Candidate>,
    /// Open approvals of this binding past their life: ended `EXPIRED`.
    stale: Vec<String>,
    /// An open approval this call's key was requested for, under another
    /// binding: the world, the run or the call changed since.
    drift: Option<String>,
}

impl Considered {
    /// Whether the launch is approved: an approval passed every guard.
    pub(super) const fn approved(&self) -> bool {
        self.spendable.is_some()
    }
}

/// The registry's clock: the authority's, never below the highest instant
/// any registry transaction has recorded -- so an instant once passed is not
/// current again after the host clock moves back.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be read.
pub(super) fn clock(work: &Work<'_>) -> Result<u64, AuthorityError> {
    let high: i64 = work.db(work.tx.query_row(
        "SELECT high_water_ms FROM approval_clock WHERE singleton = 1",
        [],
        |row| row.get(0),
    ))?;
    let high = u64::try_from(high)
        .map_err(|_| AuthorityError::Invariant("the approval clock is negative"))?;
    Ok(work.now.max(high))
}

/// [`clock`], recorded: the high-water mark rises to it.
fn advance(work: &Work<'_>) -> Result<u64, AuthorityError> {
    let now = clock(work)?;
    work.db(work.tx.execute(
        "UPDATE approval_clock SET high_water_ms = ?1 WHERE singleton = 1 AND high_water_ms < ?1",
        [to_sql(now)?],
    ))?;
    Ok(now)
}

/// A judgement that a `READY` environment's effective level stands for: it
/// was measured usable, or it would not be `READY`.
fn measured(level: AssuranceLevel) -> Judgement {
    let declared = EnvironmentKind::Oci.declared();
    let measured = MeasuredAssurance(level);
    Judgement {
        declared,
        measured,
        effective: EffectiveAssurance::of(declared, measured),
        failed: Vec::new(),
        unobservable: Vec::new(),
    }
}

/// Whether `subject` is one of the approvers attached to this authority.
fn approver_known(work: &Work<'_>, subject: &str) -> bool {
    work.shared.attachments.approvers.get().is_some_and(|set| {
        set.iter()
            .any(|uid| AuthenticatedSubject::unix_uid(*uid).storage_key() == subject)
    })
}

/// One open approval of a binding, with its request.
#[derive(Debug, Clone)]
struct Open {
    approval_id: String,
    request_id: String,
    approver: String,
    assurance: String,
    not_after: u64,
    uses: i64,
    max_uses: i64,
    requester: String,
    session: String,
    epoch: u64,
    incarnation: u64,
    policy_revision: String,
    binding: Vec<u8>,
    assurance_required: String,
}

fn opened(work: &Work<'_>, run: &RunId, hash: &str) -> Result<Vec<Open>, AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "SELECT a.approval_id, a.request_id, a.approver, a.assurance, a.not_after_ms, a.uses, \
         a.max_uses, r.requester, r.session_id, r.epoch, r.incarnation, r.policy_revision, \
         r.binding, r.assurance_required FROM approval a \
         JOIN approval_request r ON r.request_id = a.request_id \
         WHERE r.run_id = ?1 AND r.binding_sha256 = ?2 AND a.state = 'OPEN' \
         ORDER BY a.granted_ms, a.approval_id",
    ))?;
    let rows = work.db(
        statement.query_map(rusqlite::params![run.as_str(), hash], |row| {
            Ok((
                (
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ),
                (
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, String>(13)?,
                ),
            ))
        }),
    )?;
    let malformed = || AuthorityError::Invariant("a stored approval is malformed");
    let mut out = Vec::new();
    for row in rows {
        let (
            (approval_id, request_id, approver, assurance, not_after, uses, max_uses),
            (requester, session, epoch, incarnation, policy_revision, binding, assurance_required),
        ) = work.db(row)?;
        out.push(Open {
            approval_id,
            request_id,
            approver,
            assurance,
            not_after: u64::try_from(not_after).map_err(|_| malformed())?,
            uses,
            max_uses,
            requester,
            session,
            epoch: u64::try_from(epoch).map_err(|_| malformed())?,
            incarnation: u64::try_from(incarnation).map_err(|_| malformed())?,
            policy_revision,
            binding,
            assurance_required,
        });
    }
    Ok(out)
}

/// Every guard a use must pass that the binding's equality does not already
/// carry (ADR-0079 §8): the requester, session and tenure; the policy
/// revision; the binding itself, byte for byte; the approver, still one of
/// the operator's and never the requester; the assurance; a use left.
fn passes(open: &Open, canonical: &[u8], tenure: &Tenure<'_>, revision: &str) -> bool {
    open.requester == tenure.subject
        && open.session == tenure.session.as_str()
        && open.epoch == tenure.epoch.get()
        && open.incarnation == tenure.incarnation
        && open.policy_revision == revision
        && open.binding.as_slice() == canonical
        && open.approver != open.requester
        && open.assurance == Assurance::A1.as_str()
        && open.assurance_required == Assurance::A1.as_str()
        && open.uses < open.max_uses
}

/// For one sandboxed launch, whether it is approvable at all and, if so,
/// its binding and the approval it may spend. Read-only: [`settle`],
/// [`request`] and [`consume`] write what this found, in the same
/// transaction.
///
/// `None` -- no request and no spend, the launch decided as it was before
/// M6.2 -- for an in-process launch, a decision that is not
/// `REQUIRE_APPROVAL`, a missing capability, an obligation the route does not
/// keep, an A2 class, a scope other than `exact_action`, a run with no
/// `READY` environment, a run that is not active, or a binding that cannot be
/// built.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be read.
pub(super) fn consider(
    work: &Work<'_>,
    asked: &Asked<'_>,
) -> Result<Option<Box<Considered>>, AuthorityError> {
    let Some(tenure) = asked.tenure else {
        return Ok(None);
    };
    if asked.decision.effect() != Effect::RequireApproval
        || !asked.capability_satisfied
        || !asked.obligations_kept
        || required(asked.action, asked.injects_credential) != Assurance::A1
    {
        return Ok(None);
    }
    let Some(spec) = asked.decision.approval() else {
        return Ok(None);
    };
    if spec.scope() != ApprovalScopeKind::ExactAction {
        return Ok(None);
    }
    let (Some(level), Some(config)) = (asked.environment, work.shared.sandbox.get()) else {
        return Ok(None);
    };
    let Ok(environment) = BoundEnvironment::sandbox(config, &measured(level)) else {
        return Ok(None);
    };
    let Ok(run) = RunContext::load(work, asked.run)? else {
        return Ok(None);
    };
    let args: Vec<&str> = asked.args.iter().map(String::as_str).collect();
    let Ok(arguments) = BoundArguments::argv(&args) else {
        return Ok(None);
    };
    let Ok(binding) = ApprovalBinding::new(&BindingInput {
        action: asked.action,
        decision: asked.decision,
        obligations_kept: asked.obligations_kept,
        run: &run,
        environment: &environment,
        resource: &BoundResource::executable(asked.executable),
        arguments: &arguments,
        credentials: &BoundCredentials::none(),
        scope: &BoundScope::exact_action(),
    }) else {
        return Ok(None);
    };
    let now = clock(work)?;
    let hash = binding.binding_hash().to_hex();
    let revision = asked.active.revision.to_hex();
    let mut spendable = None;
    let mut stale = Vec::new();
    for open in opened(work, asked.run, &hash)? {
        if now >= open.not_after {
            stale.push(open.approval_id);
            continue;
        }
        if spendable.is_none()
            && passes(&open, binding.canonical_bytes(), &tenure, &revision)
            && approver_known(work, &open.approver)
        {
            spendable = Some(Candidate {
                approval_id: open.approval_id,
                request_id: open.request_id,
                approver: open.approver,
                seq: open.uses + 1,
                max_uses: open.max_uses,
            });
        }
    }
    let drift = if spendable.is_none() {
        work.db(work
            .tx
            .query_row(
                "SELECT a.approval_id FROM approval a \
                 JOIN approval_request r ON r.request_id = a.request_id \
                 WHERE r.run_id = ?1 AND r.idempotency_key = ?2 AND r.binding_sha256 != ?3 \
                 AND a.state = 'OPEN' ORDER BY a.granted_ms, a.approval_id LIMIT 1",
                rusqlite::params![asked.run.as_str(), asked.key, hash],
                |row| row.get(0),
            )
            .optional())?
    } else {
        None
    };
    Ok(Some(Box::new(Considered {
        binding,
        run: asked.run.clone(),
        subject: tenure.subject.to_owned(),
        session: tenure.session.clone(),
        epoch: tenure.epoch.get(),
        incarnation: tenure.incarnation,
        key: asked.key.to_owned(),
        ttl_s: spec.ttl().seconds(),
        max_uses: spec.max_uses(),
        rule_id: asked.decision.rule_id().as_str().to_owned(),
        policy_revision: asked.active.revision,
        spendable,
        stale,
        drift,
    })))
}

/// End each stale approval `EXPIRED`, and record a drift: both before the
/// launch is denied or permitted, in its own transaction.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be written.
pub(super) fn settle(work: &mut Work<'_>, considered: &Considered) -> Result<(), AuthorityError> {
    let now = advance(work)?;
    for approval in &considered.stale {
        expire(work, approval, now)?;
    }
    if let Some(approval) = &considered.drift {
        let fields = Fields::new()
            .text("approval_id", approval.as_str())
            .text("run_id", considered.run.as_str())
            .text("idempotency_key", considered.key.as_str())
            .text("binding_sha256", considered.binding.binding_hash().to_hex());
        work.audit(AuditEvent::ApprovalDriftDetected, fields)?;
    }
    Ok(())
}

/// End one open approval `EXPIRED`, audited.
fn expire(work: &mut Work<'_>, approval: &str, now: u64) -> Result<(), AuthorityError> {
    let ended = work.db(work.tx.execute(
        "UPDATE approval SET state = 'EXPIRED', ended_ms = ?2, ended_reason = 'EXPIRED' \
         WHERE approval_id = ?1 AND state = 'OPEN'",
        rusqlite::params![approval, to_sql(now)?],
    ))?;
    if ended == 1 {
        let fields = Fields::new()
            .text("approval_id", approval)
            .text("kind", "approval");
        work.audit(AuditEvent::ApprovalExpired, fields)?;
    }
    Ok(())
}

/// End a run's pending requests that are past their window `EXPIRED`.
fn expire_requests(work: &mut Work<'_>, run: &RunId, now: u64) -> Result<(), AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "SELECT request_id FROM approval_request WHERE run_id = ?1 AND state = 'PENDING' \
         AND not_after_ms <= ?2 ORDER BY request_id",
    ))?;
    let ids = work
        .db(
            statement.query_map(rusqlite::params![run.as_str(), to_sql(now)?], |row| {
                row.get::<_, String>(0)
            }),
        )?
        .collect::<rusqlite::Result<Vec<String>>>();
    drop(statement);
    for request in work.db(ids)? {
        expire_request(work, &request, run.as_str(), now, "WINDOW")?;
    }
    Ok(())
}

/// End one pending request `EXPIRED`, audited, with its `cause`: its window
/// passed with no decision (`WINDOW`), or its run's authority ended before
/// one (`RUN_ENDED`). No decision is no execution.
fn expire_request(
    work: &mut Work<'_>,
    request: &str,
    run: &str,
    now: u64,
    cause: &'static str,
) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "UPDATE approval_request SET state = 'EXPIRED', decided_ms = ?2 \
         WHERE request_id = ?1 AND state = 'PENDING'",
        rusqlite::params![request, to_sql(now)?],
    ))?;
    let fields = Fields::new()
        .text("request_id", request)
        .text("run_id", run)
        .text("kind", "request")
        .text("cause", cause);
    work.audit(AuditEvent::ApprovalExpired, fields)
}

/// Whether `run` still holds its authority.
fn run_active(work: &Work<'_>, run: &str) -> Result<bool, AuthorityError> {
    let found: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM run WHERE run_id = ?1 AND state = 'ACTIVE'",
            [run],
            |row| row.get(0),
        )
        .optional())?;
    Ok(found.is_some())
}

/// What recording a request did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Requested {
    /// A new pending request, audited `approval.requested`.
    Recorded,
    /// The run already waits on this binding: nothing new.
    Pending,
    /// The run, or the store, holds as many pending requests as it may.
    Exhausted,
}

/// When a request asked at `now` stops waiting: its rule's TTL, never more
/// than [`MAX_REQUEST_WINDOW_MS`]; `None` past the clock's range -- refused,
/// never wrapped.
fn request_deadline(now: u64, ttl_s: u32) -> Option<u64> {
    let window = u64::from(ttl_s)
        .checked_mul(1000)
        .map_or(MAX_REQUEST_WINDOW_MS, |ttl| ttl.min(MAX_REQUEST_WINDOW_MS));
    now.checked_add(window)
}

/// When an approval granted at `now` for `life_s` seconds expires; `None`
/// past the clock's range -- refused, never wrapped.
fn approval_deadline(now: u64, life_s: u64) -> Option<u64> {
    life_s
        .checked_mul(1000)
        .and_then(|life| now.checked_add(life))
}

/// Whether a run holding `in_run` pending requests, in a store holding
/// `in_store`, may hold one more.
const fn room(in_run: i64, in_store: i64) -> bool {
    in_run < MAX_PENDING_PER_RUN && in_store < MAX_PENDING
}

/// How many requests still wait -- pending and inside their window -- in
/// `run`, or in the store: a request whose window has passed waits for
/// nothing, whether or not a later transaction has ended it yet.
fn waiting(work: &Work<'_>, run: Option<&RunId>, now: u64) -> Result<i64, AuthorityError> {
    let now = to_sql(now)?;
    match run {
        Some(run) => work.db(work.tx.query_row(
            "SELECT count(*) FROM approval_request WHERE run_id = ?1 AND state = 'PENDING'              AND not_after_ms > ?2",
            rusqlite::params![run.as_str(), now],
            |row| row.get(0),
        )),
        None => work.db(work.tx.query_row(
            "SELECT count(*) FROM approval_request WHERE state = 'PENDING' AND not_after_ms > ?1",
            [now],
            |row| row.get(0),
        )),
    }
}

/// Record a pending request for a launch denied `REQUIRE_APPROVAL`, unless
/// its run already waits on this binding, or holds as many as it may.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be written.
pub(super) fn request(
    work: &mut Work<'_>,
    considered: &Considered,
) -> Result<Requested, AuthorityError> {
    let now = advance(work)?;
    expire_requests(work, &considered.run, now)?;
    let hash = considered.binding.binding_hash().to_hex();
    let pending: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT request_id FROM approval_request \
             WHERE run_id = ?1 AND binding_sha256 = ?2 AND state = 'PENDING'",
            rusqlite::params![considered.run.as_str(), hash],
            |row| row.get(0),
        )
        .optional())?;
    if pending.is_some() {
        return Ok(Requested::Pending);
    }
    let in_run = waiting(work, Some(&considered.run), now)?;
    let in_store = waiting(work, None, now)?;
    if !room(in_run, in_store) {
        return Ok(Requested::Exhausted);
    }
    let seq: i64 = work.db(work.tx.query_row(
        "SELECT count(*) FROM approval_request WHERE run_id = ?1 AND binding_sha256 = ?2",
        rusqlite::params![considered.run.as_str(), hash],
        |row| row.get(0),
    ))?;
    let seq = u64::try_from(seq).map_err(|_| AuthorityError::Invariant("a negative count"))?;
    let id = DomainHash::new(digest::APPROVAL_REQUEST)
        .text(considered.run.as_str())
        .text(&hash)
        .int(seq)
        .finish()
        .to_hex();
    let not_after = request_deadline(now, considered.ttl_s).ok_or(AuthorityError::Invariant(
        "a request window past the clock's range",
    ))?;
    work.shared.crash(CrashPoint::ApprovalBeforeRequest)?;
    work.db(work.tx.execute(
        "INSERT INTO approval_request (request_id, run_id, session_id, requester, epoch, \
         incarnation, idempotency_key, binding_schema, binding_sha256, binding, scope, ttl_s, \
         max_uses, assurance_required, policy_revision, rule_id, requested_ms, not_after_ms, \
         state, decided_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'exact_action', \
         ?11, ?12, 'A1', ?13, ?14, ?15, ?16, 'PENDING', NULL)",
        rusqlite::params![
            id,
            considered.run.as_str(),
            considered.session.as_str(),
            considered.subject,
            to_sql(considered.epoch)?,
            to_sql(considered.incarnation)?,
            considered.key,
            super::binding::SCHEMA,
            hash,
            considered.binding.canonical_bytes(),
            considered.ttl_s,
            considered.max_uses,
            considered.policy_revision.to_hex(),
            considered.rule_id,
            to_sql(now)?,
            to_sql(not_after)?,
        ],
    ))?;
    let fields = Fields::new()
        .text("request_id", id.as_str())
        .text("run_id", considered.run.as_str())
        .text("requester", considered.subject.as_str())
        .text("binding_sha256", hash)
        .text("scope", "exact_action")
        .int("ttl_s", u64::from(considered.ttl_s))
        .int("max_uses", u64::from(considered.max_uses))
        .text("assurance_required", Assurance::A1.as_str())
        .text("rule_id", considered.rule_id.as_str())
        .text("policy_revision", considered.policy_revision.to_hex())
        .int("not_after_ms", not_after);
    work.audit(AuditEvent::ApprovalRequested, fields)?;
    Ok(Requested::Recorded)
}

/// Spend one use of the approval [`consider`] found, on the intent the
/// launch has just recorded -- in that intent's transaction, after it, so
/// that neither commits without the other. The database counts the use and,
/// at `max_uses`, ends the approval `EXHAUSTED`; it refuses a use that is
/// not of an open, unexpired approval of the intent's own run.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be written, or a use the
/// database refuses -- which no guarded launch reaches, and which rolls the
/// intent back with it.
pub(super) fn consume(
    work: &mut Work<'_>,
    considered: &Considered,
    invocation: &InvocationId,
) -> Result<(), AuthorityError> {
    let Some(candidate) = &considered.spendable else {
        return Err(AuthorityError::Invariant(
            "an approval was consumed with nothing to spend",
        ));
    };
    let now = advance(work)?;
    work.shared.crash(CrashPoint::ApprovalBeforeUse)?;
    let hash = considered.binding.binding_hash().to_hex();
    work.db(work.tx.execute(
        "INSERT INTO approval_use (approval_id, seq, invocation_id, run_id, action_sha256, \
         used_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            candidate.approval_id,
            candidate.seq,
            invocation.as_str(),
            considered.run.as_str(),
            hash,
            to_sql(now)?,
        ],
    ))?;
    let seq = u64::try_from(candidate.seq).unwrap_or(0);
    let fields = Fields::new()
        .text("approval_id", candidate.approval_id.as_str())
        .text("request_id", candidate.request_id.as_str())
        .text("invocation_id", invocation.as_str())
        .text("run_id", considered.run.as_str())
        .text("binding_sha256", hash)
        .text("approver", candidate.approver.as_str())
        .text("assurance", Assurance::A1.as_str())
        .text("policy_revision", considered.policy_revision.to_hex())
        .int("use", seq)
        .int("max_uses", u64::try_from(candidate.max_uses).unwrap_or(0));
    work.audit(AuditEvent::ApprovalUsed, fields)
}

/// What an approver decided on a request. Built by M6.3's approver
/// operations from the approver endpoint's kernel report; in this build, by
/// tests alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(all(test, target_os = "linux")),
    expect(
        dead_code,
        reason = "M6.3's approver operations build the first production decision"
    )
)]
pub(crate) enum ApproverDecision {
    /// Granted, at a level.
    Grant {
        /// The approver, as the kernel reported them.
        approver: AuthenticatedSubject,
        /// The level the decision carries.
        assurance: Assurance,
    },
    /// Denied.
    Deny {
        /// The approver, as the kernel reported them.
        approver: AuthenticatedSubject,
    },
}

/// Why a decision was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionRefused {
    /// No such request.
    UnknownRequest,
    /// Decided already, or expired: a decision is recorded once.
    NotPending,
    /// The request's window has passed; it is ended `EXPIRED`.
    Expired,
    /// The request's run no longer holds its authority; it is ended
    /// `EXPIRED`: no approval is recorded for authority that has ended.
    RunEnded,
    /// Not one of the operator's approvers.
    UnknownApprover,
    /// The approver is the requester.
    SelfApproval,
    /// An A2 decision, or a request that needs A2: no presence factor exists.
    AssuranceUnavailable,
}

/// A pending request, as a decision reads it.
#[derive(Debug, Clone)]
struct Pending {
    run: String,
    requester: String,
    state: String,
    asked_ms: u64,
    not_after: u64,
    life_s: u64,
    max_uses: i64,
    needed: String,
}

fn pending(work: &Work<'_>, request: &str) -> Result<Option<Pending>, AuthorityError> {
    let row = work.db(work
        .tx
        .query_row(
            "SELECT run_id, requester, state, requested_ms, not_after_ms, ttl_s, max_uses, \
             assurance_required FROM approval_request WHERE request_id = ?1",
            [request],
            |row| {
                Ok((
                    (
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ),
                    (
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                    ),
                ))
            },
        )
        .optional())?;
    let Some(((run, requester, state), (asked_ms, not_after, life_s, max_uses, needed))) = row
    else {
        return Ok(None);
    };
    let malformed = || AuthorityError::Invariant("a stored request is malformed");
    Ok(Some(Pending {
        run,
        requester,
        state,
        asked_ms: u64::try_from(asked_ms).map_err(|_| malformed())?,
        not_after: u64::try_from(not_after).map_err(|_| malformed())?,
        life_s: u64::try_from(life_s).map_err(|_| malformed())?,
        max_uses,
        needed,
    }))
}

/// Record an approver's decision on a pending request: an approval, with
/// its life and use limit from the request, or a denial. M6.3's seam; no
/// production caller in M6.2.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be written.
pub(super) fn decide(
    work: &mut Work<'_>,
    request: &str,
    decision: ApproverDecision,
) -> Result<Result<Option<String>, DecisionRefused>, AuthorityError> {
    let now = advance(work)?;
    let Some(pending) = pending(work, request)? else {
        return Ok(Err(DecisionRefused::UnknownRequest));
    };
    if pending.state != "PENDING" {
        return Ok(Err(DecisionRefused::NotPending));
    }
    if now >= pending.not_after {
        expire_request(work, request, &pending.run, now, "WINDOW")?;
        return Ok(Err(DecisionRefused::Expired));
    }
    if !run_active(work, &pending.run)? {
        expire_request(work, request, &pending.run, now, "RUN_ENDED")?;
        return Ok(Err(DecisionRefused::RunEnded));
    }
    let approver = match decision {
        ApproverDecision::Grant { approver, .. } | ApproverDecision::Deny { approver } => approver,
    };
    let approver = approver.storage_key();
    if !approver_known(work, &approver) {
        return Ok(Err(DecisionRefused::UnknownApprover));
    }
    if approver == pending.requester {
        return Ok(Err(DecisionRefused::SelfApproval));
    }
    match decision {
        ApproverDecision::Deny { .. } => {
            deny(work, request, &pending, &approver, now)?;
            Ok(Ok(None))
        }
        ApproverDecision::Grant { assurance, .. } => {
            if assurance != Assurance::A1 || pending.needed != Assurance::A1.as_str() {
                return Ok(Err(DecisionRefused::AssuranceUnavailable));
            }
            grant(work, request, &pending, &approver, now).map(|id| Ok(Some(id)))
        }
    }
}

/// End a pending request `DENIED`, audited.
fn deny(
    work: &mut Work<'_>,
    request: &str,
    pending: &Pending,
    approver: &str,
    now: u64,
) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "UPDATE approval_request SET state = 'DENIED', decided_ms = ?2 \
         WHERE request_id = ?1 AND state = 'PENDING'",
        rusqlite::params![request, to_sql(now)?],
    ))?;
    let fields = Fields::new()
        .text("request_id", request)
        .text("run_id", pending.run.as_str())
        .text("approver", approver)
        .text("channel", CHANNEL);
    work.audit(AuditEvent::ApprovalDenied, fields)
}

/// Record an A1 approval of a pending request -- its life the request's
/// TTL from now, its use limit the request's -- and end the request
/// `GRANTED`, audited. The approval's id is the request's, hashed: one
/// request, one approval, ever.
fn grant(
    work: &mut Work<'_>,
    request: &str,
    pending: &Pending,
    approver: &str,
    now: u64,
) -> Result<String, AuthorityError> {
    let not_after = approval_deadline(now, pending.life_s).ok_or(AuthorityError::Invariant(
        "an approval's life past the clock's range",
    ))?;
    let id = DomainHash::new(digest::APPROVAL)
        .text(request)
        .finish()
        .to_hex();
    work.db(work.tx.execute(
        "INSERT INTO approval (approval_id, request_id, approver, channel, assurance, \
         granted_ms, not_after_ms, max_uses, uses, state, ended_ms, ended_reason) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 'OPEN', NULL, NULL)",
        rusqlite::params![
            id,
            request,
            approver,
            CHANNEL,
            Assurance::A1.as_str(),
            to_sql(now)?,
            to_sql(not_after)?,
            pending.max_uses,
        ],
    ))?;
    work.db(work.tx.execute(
        "UPDATE approval_request SET state = 'GRANTED', decided_ms = ?2 \
         WHERE request_id = ?1 AND state = 'PENDING'",
        rusqlite::params![request, to_sql(now)?],
    ))?;
    let fields = Fields::new()
        .text("approval_id", id.as_str())
        .text("request_id", request)
        .text("run_id", pending.run.as_str())
        .text("approver", approver)
        .text("channel", CHANNEL)
        .text("assurance", Assurance::A1.as_str())
        .int("not_after_ms", not_after)
        .int("max_uses", u64::try_from(pending.max_uses).unwrap_or(0))
        .int("latency_ms", now.saturating_sub(pending.asked_ms));
    work.audit(AuditEvent::ApprovalGranted, fields)?;
    Ok(id)
}

/// End an open approval `REVOKED`, audited. `false` if it was not open.
///
/// # Errors
///
/// [`AuthorityError`] for a store that cannot be written.
pub(super) fn revoke(
    work: &mut Work<'_>,
    approval: &str,
    reason: &'static str,
) -> Result<bool, AuthorityError> {
    let now = advance(work)?;
    let ended = work.db(work.tx.execute(
        "UPDATE approval SET state = 'REVOKED', ended_ms = ?2, ended_reason = ?3 \
         WHERE approval_id = ?1 AND state = 'OPEN'",
        rusqlite::params![approval, to_sql(now)?, reason],
    ))?;
    if ended != 1 {
        return Ok(false);
    }
    let fields = Fields::new()
        .text("approval_id", approval)
        .text("reason", reason);
    work.audit(AuditEvent::ApprovalRevoked, fields)?;
    Ok(true)
}

impl Authority {
    /// Attach the approvers an approval may be decided by and spent under.
    /// **Test-only in M6.2** -- the Linux route tests', its one caller: no
    /// production path attaches a set, so in the shipped build no approval can
    /// be decided or spent. M6.3 attaches the approver endpoint's set under a
    /// decision of its own.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn attach_approvers(&self, uids: &[u32]) -> bool {
        self.shared.attachments.approvers.set(uids.to_vec()).is_ok()
    }

    /// Record an approver's decision on a pending request ([`decide`]), in
    /// one transaction. M6.3's seam: no production caller in M6.2.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] for a store that cannot be written.
    #[cfg_attr(
        not(all(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "M6.3's approver operations are its first production caller"
        )
    )]
    pub(crate) fn decide_approval(
        &mut self,
        request: &str,
        decision: ApproverDecision,
    ) -> Result<Result<Option<String>, DecisionRefused>, AuthorityError> {
        self.transact(|work| decide(work, request, decision))
    }

    /// Revoke an open approval ([`revoke`]): an end of authority, serialised
    /// with every effect already decided (ADR-0064's gate). A use already
    /// committed stands, and its effect goes on; no use begins after.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] for a store that cannot be written, or a gate past
    /// its wait.
    #[cfg_attr(
        not(all(test, target_os = "linux")),
        expect(
            dead_code,
            reason = "M6.3's operator revocation is its first production caller"
        )
    )]
    pub(crate) fn revoke_approval(&mut self, approval: &str) -> Result<bool, AuthorityError> {
        let ending = self.shared.gate.ending()?;
        let revoked = self.transact(|work| revoke(work, approval, "REVOKED"));
        drop(ending);
        revoked
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]

    use dwk_proto::wire::id::SessionId;
    use dwk_proto::wire::scalar::Epoch;

    use super::{
        Assurance, MAX_PENDING, MAX_PENDING_PER_RUN, MAX_REQUEST_WINDOW_MS, Open, Tenure,
        approval_deadline, passes, request_deadline, required, room,
    };
    use crate::policy::testing::{
        executable_capability, on_host, path_capability, sandboxed, syntactic_capability,
    };

    #[test]
    fn the_a2_classes_are_the_host_a_credential_and_a_deletion() {
        let exec = || executable_capability("process.exec", &["usr", "bin", "git"], 7);
        assert_eq!(required(&sandboxed(exec()), false), Assurance::A1);
        assert_eq!(
            required(&on_host(exec()), false),
            Assurance::A2,
            "host execution"
        );
        assert_eq!(
            required(&sandboxed(exec()), true),
            Assurance::A2,
            "a credential injected"
        );
        let delete = path_capability("fs.delete", &["workspace", "a"]);
        assert_eq!(
            required(&sandboxed(delete), false),
            Assurance::A2,
            "a deletion"
        );
        let secret = syntactic_capability("secret.use:gh-token");
        assert_eq!(
            required(&sandboxed(secret), false),
            Assurance::A2,
            "a credential's use"
        );
        // ADR-0078 §1 as written: every fs and net.http action is decided on
        // the host, so each is an A2 class -- and so not approvable in M6.
        let write = path_capability("fs.write", &["workspace", "a"]);
        assert_eq!(required(&on_host(write), false), Assurance::A2);
        let https = syntactic_capability("network.https:api.example.com");
        assert_eq!(required(&on_host(https), false), Assurance::A2);
    }

    #[test]
    fn a_deadline_past_the_clocks_range_is_refused_never_wrapped() {
        assert_eq!(request_deadline(1_000, 60), Some(61_000));
        assert_eq!(
            request_deadline(1_000, 3_600),
            Some(1_000 + MAX_REQUEST_WINDOW_MS),
            "ten minutes at most"
        );
        assert_eq!(request_deadline(u64::MAX - 1, 1), None);
        assert_eq!(request_deadline(u64::MAX, u32::MAX), None);
        assert_eq!(approval_deadline(1_000, 3_600), Some(3_601_000));
        assert_eq!(approval_deadline(u64::MAX - 999, 1), None);
        assert_eq!(
            approval_deadline(0, u64::MAX),
            None,
            "seconds to milliseconds"
        );
    }

    #[test]
    fn the_pending_bounds_are_the_runs_and_the_stores() {
        assert!(room(0, 0));
        assert!(room(MAX_PENDING_PER_RUN - 1, MAX_PENDING - 1));
        assert!(!room(MAX_PENDING_PER_RUN, 0), "the run's bound");
        assert!(!room(0, MAX_PENDING), "the store's bound");
        assert_eq!((MAX_PENDING_PER_RUN, MAX_PENDING), (16, 1024));
    }

    const REVISION: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn open(session: &SessionId) -> Open {
        Open {
            approval_id: "a".repeat(64),
            request_id: "b".repeat(64),
            approver: "uid:2001".to_owned(),
            assurance: "A1".to_owned(),
            not_after: 10,
            uses: 0,
            max_uses: 1,
            requester: "uid:1000".to_owned(),
            session: session.as_str().to_owned(),
            epoch: 3,
            incarnation: 2,
            policy_revision: REVISION.to_owned(),
            binding: b"{}".to_vec(),
            assurance_required: "A1".to_owned(),
        }
    }

    /// A version-7 UUID, `n` in its random bits.
    fn v7(n: u64) -> u128 {
        let n = u128::from(n);
        (u128::from(1_760_000_000_000_u64) << 80) | (0x7 << 76) | (0b10 << 62) | n
    }

    #[test]
    fn every_spend_guard_refuses_on_its_own() {
        let session = SessionId::from_uuid(v7(1)).unwrap();
        let other = SessionId::from_uuid(v7(2)).unwrap();
        let tenure = Tenure {
            subject: "uid:1000",
            session: &session,
            epoch: Epoch::new(3).unwrap(),
            incarnation: 2,
        };
        let base = open(&session);
        assert!(passes(&base, b"{}", &tenure, REVISION), "every guard holds");
        let cases = [
            (
                "requester",
                Open {
                    requester: "uid:1001".to_owned(),
                    ..base.clone()
                },
            ),
            (
                "session",
                Open {
                    session: other.as_str().to_owned(),
                    ..base.clone()
                },
            ),
            (
                "epoch",
                Open {
                    epoch: 4,
                    ..base.clone()
                },
            ),
            (
                "incarnation",
                Open {
                    incarnation: 3,
                    ..base.clone()
                },
            ),
            (
                "policy revision",
                Open {
                    policy_revision: "2".repeat(64),
                    ..base.clone()
                },
            ),
            (
                "binding",
                Open {
                    binding: b"{ }".to_vec(),
                    ..base.clone()
                },
            ),
            (
                "self-approval",
                Open {
                    approver: "uid:1000".to_owned(),
                    ..base.clone()
                },
            ),
            (
                "assurance A2",
                Open {
                    assurance: "A2".to_owned(),
                    ..base.clone()
                },
            ),
            (
                "assurance A0",
                Open {
                    assurance: "A0".to_owned(),
                    ..base.clone()
                },
            ),
            (
                "an A2 request",
                Open {
                    assurance_required: "A2".to_owned(),
                    ..base.clone()
                },
            ),
            (
                "exhausted",
                Open {
                    uses: 1,
                    ..base.clone()
                },
            ),
            (
                "past its count",
                Open {
                    uses: 2,
                    ..base.clone()
                },
            ),
        ];
        for (name, refused) in cases {
            assert!(!passes(&refused, b"{}", &tenure, REVISION), "{name}");
        }
        assert!(!passes(&base, b"{ }", &tenure, REVISION), "another binding");
        assert!(
            !passes(&base, b"{}", &tenure, &"2".repeat(64)),
            "another policy"
        );
        for (name, tenure) in [
            (
                "another subject",
                Tenure {
                    subject: "uid:1001",
                    ..tenure
                },
            ),
            (
                "another session",
                Tenure {
                    session: &other,
                    ..tenure
                },
            ),
            (
                "another epoch",
                Tenure {
                    epoch: Epoch::new(4).unwrap(),
                    ..tenure
                },
            ),
            (
                "another incarnation",
                Tenure {
                    incarnation: 3,
                    ..tenure
                },
            ),
        ] {
            assert!(!passes(&base, b"{}", &tenure, REVISION), "{name}");
        }
    }
}
