//! `QueryAuthority`: effective authority, and both gates for an action the
//! authority can describe completely.
//!
//! # First, the state checks
//!
//! The fence (lease, holder, epoch, expiry), then the run: it must exist, be
//! **active**, belong to this caller's subject and session, and be fenced to
//! the presented epoch. A run that fails any of these is `UNKNOWN_RUN` — one
//! answer for "never existed", "released", "reaped" and "someone else's", so
//! the refusal is not a probe for which run ids are real.
//!
//! # Then, a proposal — decided only if it is a complete canonical action
//!
//! Policy decides on a canonical action ([`POLICY.md`] §1 rule 3): a resolved
//! capability **and** every fact a rule may read about it — where it runs, the
//! address it reaches, whether that is new to the run, how its argv would be
//! interpreted, how many bytes it moves. Capability text carries none of those
//! facts, and M3c reads an absent fact as "does not match", which silently
//! switches off a `DENY` rule keyed on it. So a [`Proposal::Text`] — what
//! `QueryAuthority.proposed` carries — is **never** decided: it is refused with
//! `NO_CANONICAL_ACTION`, no policy rule runs, and no rule is attributed
//! ([ADR-0040]). The audit record keeps the kernel's own reason
//! ([`Undecidable`]) for an operator.
//!
//! A [`Proposal::Action`] is a complete canonical action another kernel
//! component built. It is the entry M4's canonicaliser will use; in M3d only
//! tests call it, standing in for that component, and no DWKP message reaches
//! it. For one, both gates run, independently, always ([ADR-0006]):
//!
//! ```text
//! capability gate:  the run's effective grant set covers the action
//! policy gate:      M3c evaluate(active policy, action, kernel-built context)
//! ALLOW             iff both
//! ```
//!
//! Neither is skipped because the other refused, and neither result is
//! derived from the other. Policy's three-valued effect is kept internally;
//! `REQUIRE_APPROVAL` fails the policy gate, because nothing in this build can
//! obtain an approval — `wire` maps it to `DENY` and keeps the rule that asked.
//!
//! # The context is built here, from `kernel.db`, and nowhere else
//!
//! [`policy_context`] reads the run's `run_policy_input` row — origin, taint,
//! privacy — and the activation's configuration flags. There is no constructor
//! from a request, from JSON, or from anything the runtime sends. Path anchors
//! stay unresolved: they are canonical paths, and only `crate::resource` may
//! create one (ADR-0037).
//!
//! # Read-only, as a decision
//!
//! A query grants nothing, changes no capability and touches no resource. It
//! appends an audit record of the decision or the refusal, which is
//! bookkeeping about the question and not a change to authority.
//!
//! [ADR-0006]: ../../../../../docs/adr/0006-policy-and-capability-boundary.md
//! [ADR-0040]: ../../../../../docs/adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use core::fmt;

use dwk_proto::wire::id::{CapId, RunId, SessionId};
use dwk_proto::wire::scalar::{CapabilityText, Epoch, RefusalReason, RefusedOperation};
use rusqlite::OptionalExtension as _;

use crate::capability::{self, Capability, PrivacyClass, UnresolvedScope};
use crate::policy::{
    self, CanonicalAction, Decision, Effect, IpAddress, Origin, PolicyContext, TaintLevel,
};

use super::admission::{self, Admission, taint_from_rank, taint_rank};
use super::audit::{AuditEvent, Fields};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::policy_state::ActiveAuthority;
use super::{Reply, Work};

/// What a query asks to have decided.
#[derive(Debug, Clone, Copy)]
pub enum Proposal<'a> {
    /// A capability in the wire grammar — `QueryAuthority.proposed`. Never
    /// decided: capability text does not determine a canonical action, so
    /// this is always refused with `NO_CANONICAL_ACTION` (ADR-0040).
    Text(&'a CapabilityText),
    /// A complete canonical action another kernel component built — the entry
    /// point M4's canonicaliser will use. **Nothing on the M3d wire path
    /// produces one**; tests stand in for that component.
    Action(&'a CanonicalAction),
}

/// Why a [`Proposal::Text`] could not be decided. Kept in the audit record;
/// the wire carries one reason, because the caller has one remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undecidable {
    /// The capability names a verb, scope type or constraint outside the
    /// kernel's vocabulary. No canonical action exists for it.
    UnknownVocabulary,
    /// The capability names an `fs` or `process` resource, whose identity
    /// only M4's canonicaliser can derive (ADR-0037).
    UnresolvedResource(UnresolvedScope),
    /// The capability resolves, but the action depends on facts the request
    /// cannot carry — where it would run, and, by family, the address it
    /// reaches or whether that destination is new to the run.
    ActionFactsUnavailable,
}

impl Undecidable {
    /// Classify a proposal. Pure; decides nothing.
    #[must_use]
    pub fn of(text: &CapabilityText) -> Self {
        match capability::parse(text.as_str()) {
            Err(_) => Self::UnknownVocabulary,
            Ok(spec) => match spec.resolve() {
                Err(scope) => Self::UnresolvedResource(scope),
                Ok(_) => Self::ActionFactsUnavailable,
            },
        }
    }

    /// The audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownVocabulary => "unknown_vocabulary",
            Self::UnresolvedResource(_) => "unresolved_resource",
            Self::ActionFactsUnavailable => "action_facts_unavailable",
        }
    }
}

impl fmt::Display for Undecidable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedResource(scope) => write!(f, "{}: {scope}", self.as_str()),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Both gates' results for one complete canonical action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    required: Capability,
    covering: Option<CapId>,
    policy: Decision,
    destination_ip: Option<IpAddress>,
}

impl DecisionRecord {
    /// The capability the action requires.
    #[must_use]
    pub const fn required(&self) -> &Capability {
        &self.required
    }

    /// Gate one: whether a held grant covers the action.
    #[must_use]
    pub const fn capability_satisfied(&self) -> bool {
        self.covering.is_some()
    }

    /// The grant that covers it, if one does.
    #[must_use]
    pub const fn covering_grant(&self) -> Option<&CapId> {
        self.covering.as_ref()
    }

    /// Gate two: M3c's decision, three-valued and with its rule.
    #[must_use]
    pub const fn policy(&self) -> &Decision {
        &self.policy
    }

    /// Whether policy permits it. `REQUIRE_APPROVAL` does not: no approval
    /// can be obtained in this build.
    #[must_use]
    pub fn policy_satisfied(&self) -> bool {
        self.policy.effect() == Effect::Allow
    }

    /// The final answer: both gates, never one.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.capability_satisfied() && self.policy_satisfied()
    }

    /// The destination address policy evaluated, if the action had one. This
    /// is the evidence M4 needs to hold the connection to the address that
    /// was decided; **M3d binds nothing** and makes no DNS-rebinding claim.
    #[must_use]
    pub const fn destination_ip(&self) -> Option<IpAddress> {
        self.destination_ip
    }
}

/// A run's effective authority, and a decision if a complete canonical action
/// was proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityAnswer {
    admission: Admission,
    decision: Option<DecisionRecord>,
}

impl AuthorityAnswer {
    /// The admission the run holds.
    #[must_use]
    pub const fn admission(&self) -> &Admission {
        &self.admission
    }

    /// The decision, present exactly when a [`Proposal::Action`] was made.
    #[must_use]
    pub const fn decision(&self) -> Option<&DecisionRecord> {
        self.decision.as_ref()
    }
}

/// What caused taint to rise. Closed; each variant names the future producer
/// that will call [`raise_taint`], none of which exists in M3d.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintCause {
    /// A tool result the kernel delivered (M4 onward).
    ToolResult,
    /// An artifact the run read (M12).
    ArtifactRead,
    /// A memory item retrieved into the run (M13).
    MemoryRetrieval,
}

impl TaintCause {
    /// The audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolResult => "tool_result",
            Self::ArtifactRead => "artifact_read",
            Self::MemoryRetrieval => "memory_retrieval",
        }
    }
}

impl fmt::Display for TaintCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the run's `PolicyContext` from kernel-owned state. The only way one
/// is built for a live decision.
pub(super) fn policy_context(
    work: &Work<'_>,
    run: &str,
    active: &ActiveAuthority,
) -> Result<PolicyContext, AuthorityError> {
    let (origin, taint, privacy): (String, i64, String) = work
        .db(work
            .tx
            .query_row(
                "SELECT origin, taint, privacy FROM run_policy_input WHERE run_id = ?1",
                [run],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional())?
        .ok_or(AuthorityError::Invariant("a run has no policy inputs"))?;
    let origin =
        Origin::parse(&origin).ok_or(AuthorityError::Invariant("a stored origin is malformed"))?;
    let taint =
        taint_from_rank(taint).ok_or(AuthorityError::Invariant("a stored taint is malformed"))?;
    let privacy = PrivacyClass::parse(&privacy).ok_or(AuthorityError::Invariant(
        "a stored privacy class is malformed",
    ))?;
    Ok(PolicyContext::new(origin, taint)
        .with_privacy(privacy)
        .with_config(active.flags))
}

fn refuse(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    epoch: Epoch,
    reason: RefusalReason,
    extra: Fields,
) -> Result<Reply<AuthorityAnswer>, AuthorityError> {
    let mut fields = lease::refusal_fields(
        caller,
        RefusedOperation::QueryAuthority,
        reason,
        session,
        Some(epoch),
    );
    fields.extend(extra);
    work.audit(AuditEvent::QueryRefused, fields)?;
    Ok(Reply::Refused(reason))
}

/// `QueryAuthority`.
pub(super) fn query(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    proposal: Option<Proposal<'_>>,
    active: &ActiveAuthority,
) -> Result<Reply<AuthorityAnswer>, AuthorityError> {
    if !lease::fence(work, caller, session, epoch)? {
        return refuse(
            work,
            caller,
            session,
            epoch,
            RefusalReason::StaleEpoch,
            Fields::new(),
        );
    }
    let subject = caller.subject().storage_key();
    let activation: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT activation_id FROM run WHERE run_id = ?1 AND session_id = ?2 \
                 AND subject = ?3 AND epoch = ?4 AND state = 'ACTIVE'",
            rusqlite::params![
                run.as_str(),
                session.as_str(),
                subject,
                to_sql(epoch.get())?
            ],
            |row| row.get(0),
        )
        .optional())?;
    let Some(activation) = activation else {
        return refuse(
            work,
            caller,
            session,
            epoch,
            RefusalReason::UnknownRun,
            Fields::new(),
        );
    };
    if activation != active.activation_id {
        // Every restart reaps every active run, so a live run always belongs
        // to this incarnation's activation. One that does not is a store that
        // contradicts itself.
        return Err(AuthorityError::Invariant(
            "a live run belongs to an activation that is not in force",
        ));
    }
    let admission = admission::load(work, run.as_str())?;
    let action = match proposal {
        None => {
            return Ok(Reply::Done(AuthorityAnswer {
                admission,
                decision: None,
            }));
        }
        // Capability text never determines a canonical action. Refused, with
        // no rule run and no rule attributed (ADR-0040 part 2).
        Some(Proposal::Text(text)) => {
            let why = Undecidable::of(text);
            let mut extra = Fields::new()
                .text("run_id", run.as_str())
                .text("proposed", text.as_str())
                .text("undecidable", why.as_str());
            if let Undecidable::UnresolvedResource(scope) = why {
                extra = extra.text("unresolved", scope.to_string());
            }
            return refuse(
                work,
                caller,
                session,
                epoch,
                RefusalReason::NoCanonicalAction,
                extra,
            );
        }
        Some(Proposal::Action(action)) => action,
    };

    let context = policy_context(work, run.as_str(), active)?;
    let record = decide(action, &admission, &context, active);
    audit_decision(work, caller, session, run, epoch, active, &record)?;
    Ok(Reply::Done(AuthorityAnswer {
        admission,
        decision: Some(record),
    }))
}

/// Both gates. Neither consults the other.
fn decide(
    action: &CanonicalAction,
    admission: &Admission,
    context: &PolicyContext,
    active: &ActiveAuthority,
) -> DecisionRecord {
    let covering = admission
        .granted()
        .iter()
        .find(|grant| grant.capability().contains(action.capability()))
        .map(|grant| grant.cap_id().clone());
    let decision = policy::evaluate(&active.compiled, action, context);
    DecisionRecord {
        required: action.capability().clone(),
        covering,
        policy: decision,
        destination_ip: action.destination_ip(),
    }
}

fn audit_decision(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    active: &ActiveAuthority,
    record: &DecisionRecord,
) -> Result<(), AuthorityError> {
    let fields = Fields::new()
        .text("subject", caller.subject().storage_key())
        .text("holder", caller.holder().to_string())
        .text("session_id", session.as_str())
        .text("run_id", run.as_str())
        .int("epoch", epoch.get())
        .text("policy_revision", active.revision.to_hex())
        .text("required_capability", record.required.to_canonical_string())
        .flag("capability_satisfied", record.capability_satisfied())
        .maybe_text(
            "covering_cap_id",
            record.covering.as_ref().map(|c| c.as_str().to_owned()),
        )
        .text("policy_effect", record.policy.effect().as_str())
        .flag("policy_satisfied", record.policy_satisfied())
        .text("rule_id", record.policy.rule_id().as_str())
        .text("rule_source", record.policy.rule_source().to_string())
        .text("reason", record.policy.reason().as_str())
        .maybe_text(
            "unevaluable",
            record.policy.unevaluable().map(|u| u.to_string()),
        )
        .maybe_text(
            "destination_ip",
            record.destination_ip.map(|ip| ip.to_string()),
        )
        .text("effect", if record.permits() { "ALLOW" } else { "DENY" });
    work.audit(AuditEvent::AuthorityDecision, fields)
}

/// Raise a run's taint to at least `observed`. Never lowers it: the result is
/// the more restrictive of the two, and a trigger refuses any write that
/// would decrease it. There is no clear, reset or set operation.
pub(super) fn raise_taint(
    work: &mut Work<'_>,
    run: &RunId,
    observed: TaintLevel,
    cause: TaintCause,
) -> Result<TaintLevel, AuthorityError> {
    let current: i64 = work
        .db(work
            .tx
            .query_row(
                "SELECT taint FROM run_policy_input WHERE run_id = ?1",
                [run.as_str()],
                |row| row.get(0),
            )
            .optional())?
        .ok_or(AuthorityError::Rejected(format!(
            "no run {} has policy inputs",
            run.as_str()
        )))?;
    let current =
        taint_from_rank(current).ok_or(AuthorityError::Invariant("a stored taint is malformed"))?;
    let raised = core::cmp::max(current, observed);
    if raised != current {
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
                .text("cause", cause.as_str()),
        )?;
    }
    Ok(raised)
}
