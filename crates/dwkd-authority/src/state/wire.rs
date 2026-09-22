//! Mapping internal outcomes onto the M3 wire — truthfully, or not at all.
//!
//! M3d has no transport. These functions are the boundary M3e will call: an
//! internal outcome in, a `dwk-proto` response body out. Every answer an M3
//! request can receive has a truthful wire form ([ADR-0040]): an admission's
//! withheld capabilities all have reasons, a proposal the authority cannot
//! describe as a complete canonical action is a refusal
//! (`NO_CANONICAL_ACTION`) rather than a decision, and an ended admission is a
//! refusal (`ADMISSION_ENDED`) rather than a replayed grant. [`WireGap`]
//! remains for one in-process case and for bugs, and there is no case where an
//! inaccurate value is chosen to fill a closed enum.
//!
//! # The decision mapping ([ADR-0036] §§9–10, [ADR-0040])
//!
//! A decision exists only for a complete canonical action, so every row names
//! the rule that produced the effect — never a stand-in:
//!
//! | capability gate | policy | wire `effect` | wire `reason` | rule reported |
//! |---|---|---|---|---|
//! | covered | `ALLOW` | `ALLOW` | `ALLOWED_BY_RULE` | the allowing rule |
//! | not covered | `ALLOW` | `DENY` | `NO_CAPABILITY` | the allowing rule |
//! | either | `DENY` by a rule | `DENY` | `DENIED_BY_RULE` | the denying rule or postcondition |
//! | either | `DENY` by `default` | `DENY` | `DEFAULT_DENY` | the policy's own mandatory `default` rule, which matched |
//! | either | `REQUIRE_APPROVAL` | `DENY` | `DENIED_BY_RULE` | the rule that required approval |
//! | — | a rule needed a value the action lacks | **gap** (in-process only) | — | — |
//!
//! `REQUIRE_APPROVAL` becomes `DENY` because an authority with no approval
//! registry cannot obtain one ([APPROVALS.md]: with no human present, approval
//! degrades to denial). The rule's own id and source travel with it, so the
//! refusal remains explicable as the approval rule it was. `REQUIRE_APPROVAL`
//! never appears on this wire; M6 adds it with a schema version.
//!
//! # The one remaining gap
//!
//! A rule that constrains a destination address, asked about an action that
//! carries none, denies internally with `UNRESOLVED_CANONICAL_INPUT`.
//! `DENIED_BY_RULE` would claim the rule matched and said deny. Only a
//! [`Proposal::Action`](super::Proposal::Action) can reach it — the in-process
//! entry M4's canonicaliser will use — because a wire proposal is refused
//! before any rule runs. It is therefore unreachable from any M3 request, and
//! M4, which supplies the address, owns it.
//!
//! [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
//! [ADR-0040]: ../../../../../docs/adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md
//! [APPROVALS.md]: ../../../../../docs/APPROVALS.md

use core::fmt;

use dwk_proto::dwkp::messages::{
    AuthorityDecision, AuthorityRefusal, CapabilityGrant, EffectiveAuthority, GrantSet, LeaseGrant,
    RunGrant, WithheldCapability, WithheldSet,
};
use dwk_proto::wire::id::SessionId;
use dwk_proto::wire::scalar::{
    CapabilityText, DecisionEffect, DecisionReason, Epoch, GateResult, PolicyRevision,
    RefusalReason, RefusedOperation, RuleId, RuleSource,
};

use crate::policy::{Effect, SourceLocation, Unevaluable};

use super::admission::Admission;
use super::query::{AuthorityAnswer, DecisionRecord};

/// What the M3 wire cannot say truthfully. Unreachable from any M3 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGap {
    /// A policy rule needed a canonical value the action did not carry. Only
    /// an in-process [`Proposal::Action`](super::Proposal::Action) reaches it.
    UnevaluablePolicyInput(Unevaluable),
    /// A kernel value does not fit the wire type that must carry it. A bug,
    /// never produced by a sound store.
    Unrepresentable(&'static str),
}

impl fmt::Display for WireGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnevaluablePolicyInput(what) => write!(
                f,
                "{what}: no M3 wire reason says this truthfully (M4 supplies it)"
            ),
            Self::Unrepresentable(what) => write!(f, "not representable on the wire: {what}"),
        }
    }
}

impl std::error::Error for WireGap {}

/// `LeaseGrant`.
#[must_use]
pub fn lease_grant(session: &SessionId, epoch: Epoch) -> LeaseGrant {
    LeaseGrant {
        session_id: session.clone(),
        epoch,
    }
}

/// `AuthorityRefusal`. The pairing of operation and reason is closed by the
/// decoder in both languages; every pair this module produces is in it, and
/// `tests/state_wire.rs` round-trips each one through the real decoder.
#[must_use]
pub const fn refusal(operation: RefusedOperation, reason: RefusalReason) -> AuthorityRefusal {
    AuthorityRefusal { operation, reason }
}

fn revision(admission: &Admission) -> Result<PolicyRevision, WireGap> {
    PolicyRevision::new(admission.policy_revision().to_hex())
        .ok_or(WireGap::Unrepresentable("policy revision"))
}

fn grants(admission: &Admission) -> Result<(GrantSet, WithheldSet), WireGap> {
    let granted = admission
        .granted()
        .iter()
        .map(|grant| {
            Ok(CapabilityGrant {
                cap_id: grant.cap_id().clone(),
                capability: CapabilityText::new(grant.capability().to_canonical_string())
                    .ok_or(WireGap::Unrepresentable("granted capability"))?,
            })
        })
        .collect::<Result<Vec<_>, WireGap>>()?;
    let withheld = admission
        .withheld()
        .iter()
        .map(|entry| WithheldCapability {
            capability: entry.requested().clone(),
            reason: entry.cause().to_wire(),
        })
        .collect::<Vec<_>>();
    Ok((
        GrantSet::new(granted).ok_or(WireGap::Unrepresentable("too many grants"))?,
        WithheldSet::new(withheld).ok_or(WireGap::Unrepresentable("too many withheld"))?,
    ))
}

/// `RunGrant`, for a first admission or its replay alike.
///
/// # Errors
///
/// [`WireGap::Unrepresentable`] only: a store value the wire type rejects.
pub fn run_grant(admission: &Admission) -> Result<RunGrant, WireGap> {
    let (granted, withheld) = grants(admission)?;
    Ok(RunGrant {
        run_id: admission.run_id().clone(),
        epoch: admission.epoch(),
        policy_revision: revision(admission)?,
        profile: admission.mode(),
        granted,
        withheld,
    })
}

fn rule(id: &str, at: &SourceLocation) -> Result<(RuleId, RuleSource), WireGap> {
    Ok((
        RuleId::new(id).ok_or(WireGap::Unrepresentable("rule id"))?,
        RuleSource::new(at.to_string()).ok_or(WireGap::Unrepresentable("rule source"))?,
    ))
}

const fn gate(satisfied: bool) -> GateResult {
    if satisfied {
        GateResult::Satisfied
    } else {
        GateResult::NotSatisfied
    }
}

/// `AuthorityDecision`, for a decision both gates made on a complete canonical
/// action. The rule reported is the rule M3c says produced the effect.
///
/// # Errors
///
/// [`WireGap::UnevaluablePolicyInput`] when a rule needed a value the action
/// did not carry; [`WireGap::Unrepresentable`] for a bug.
pub fn decision(record: &DecisionRecord) -> Result<AuthorityDecision, WireGap> {
    let policy = record.policy();
    if let Some(what) = policy.unevaluable() {
        return Err(WireGap::UnevaluablePolicyInput(what));
    }
    let reason = if record.permits() {
        DecisionReason::AllowedByRule
    } else if policy.effect() == Effect::Allow {
        DecisionReason::NoCapability
    } else if policy.rule_id().is_default() {
        DecisionReason::DefaultDeny
    } else {
        DecisionReason::DeniedByRule
    };
    let (rule_id, rule_source) = rule(policy.rule_id().as_str(), policy.rule_source())?;
    Ok(AuthorityDecision {
        effect: if record.permits() {
            DecisionEffect::Allow
        } else {
            DecisionEffect::Deny
        },
        reason,
        capability_result: gate(record.capability_satisfied()),
        policy_result: gate(record.policy_satisfied()),
        rule_id,
        rule_source,
        required_capability: CapabilityText::new(record.required().to_canonical_string())
            .ok_or(WireGap::Unrepresentable("required capability"))?,
    })
}

/// `EffectiveAuthority`, with the decision exactly when one was made.
///
/// # Errors
///
/// A gap in the decision (in-process proposals only), or a bug.
pub fn effective_authority(answer: &AuthorityAnswer) -> Result<EffectiveAuthority, WireGap> {
    let admission = answer.admission();
    let (granted, withheld) = grants(admission)?;
    Ok(EffectiveAuthority {
        run_id: admission.run_id().clone(),
        epoch: admission.epoch(),
        policy_revision: revision(admission)?,
        profile: admission.mode(),
        granted,
        withheld,
        decision: answer.decision().map(decision).transpose()?,
    })
}
