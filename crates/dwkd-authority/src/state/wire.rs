//! Mapping internal outcomes onto the M3 wire — truthfully, or not at all.
//!
//! These functions are the boundary the M3e server carries: an internal
//! outcome in, a `dwk-proto` response body out. The server adds the envelope
//! and nothing else. Every answer an M3
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

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::dwkp::fsops::{
    ActionDecision, CanonicalPreviewResultV2, PlannedAction as WireAction, PlannedActions,
    ToolDenialV2, ToolFailureV2, ToolPlan as WirePlan, ToolRefusalV2, ToolResultV2,
};
use dwk_proto::dwkp::messages::{
    AuthorityDecision, AuthorityRefusal, CanonicalPreviewResult, CapabilityGrant,
    EffectiveAuthority, GrantSet, LeaseGrant, RunGrant, ToolAction, ToolDecision, ToolDenial,
    ToolFailure, ToolRefusal, ToolResult, WithheldCapability, WithheldSet,
};
use dwk_proto::dwkp::procops::{
    CanonicalPreviewResultV3, ExecutableRef, PlannedActionV3, PlannedActionsV3,
    PlannedProcessAction, ProcessActionDecision, ProcessExecResult, ProcessKillResult,
    ProcessStatusResult, ProcessStreamSnapshot, ToolDenialV3, ToolFailureV3, ToolOutputV3,
    ToolPlanV3, ToolRefusalV3, ToolResultV3,
};
use dwk_proto::wire::id::SessionId;
use dwk_proto::wire::scalar::{
    ActionEnvironment, ByteCount, CapabilityText, DecisionEffect, DecisionReason, Epoch,
    FsDecisionReason, FsFailureReason, FsRefusalReason, FsTool, FsVerb, GateResult, PolicyRevision,
    ReadLimit, RefusalReason, RefusedOperation, RuleId, RuleSource, ToolDecisionReason,
    ToolFailureReason, ToolName, ToolRefusalReason, WorkspacePath,
};

use crate::policy::{Effect, SourceLocation, Unevaluable};

use super::admission::Admission;
use super::plan::{PlannedAction, ToolPlan};
use super::process::{ProcessOutput, ProcessPlan, ProcessReply, StreamSnapshot};
use super::query::{AuthorityAnswer, DecisionRecord};
use super::tool::ToolReply;

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

// ---------------------------------------------------------------------------
// Tool operations: version 1 (M4b, ADR-0043) and version 2 (M4c, ADR-0044).
//
// Every tool outcome has a truthful wire form, including the one the M3 table
// above calls a gap: a rule that could not be evaluated -- today, any rule
// naming `~`, which has no kernel-owned value yet -- is reported as
// `UNRESOLVED_POLICY_INPUT` with that rule's id, not dressed as a rule that
// matched.
//
// A request is answered in its own version. Version 1 is M4b's contract,
// exactly: one `fs.read`, one action. Its closed enumerations are not widened;
// the one M4c decision it has no word for -- a rule that allowed with an
// obligation this build cannot enforce -- is reported the way a
// `REQUIRE_APPROVAL` rule is: `DENY`, `DENIED_BY_RULE`, the policy gate not
// satisfied, attributed to that rule. Nothing a version-1 `fs.read` can reach
// lacks a version-1 spelling; anything else is a bug, and a gap.
// ---------------------------------------------------------------------------

/// A version-1 spelling of a version-2 value, found by its wire text: the two
/// enumerations share every version-1 member's spelling by construction.
fn v1_spelling<V: Copy, W: Copy>(
    value: V,
    spell: fn(V) -> &'static str,
    all: &'static [W],
    spelled: fn(W) -> &'static str,
) -> Option<W> {
    all.iter().copied().find(|w| spelled(*w) == spell(value))
}

/// The version-1 action of a one-action `fs.read` plan.
fn v1_action(plan: &ToolPlan) -> Result<(ToolAction, &PlannedAction), WireGap> {
    let gap = || WireGap::Unrepresentable("a version-1 tool plan");
    let [planned] = plan.actions() else {
        return Err(gap());
    };
    if plan.tool() != FsTool::FsRead || planned.verb() != FsVerb::FsRead {
        return Err(gap());
    }
    let byte_count = u32::try_from(planned.byte_count())
        .ok()
        .and_then(ReadLimit::new)
        .ok_or_else(gap)?;
    Ok((
        ToolAction {
            tool: ToolName::FsRead,
            canonical_path: WorkspacePath::new(planned.canonical_path().to_string())
                .ok_or(WireGap::Unrepresentable("canonical path"))?,
            byte_count,
            environment: ActionEnvironment::Host,
        },
        planned,
    ))
}

/// Both gates of one action, on the version-1 tool wire.
fn tool_decision(planned: &PlannedAction) -> Result<ToolDecision, WireGap> {
    let policy = planned.record().policy();
    let reason = match planned.reason() {
        FsDecisionReason::AllowedByRule => ToolDecisionReason::AllowedByRule,
        FsDecisionReason::UnresolvedPolicyInput => ToolDecisionReason::UnresolvedPolicyInput,
        FsDecisionReason::NoCapability => ToolDecisionReason::NoCapability,
        FsDecisionReason::DefaultDeny => ToolDecisionReason::DefaultDeny,
        FsDecisionReason::DeniedByRule | FsDecisionReason::ObligationUnenforceable => {
            ToolDecisionReason::DeniedByRule
        }
    };
    let (rule_id, rule_source) = rule(policy.rule_id().as_str(), policy.rule_source())?;
    Ok(ToolDecision {
        effect: if planned.permits() {
            DecisionEffect::Allow
        } else {
            DecisionEffect::Deny
        },
        reason,
        capability_result: gate(planned.record().capability_satisfied()),
        policy_result: gate(planned.policy_satisfied()),
        rule_id,
        rule_source,
    })
}

/// The response body for a version-1 tool operation's outcome.
///
/// # Errors
///
/// [`WireGap::Unrepresentable`] only for a value that does not fit its wire
/// type -- a bug, never a sound outcome of a version-1 request.
pub fn tool_reply(reply: &ToolReply) -> Result<DwkpBody, WireGap> {
    Ok(match reply {
        ToolReply::Done {
            invocation,
            plan,
            output,
        } => {
            let (action, planned) = v1_action(plan)?;
            DwkpBody::ToolResult(ToolResult {
                invocation_id: invocation.clone(),
                action,
                decision: tool_decision(planned)?,
                fs_read: output
                    .fs_read
                    .clone()
                    .ok_or(WireGap::Unrepresentable("a version-1 result"))?,
            })
        }
        ToolReply::Denied(plan) => {
            let (action, planned) = v1_action(plan)?;
            DwkpBody::ToolDenied(ToolDenial {
                action,
                decision: tool_decision(planned)?,
            })
        }
        ToolReply::Previewed(plan) => {
            let (action, planned) = v1_action(plan)?;
            DwkpBody::ToolPreviewed(CanonicalPreviewResult {
                action,
                decision: tool_decision(planned)?,
            })
        }
        ToolReply::Refused(operation, reason) => DwkpBody::ToolRefused(ToolRefusal {
            operation: *operation,
            reason: v1_spelling(
                *reason,
                FsRefusalReason::as_str,
                ToolRefusalReason::ALL,
                ToolRefusalReason::as_str,
            )
            .ok_or(WireGap::Unrepresentable("a version-1 refusal"))?,
        }),
        ToolReply::Failed { invocation, reason } => DwkpBody::ToolFailed(ToolFailure {
            invocation_id: invocation.clone(),
            reason: v1_spelling(
                *reason,
                FsFailureReason::as_str,
                ToolFailureReason::ALL,
                ToolFailureReason::as_str,
            )
            .ok_or(WireGap::Unrepresentable("a version-1 failure"))?,
        }),
    })
}

/// A plan on the version-2 wire: every action, each with both gates.
fn wire_plan(plan: &ToolPlan) -> Result<WirePlan, WireGap> {
    let mut actions = Vec::new();
    for planned in plan.actions() {
        let policy = planned.record().policy();
        let (rule_id, rule_source) = rule(policy.rule_id().as_str(), policy.rule_source())?;
        actions.push(WireAction {
            role: planned.role(),
            verb: planned.verb(),
            canonical_path: WorkspacePath::new(planned.canonical_path().to_string())
                .ok_or(WireGap::Unrepresentable("canonical path"))?,
            object: planned.object(),
            byte_count: ByteCount::new(planned.byte_count())
                .ok_or(WireGap::Unrepresentable("byte count"))?,
            decision: ActionDecision {
                effect: if planned.permits() {
                    DecisionEffect::Allow
                } else {
                    DecisionEffect::Deny
                },
                reason: planned.reason(),
                capability_result: gate(planned.record().capability_satisfied()),
                policy_result: gate(planned.policy_satisfied()),
                rule_id,
                rule_source,
            },
        });
    }
    Ok(WirePlan {
        tool: plan.tool(),
        environment: ActionEnvironment::Host,
        effect: if plan.permits() {
            DecisionEffect::Allow
        } else {
            DecisionEffect::Deny
        },
        actions: PlannedActions::new(actions).ok_or(WireGap::Unrepresentable("a plan"))?,
    })
}

/// The response body for a version-2 tool operation's outcome.
///
/// # Errors
///
/// [`WireGap::Unrepresentable`] only for a value that does not fit its wire
/// type -- a bug.
pub fn tool_reply_v2(reply: &ToolReply) -> Result<DwkpBody, WireGap> {
    tool_reply_v2_inner(reply)
}

/// A filesystem plan on the version-3 wire: the version-2 actions, each
/// wrapped as `{"fs": ...}` beside the process actions version 3 adds.
fn wire_plan_v3(plan: &ToolPlan) -> Result<ToolPlanV3, WireGap> {
    let v2 = wire_plan(plan)?;
    let actions: Vec<PlannedActionV3> = v2
        .actions
        .into_iter()
        .map(|action| PlannedActionV3 {
            fs: Some(action),
            process: None,
        })
        .collect();
    Ok(ToolPlanV3 {
        tool: dwk_proto::wire::scalar::CoreTool::ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == v2.tool.as_str())
            .ok_or(WireGap::Unrepresentable("a filesystem tool"))?,
        environment: v2.environment,
        effect: v2.effect,
        actions: PlannedActionsV3::new(actions).ok_or(WireGap::Unrepresentable("a plan"))?,
    })
}

/// A filesystem output on the version-3 wire: the same member.
fn wire_output_v3(output: &dwk_proto::dwkp::fsops::ToolOutput) -> ToolOutputV3 {
    ToolOutputV3 {
        fs_read: output.fs_read.clone(),
        fs_list: output.fs_list.clone(),
        fs_search: output.fs_search.clone(),
        fs_stat: output.fs_stat.clone(),
        fs_write: output.fs_write.clone(),
        fs_patch: output.fs_patch.clone(),
        fs_move: output.fs_move.clone(),
        fs_delete: output.fs_delete.clone(),
        process_exec: None,
        process_status: None,
        process_kill: None,
    }
}

/// The response body for a filesystem tool operation asked at version 3
/// (M4d): version 2's answer, in version 3's shapes. Nothing about the
/// operation differs.
///
/// # Errors
///
/// [`WireGap::Unrepresentable`] only for a value that does not fit its wire
/// type -- a bug.
pub fn tool_reply_v3(reply: &ToolReply) -> Result<DwkpBody, WireGap> {
    use super::process::{widen_failure, widen_refusal};
    Ok(match reply {
        ToolReply::Done {
            invocation,
            plan,
            output,
        } => DwkpBody::ToolResultV3(ToolResultV3 {
            invocation_id: invocation.clone(),
            plan: wire_plan_v3(plan)?,
            output: wire_output_v3(output),
        }),
        ToolReply::Denied(plan) => DwkpBody::ToolDeniedV3(ToolDenialV3 {
            plan: wire_plan_v3(plan)?,
        }),
        ToolReply::Previewed(plan) => DwkpBody::ToolPreviewedV3(CanonicalPreviewResultV3 {
            plan: wire_plan_v3(plan)?,
        }),
        ToolReply::Refused(operation, reason) => DwkpBody::ToolRefusedV3(ToolRefusalV3 {
            operation: *operation,
            reason: widen_refusal(*reason),
        }),
        ToolReply::Failed { invocation, reason } => DwkpBody::ToolFailedV3(ToolFailureV3 {
            invocation_id: invocation.clone(),
            reason: widen_failure(*reason),
        }),
    })
}

/// A process plan on the version-3 wire: its one action, with both gates, the
/// host floor's reason, and — for a launch — the argv's count, digest and
/// classification. Never the arguments: those are in the audit record.
fn wire_process_plan(plan: &ProcessPlan) -> Result<ToolPlanV3, WireGap> {
    use dwk_proto::wire::scalar::{ArgCount, ArgvSafetyClass, ContentDigest, HostPath};
    let action = plan.action();
    let policy = action.record().policy();
    let (rule_id, rule_source) = rule(policy.rule_id().as_str(), policy.rule_source())?;
    let executable = ExecutableRef {
        path: HostPath::new(action.executable().path().to_string())
            .ok_or(WireGap::Unrepresentable("an executable path"))?,
        sha256: ContentDigest::new(action.executable().digest().to_string())
            .ok_or(WireGap::Unrepresentable("an executable digest"))?,
    };
    let launch = action.launch();
    let wire = PlannedProcessAction {
        role: dwk_proto::wire::scalar::ActionRole::Target,
        verb: action.verb(),
        executable,
        process_id: action.process().cloned(),
        cwd: launch
            .map(|l| {
                WorkspacePath::new(l.cwd().to_string())
                    .ok_or(WireGap::Unrepresentable("a working directory"))
            })
            .transpose()?,
        arg_count: launch
            .map(|l| {
                u16::try_from(l.arg_count())
                    .ok()
                    .and_then(ArgCount::new)
                    .ok_or(WireGap::Unrepresentable("an argument count"))
            })
            .transpose()?,
        argv_sha256: launch
            .map(|l| {
                ContentDigest::new(l.argv_sha256().to_hex())
                    .ok_or(WireGap::Unrepresentable("an argv digest"))
            })
            .transpose()?,
        argv_safety: launch.map(|l| {
            if l.reinterpreting() {
                ArgvSafetyClass::Reinterpreting
            } else {
                ArgvSafetyClass::Safe
            }
        }),
        decision: ProcessActionDecision {
            effect: if action.permits() {
                DecisionEffect::Allow
            } else {
                DecisionEffect::Deny
            },
            reason: action.reason(),
            capability_result: gate(action.record().capability_satisfied()),
            policy_result: gate(action.policy_satisfied()),
            rule_id,
            rule_source,
        },
    };
    Ok(ToolPlanV3 {
        tool: plan.tool(),
        environment: ActionEnvironment::Host,
        effect: if plan.permits() {
            DecisionEffect::Allow
        } else {
            DecisionEffect::Deny
        },
        actions: PlannedActionsV3::new(vec![PlannedActionV3 {
            fs: None,
            process: Some(wire),
        }])
        .ok_or(WireGap::Unrepresentable("a plan"))?,
    })
}

fn wire_stream(stream: &StreamSnapshot) -> Result<ProcessStreamSnapshot, WireGap> {
    Ok(ProcessStreamSnapshot {
        content: dwk_proto::wire::scalar::StreamContent::from_bytes(&stream.content)
            .ok_or(WireGap::Unrepresentable("a stream"))?,
        observed: ByteCount::new(stream.observed)
            .ok_or(WireGap::Unrepresentable("a stream's count"))?,
        truncated: stream.truncated,
    })
}

fn wire_process_output(output: &ProcessOutput) -> Result<ToolOutputV3, WireGap> {
    use dwk_proto::wire::scalar::{ExitCode, SignalNumber};
    let exit = |code: Option<u8>| {
        code.map(|c| ExitCode::new(c).ok_or(WireGap::Unrepresentable("an exit code")))
            .transpose()
    };
    let signal = |number: Option<u8>| {
        number
            .map(|n| SignalNumber::new(n).ok_or(WireGap::Unrepresentable("a signal")))
            .transpose()
    };
    let mut out = ToolOutputV3 {
        fs_read: None,
        fs_list: None,
        fs_search: None,
        fs_stat: None,
        fs_write: None,
        fs_patch: None,
        fs_move: None,
        fs_delete: None,
        process_exec: None,
        process_status: None,
        process_kill: None,
    };
    match output {
        ProcessOutput::Launched {
            process_id,
            state,
            exit_code,
            signal: sig,
        } => {
            out.process_exec = Some(ProcessExecResult {
                process_id: process_id.clone(),
                state: *state,
                exit_code: exit(*exit_code)?,
                signal: signal(*sig)?,
            });
        }
        ProcessOutput::Observed {
            process_id,
            state,
            exit_code,
            signal: sig,
            timed_out,
            stdout,
            stderr,
        } => {
            out.process_status = Some(ProcessStatusResult {
                process_id: process_id.clone(),
                state: *state,
                exit_code: exit(*exit_code)?,
                signal: signal(*sig)?,
                timed_out: *timed_out,
                stdout: wire_stream(stdout)?,
                stderr: wire_stream(stderr)?,
            });
        }
        ProcessOutput::Killed {
            process_id,
            outcome,
        } => {
            out.process_kill = Some(ProcessKillResult {
                process_id: process_id.clone(),
                outcome: *outcome,
            });
        }
    }
    Ok(out)
}

/// The response body for a process tool operation (M4d, ADR-0045).
///
/// # Errors
///
/// [`WireGap::Unrepresentable`] only for a value that does not fit its wire
/// type -- a bug.
pub fn process_reply(reply: &ProcessReply) -> Result<DwkpBody, WireGap> {
    Ok(match reply {
        ProcessReply::Done {
            invocation,
            plan,
            output,
        } => DwkpBody::ToolResultV3(ToolResultV3 {
            invocation_id: invocation.clone(),
            plan: wire_process_plan(plan)?,
            output: wire_process_output(output)?,
        }),
        ProcessReply::Denied(plan) => DwkpBody::ToolDeniedV3(ToolDenialV3 {
            plan: wire_process_plan(plan)?,
        }),
        ProcessReply::Previewed(plan) => DwkpBody::ToolPreviewedV3(CanonicalPreviewResultV3 {
            plan: wire_process_plan(plan)?,
        }),
        ProcessReply::Refused(operation, reason) => DwkpBody::ToolRefusedV3(ToolRefusalV3 {
            operation: *operation,
            reason: *reason,
        }),
        ProcessReply::Failed { invocation, reason } => DwkpBody::ToolFailedV3(ToolFailureV3 {
            invocation_id: invocation.clone(),
            reason: *reason,
        }),
    })
}

fn tool_reply_v2_inner(reply: &ToolReply) -> Result<DwkpBody, WireGap> {
    Ok(match reply {
        ToolReply::Done {
            invocation,
            plan,
            output,
        } => DwkpBody::ToolResultV2(ToolResultV2 {
            invocation_id: invocation.clone(),
            plan: wire_plan(plan)?,
            output: (**output).clone(),
        }),
        ToolReply::Denied(plan) => DwkpBody::ToolDeniedV2(ToolDenialV2 {
            plan: wire_plan(plan)?,
        }),
        ToolReply::Previewed(plan) => DwkpBody::ToolPreviewedV2(CanonicalPreviewResultV2 {
            plan: wire_plan(plan)?,
        }),
        ToolReply::Refused(operation, reason) => DwkpBody::ToolRefusedV2(ToolRefusalV2 {
            operation: *operation,
            reason: *reason,
        }),
        ToolReply::Failed { invocation, reason } => DwkpBody::ToolFailedV2(ToolFailureV2 {
            invocation_id: invocation.clone(),
            reason: *reason,
        }),
    })
}
