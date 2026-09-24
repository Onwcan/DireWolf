//! `QueryAuthority`: effective authority on the wire, a typed refusal for every
//! wire proposal, and both gates — with the real rule named — for a complete
//! canonical action (ADR-0040).
//!
//! Decisions here are made through `Proposal::Action`, the in-process entry
//! M4's canonicaliser will use. The tests build the canonical action
//! themselves, choosing every fact explicitly — including the environment —
//! and so stand in for that component. No DWKP message reaches that path.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::dwkp::messages::AuthorityDecision;
use dwk_proto::wire::id::{RunId, SessionId};
use dwk_proto::wire::scalar::{
    CapabilityText, DecisionEffect, DecisionReason, Epoch, GateResult, RefusalReason,
    RefusedOperation,
};
use dwkd_authority::capability::parse;
use dwkd_authority::policy::{CanonicalAction, Effect, Environment, IpAddress, Unevaluable};
use dwkd_authority::state::wire::{self, WireGap};
use dwkd_authority::state::{AuditEvent, CallerContext, Proposal, Reply, Undecidable};
use state_support::{
    Harness, admit_simple, audit_records, config, policy, query_msg, session, text,
};

/// A policy with a rule that needs a destination address, a rule whose
/// effect is REQUIRE_APPROVAL and **no** unattended postcondition, and an
/// allow for HTTPS.
const PROBE: &str = r#"
schema_version = 1

[meta]
name = "probe"

[[rule]]
id     = "deny-internal-addresses"
effect = "DENY"
reason = "SANDBOX_ESCAPE_VECTOR"
when.verb  = "network.https"
when.ip_in = "10.0.0.0/8"

[[rule]]
id     = "approve-model-calls"
effect = "REQUIRE_APPROVAL"
reason = "PROFILE_CEILING"
when.verb = "model.call"
approval.scope    = "exact_action"
approval.ttl      = "10m"
approval.max_uses = 1

[[rule]]
id     = "allow-https"
effect = "ALLOW"
when.verb = "network.https"

[[rule]]
id     = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// The shipped `balanced` pack, as the harness installs it.
const BALANCED: &str = include_str!("../../../policy/balanced.toml");
/// The other two shipped packs, for the default-deny evidence.
const SAFE: &str = include_str!("../../../policy/safe.toml");
const POWER: &str = include_str!("../../../policy/power.toml");

struct Run {
    caller: CallerContext,
    session: SessionId,
    epoch: Epoch,
    run: RunId,
}

fn admit(h: &mut Harness, capabilities: &[&str]) -> Run {
    let caller = h.connect(1000);
    let s = session(1);
    let e = h.lease(&caller, &s);
    let Reply::Done(admission) = h
        .authority()
        .admit_run(&caller, &admit_simple(&s, e, "k", capabilities))
        .unwrap()
    else {
        panic!("admitted")
    };
    Run {
        caller,
        session: s,
        epoch: e,
        run: admission.run_id().clone(),
    }
}

/// A complete canonical action, every fact chosen by the test — which is what
/// M4's canonicaliser will do, from a real resource.
fn action(capability: &str) -> CanonicalAction {
    CanonicalAction::new(
        parse(capability).unwrap().resolve().unwrap(),
        Environment::Sandbox,
    )
}

/// Decide a complete canonical action in process, and map it to the wire.
fn decide(h: &mut Harness, run: &Run, action: &CanonicalAction) -> AuthorityDecision {
    let Reply::Done(answer) = h
        .authority()
        .query_authority(
            &run.caller,
            &run.session,
            &run.run,
            run.epoch,
            Some(Proposal::Action(action)),
        )
        .unwrap()
    else {
        panic!("answered")
    };
    let record = answer.decision().expect("a decision for an action");
    let decision = wire::decision(record).expect("a representable decision");
    // And the whole answer survives the wire mapping with it.
    let effective = wire::effective_authority(&answer).unwrap();
    assert_eq!(effective.decision.as_ref(), Some(&decision));
    decision
}

/// Ask over the wire with a proposal; return the refusal reason.
fn ask(h: &mut Harness, run: &Run, proposed: &str) -> RefusalReason {
    let message = query_msg(&run.session, &run.run, run.epoch, Some(proposed));
    match h.authority().dispatch(&run.caller, &message).unwrap() {
        DwkpBody::AuthorityRefused(refusal) => {
            assert_eq!(refusal.operation, RefusedOperation::QueryAuthority);
            refusal.reason
        }
        other => panic!("{proposed}: expected a refusal, got {other:?}"),
    }
}

/// The rule block a `rule_source` line falls in must be the block that defines
/// `rule_id`: the attribution names the rule that is actually written there.
#[track_caller]
fn assert_written_at(policy_text: &str, source: &str, rule_id: &str) {
    let (file, line) = source.rsplit_once(':').unwrap();
    assert!(file.ends_with(".toml"), "{source}");
    let line: usize = line.parse().unwrap();
    let lines: Vec<&str> = policy_text.lines().collect();
    assert!(line >= 1 && line <= lines.len(), "{source} is past the end");
    // A rule or postcondition block runs from its table header to the next one.
    let header = |i: usize| lines[i].trim_start().starts_with('[');
    let start = (0..line).rev().find(|&i| header(i)).unwrap();
    let end = (line..lines.len())
        .find(|&i| header(i))
        .unwrap_or(lines.len());
    let ids: Vec<String> = lines[start..end]
        .iter()
        .filter_map(|l| {
            let (key, value) = l.split_once('=')?;
            (key.trim() == "id").then(|| value.trim().trim_matches('"').to_owned())
        })
        .collect();
    assert_eq!(
        ids,
        [rule_id],
        "{source} is not where `{rule_id}` is written"
    );
}

#[track_caller]
fn assert_decision(
    decision: &AuthorityDecision,
    effect: DecisionEffect,
    reason: DecisionReason,
    capability: GateResult,
    policy: GateResult,
    rule: &str,
) {
    assert_eq!(decision.effect, effect, "{decision:?}");
    assert_eq!(decision.reason, reason, "{decision:?}");
    assert_eq!(decision.capability_result, capability, "{decision:?}");
    assert_eq!(decision.policy_result, policy, "{decision:?}");
    assert_eq!(decision.rule_id.as_str(), rule, "{decision:?}");
}

// ---- the wire: a proposal is refused, and nothing is attributed -------------

#[test]
fn every_wire_proposal_is_refused_before_any_rule_runs() {
    let mut h = Harness::new("wire-proposals");
    let run = admit(&mut h, &["model.call:*", "network.https:*.example.com"]);
    for (proposal, why) in [
        ("fs.read:/etc/passwd", "unresolved_resource"),
        ("fs.write:/workspace/x", "unresolved_resource"),
        ("process.exec:/usr/bin/git", "unresolved_resource"),
        ("network.https:api.example.com", "action_facts_unavailable"),
        ("network.http:example.com", "action_facts_unavailable"),
        ("memory.read:*", "action_facts_unavailable"),
        ("agent.spawn:*", "action_facts_unavailable"),
        ("artifact.read:*", "action_facts_unavailable"),
        ("model.call:anthropic/claude", "action_facts_unavailable"),
        ("scheduler.create:*", "action_facts_unavailable"),
        ("teleport.now:*", "unknown_vocabulary"),
    ] {
        assert_eq!(
            ask(&mut h, &run, proposal),
            RefusalReason::NoCanonicalAction,
            "{proposal}"
        );
        let refused = audit_records(&h.state(), AuditEvent::QueryRefused.as_str());
        let last = refused.last().unwrap();
        assert_eq!(
            text(last, "reason"),
            Some("NO_CANONICAL_ACTION"),
            "{proposal}"
        );
        assert_eq!(text(last, "proposed"), Some(proposal));
        assert_eq!(text(last, "undecidable"), Some(why), "{proposal}");
        assert_eq!(
            Undecidable::of(&CapabilityText::new(proposal).unwrap()).as_str(),
            why
        );
        // No evaluation ran, so nothing names a rule.
        for absent in ["rule_id", "rule_source", "policy_effect", "effect"] {
            assert!(last.get(absent).is_none(), "{proposal}: {absent}");
        }
    }
    assert!(
        audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str()).is_empty(),
        "no decision was made about any of them"
    );
}

#[test]
fn a_malformed_capability_invents_no_policy_rule() {
    let mut h = Harness::new("malformed");
    let run = admit(&mut h, &["model.call:*"]);
    assert_eq!(
        ask(&mut h, &run, "teleport.now:*"),
        RefusalReason::NoCanonicalAction
    );
    let record = audit_records(&h.state(), AuditEvent::QueryRefused.as_str())
        .pop()
        .unwrap();
    assert_eq!(text(&record, "undecidable"), Some("unknown_vocabulary"));
    assert!(record.get("rule_id").is_none());
    assert!(record.get("rule_source").is_none());
}

#[test]
fn a_missing_canonical_resource_invents_no_policy_rule() {
    let mut h = Harness::new("unresolved");
    let run = admit(&mut h, &["model.call:*"]);
    for (proposal, scope) in [
        ("fs.read:/etc/passwd", "an fs scope"),
        ("process.exec:/usr/bin/git", "a process scope"),
    ] {
        assert_eq!(
            ask(&mut h, &run, proposal),
            RefusalReason::NoCanonicalAction
        );
        let record = audit_records(&h.state(), AuditEvent::QueryRefused.as_str())
            .pop()
            .unwrap();
        assert_eq!(text(&record, "undecidable"), Some("unresolved_resource"));
        assert!(
            text(&record, "unresolved").unwrap().contains(scope),
            "{proposal}: {record:?}"
        );
        assert!(record.get("rule_id").is_none());
    }
}

#[test]
fn missing_action_context_invents_no_policy_rule() {
    // `balanced` has a tainted-egress rule keyed on destination novelty and a
    // host-execution denial keyed on the environment. A decision made on an
    // action missing those facts would switch them off. None is made.
    let mut h = Harness::new("no-context");
    let run = admit(&mut h, &["network.https:*", "model.call:*"]);
    for proposal in ["network.https:github.com", "model.call:anthropic/claude"] {
        assert_eq!(
            ask(&mut h, &run, proposal),
            RefusalReason::NoCanonicalAction
        );
        let record = audit_records(&h.state(), AuditEvent::QueryRefused.as_str())
            .pop()
            .unwrap();
        assert_eq!(
            text(&record, "undecidable"),
            Some("action_facts_unavailable")
        );
        assert!(record.get("rule_id").is_none());
    }
}

#[test]
fn state_refusals_precede_the_proposal() {
    let mut h = Harness::new("refusals");
    let run = admit(&mut h, &["model.call:*"]);
    let stranger = h.connect(2000);
    // Stale: a caller who does not hold the lease learns nothing about the
    // proposal, only that it is fenced.
    let DwkpBody::AuthorityRefused(refusal) = h
        .authority()
        .dispatch(
            &stranger,
            &query_msg(&run.session, &run.run, run.epoch, Some("teleport.now:*")),
        )
        .unwrap()
    else {
        panic!("refused")
    };
    assert_eq!(
        (refusal.operation, refusal.reason),
        (RefusedOperation::QueryAuthority, RefusalReason::StaleEpoch)
    );
    // Unknown run: never existed, and released, answer alike — before the
    // proposal is looked at.
    let never = state_support::run_id(777);
    let proposed = CapabilityText::new("fs.read:/etc/passwd").unwrap();
    assert_eq!(
        h.authority()
            .query_authority(
                &run.caller,
                &run.session,
                &never,
                run.epoch,
                Some(Proposal::Text(&proposed))
            )
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
    h.authority()
        .release_run(&run.caller, &run.session, &run.run, run.epoch)
        .unwrap();
    assert_eq!(
        h.authority()
            .query_authority(&run.caller, &run.session, &run.run, run.epoch, None)
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
}

#[test]
fn a_query_without_a_proposal_reports_authority_and_decides_nothing() {
    let mut h = Harness::new("report");
    let run = admit(
        &mut h,
        &["model.call:*", "secret.use:x", "fs.write:/workspace"],
    );
    let DwkpBody::EffectiveAuthority(answer) = h
        .authority()
        .dispatch(
            &run.caller,
            &query_msg(&run.session, &run.run, run.epoch, None),
        )
        .unwrap()
    else {
        panic!("answered")
    };
    assert!(answer.decision.is_none());
    assert_eq!(answer.granted.len(), 1);
    // Every withheld capability has a wire reason now, fs included.
    let reasons: Vec<&str> = answer.withheld.iter().map(|w| w.reason.as_str()).collect();
    assert_eq!(reasons, ["NOT_IN_AGENT_PROFILE", "UNRESOLVED_RESOURCE"]);
    assert_eq!(answer.run_id, run.run);
    assert!(audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str()).is_empty());
}

// ---- a complete canonical action: both gates, and the real rule --------------

#[test]
fn a_real_policy_allow_names_the_real_matched_rule() {
    let mut h = Harness::new("allow");
    let run = admit(&mut h, &["model.call:*"]);
    let d = decide(&mut h, &run, &action("model.call:anthropic/claude"));
    assert_decision(
        &d,
        DecisionEffect::Allow,
        DecisionReason::AllowedByRule,
        GateResult::Satisfied,
        GateResult::Satisfied,
        "allow-model-calls",
    );
    assert_written_at(BALANCED, d.rule_source.as_str(), "allow-model-calls");
    assert_eq!(
        d.required_capability.as_str(),
        "model.call:anthropic/claude"
    );
}

#[test]
fn policy_allow_does_not_mint_a_missing_capability_and_still_names_its_rule() {
    let mut h = Harness::new("no-cap");
    let run = admit(&mut h, &["model.call:anthropic/*"]);
    let d = decide(&mut h, &run, &action("model.call:openai/gpt"));
    assert_decision(
        &d,
        DecisionEffect::Deny,
        DecisionReason::NoCapability,
        GateResult::NotSatisfied,
        GateResult::Satisfied,
        "allow-model-calls",
    );
    assert_written_at(BALANCED, d.rule_source.as_str(), "allow-model-calls");
}

#[test]
fn a_real_policy_deny_names_the_real_matched_rule() {
    let mut h = Harness::new("deny-rule");
    let run = admit(&mut h, &["network.http:*", "scheduler.create:*"]);
    let d = decide(&mut h, &run, &action("network.http:example.com"));
    assert_decision(
        &d,
        DecisionEffect::Deny,
        DecisionReason::DeniedByRule,
        GateResult::Satisfied,
        GateResult::NotSatisfied,
        "deny-plaintext-http",
    );
    assert_written_at(BALANCED, d.rule_source.as_str(), "deny-plaintext-http");

    // Nothing matched before the mandatory default rule: DEFAULT_DENY, naming
    // the `default` rule written in the operator's file — a rule that matched,
    // not a placeholder.
    let d = decide(&mut h, &run, &action("scheduler.create:*"));
    assert_decision(
        &d,
        DecisionEffect::Deny,
        DecisionReason::DefaultDeny,
        GateResult::Satisfied,
        GateResult::NotSatisfied,
        "default",
    );
    assert_written_at(BALANCED, d.rule_source.as_str(), "default");
}

#[test]
fn both_gates_are_reported_when_both_refuse() {
    let mut h = Harness::new("both-refuse");
    let run = admit(&mut h, &["model.call:*"]);
    assert_decision(
        &decide(&mut h, &run, &action("network.http:example.com")),
        DecisionEffect::Deny,
        DecisionReason::DeniedByRule,
        GateResult::NotSatisfied,
        GateResult::NotSatisfied,
        "deny-plaintext-http",
    );
}

#[test]
fn require_approval_narrowed_by_the_unattended_postcondition_names_the_postcondition() {
    let mut h = Harness::new("unattended");
    let run = admit(&mut h, &["memory.promote:*"]);
    let a = action("memory.promote:*");
    let d = decide(&mut h, &run, &a);
    assert_decision(
        &d,
        DecisionEffect::Deny,
        DecisionReason::DeniedByRule,
        GateResult::Satisfied,
        GateResult::NotSatisfied,
        "deny-approval-needed-when-unattended",
    );
    assert_written_at(
        BALANCED,
        d.rule_source.as_str(),
        "deny-approval-needed-when-unattended",
    );
    // Internally: the primary rule asked for approval; the run is `api`, so
    // nobody can be asked, and the postcondition denied.
    let Reply::Done(answer) = h
        .authority()
        .query_authority(
            &run.caller,
            &run.session,
            &run.run,
            run.epoch,
            Some(Proposal::Action(&a)),
        )
        .unwrap()
    else {
        panic!("answered")
    };
    let record = answer.decision().unwrap();
    assert_eq!(record.policy().effect(), Effect::Deny);
    assert_eq!(
        record.policy().primary_rule().id().as_str(),
        "approve-memory-promotion"
    );
}

#[test]
fn require_approval_mapped_to_a_wire_deny_names_the_rule_that_required_it() {
    let mut h = Harness::with_config("approval", config(policy("probe", PROBE)));
    let run = admit(&mut h, &["model.call:*"]);
    let d = decide(&mut h, &run, &action("model.call:anthropic/claude"));
    assert_decision(
        &d,
        DecisionEffect::Deny,
        DecisionReason::DeniedByRule,
        GateResult::Satisfied,
        GateResult::NotSatisfied,
        "approve-model-calls",
    );
    assert_written_at(PROBE, d.rule_source.as_str(), "approve-model-calls");
    // Internally it is still REQUIRE_APPROVAL: the rule author's intent is
    // kept, and the audit record says so.
    let records = audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str());
    let last = records.last().unwrap();
    assert_eq!(text(last, "policy_effect"), Some("REQUIRE_APPROVAL"));
    assert_eq!(text(last, "effect"), Some("DENY"));
    assert_eq!(text(last, "rule_id"), Some("approve-model-calls"));
}

#[test]
fn a_rule_needing_an_address_the_action_lacks_is_a_gap_not_a_lie() {
    // Reachable only in process: the same proposal over the wire is refused
    // before any rule runs.
    let mut h = Harness::with_config("no-address", config(policy("probe", PROBE)));
    let run = admit(&mut h, &["network.https:*.example.com"]);
    let a = action("network.https:api.example.com");
    let Reply::Done(answer) = h
        .authority()
        .query_authority(
            &run.caller,
            &run.session,
            &run.run,
            run.epoch,
            Some(Proposal::Action(&a)),
        )
        .unwrap()
    else {
        panic!("answered")
    };
    assert_eq!(
        wire::decision(answer.decision().unwrap()),
        Err(WireGap::UnevaluablePolicyInput(
            Unevaluable::ResolvedAddress
        )),
        "DENIED_BY_RULE would claim the rule matched and said deny"
    );
    assert_eq!(
        ask(&mut h, &run, "network.https:api.example.com"),
        RefusalReason::NoCanonicalAction
    );
}

#[test]
fn a_decision_about_a_destination_address_records_that_address() {
    let mut h = Harness::with_config("address", config(policy("probe", PROBE)));
    let run = admit(&mut h, &["network.https:*.example.com"]);
    let decide_for = |h: &mut Harness, octets: [u8; 4]| {
        let a = action("network.https:api.example.com").with_destination_ip(IpAddress::V4(octets));
        let Reply::Done(answer) = h
            .authority()
            .query_authority(
                &run.caller,
                &run.session,
                &run.run,
                run.epoch,
                Some(Proposal::Action(&a)),
            )
            .unwrap()
        else {
            panic!("answered")
        };
        let record = answer.decision().unwrap();
        (
            record.permits(),
            record.policy().rule_id().as_str().to_owned(),
            record.destination_ip(),
        )
    };
    let (allowed, rule, ip) = decide_for(&mut h, [93, 184, 216, 34]);
    assert!(allowed);
    assert_eq!(rule, "allow-https");
    assert_eq!(ip, Some(IpAddress::V4([93, 184, 216, 34])));
    let (allowed, rule, _) = decide_for(&mut h, [10, 1, 2, 3]);
    assert!(!allowed);
    assert_eq!(rule, "deny-internal-addresses");

    let records = audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str());
    let ips: Vec<Option<&str>> = records.iter().map(|r| text(r, "destination_ip")).collect();
    assert_eq!(ips, [Some("93.184.216.34"), Some("10.1.2.3")]);
    // The record is evidence for a future binding, not a binding: nothing in
    // M3d pins the address, and the record does not say it does.
    assert!(records.iter().all(|r| r.get("pinned").is_none()));
}

#[test]
fn a_decision_record_binds_the_policy_revision_rule_and_source() {
    let mut h = Harness::new("decision-audit");
    let run = admit(&mut h, &["network.http:*"]);
    let d = decide(&mut h, &run, &action("network.http:example.com"));
    let record = audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str())
        .pop()
        .unwrap();
    assert_eq!(
        text(&record, "policy_revision"),
        Some(h.authority().policy_revision().unwrap().to_hex().as_str())
    );
    assert_eq!(text(&record, "rule_id"), Some(d.rule_id.as_str()));
    assert_eq!(text(&record, "rule_source"), Some(d.rule_source.as_str()));
    assert_eq!(text(&record, "reason"), Some("PROFILE_CEILING"));
    assert_eq!(text(&record, "run_id"), Some(run.run.as_str()));
    assert_eq!(
        text(&record, "required_capability"),
        Some("network.http:example.com")
    );
}

#[test]
fn the_same_question_against_the_same_state_gets_the_same_answer() {
    let mut h = Harness::new("deterministic");
    let run = admit(&mut h, &["model.call:*", "network.http:*"]);
    for capability in [
        "model.call:x/y",
        "network.http:a.test",
        "scheduler.create:*",
    ] {
        let a = action(capability);
        let first = decide(&mut h, &run, &a);
        for _ in 0..5 {
            assert_eq!(decide(&mut h, &run, &a), first, "{capability}");
        }
    }
    for proposal in ["model.call:x/y", "nope.nope:*"] {
        for _ in 0..3 {
            assert_eq!(
                ask(&mut h, &run, proposal),
                RefusalReason::NoCanonicalAction
            );
        }
    }
    assert_eq!(
        audit_records(&h.state(), AuditEvent::AuthorityDecision.as_str()).len(),
        18
    );
}

// ---- evaluation evidence ----------------------------------------------------

/// Evidence for the M3 evaluation `authority-security/policy-denies-by-default`.
///
/// For each shipped pack, an action none of its rules mentions is denied by the
/// pack's own mandatory `default` rule, with both gates reported, the rule's
/// source line, and an `authority.decision` record. The action differs per pack
/// because each pack mentions different verbs: `safe` names every scheduler
/// verb, `power` every agent verb. In process, through the real authority and
/// engine: over DWKP a proposal is refused with `NO_CANONICAL_ACTION` until M4
/// can build the complete canonical action policy decides on (ADR-0040), so
/// there is no truthful wire path yet, and the evaluation says so.
#[test]
#[ignore = "evaluation evidence; run by the M3 eval runner (make eval)"]
fn policy_denies_by_default_evidence() {
    for (pack, text, capability, gate) in [
        (
            "safe",
            SAFE,
            "agent.cancel:researcher",
            GateResult::NotSatisfied,
        ),
        (
            "balanced",
            BALANCED,
            "scheduler.create:*",
            GateResult::Satisfied,
        ),
        ("power", POWER, "scheduler.create:*", GateResult::Satisfied),
    ] {
        let mut h = Harness::with_config(
            &format!("eval-default-{pack}"),
            config(dwkd_authority::state::PolicySet::shipped(pack).unwrap()),
        );
        let run = admit(&mut h, &[capability]);
        let d = decide(&mut h, &run, &action(capability));
        assert_decision(
            &d,
            DecisionEffect::Deny,
            DecisionReason::DefaultDeny,
            gate,
            GateResult::NotSatisfied,
            "default",
        );
        assert_written_at(text, d.rule_source.as_str(), "default");
        let decisions = audit_records(&h.state(), "authority.decision");
        assert_eq!(decisions.len(), 1, "the decision is on the record");
        println!(
            "DWKP-EVIDENCE {{\"suite\":\"policy\",\"case\":\"default-deny-{pack}\",\"layer\":\"capability-policy\",\"contained\":true,\"audited\":true,\"rule_source\":\"{}\"}}",
            d.rule_source.as_str()
        );
    }
}
