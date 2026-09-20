//! Fuzz target bodies for the policy loader, shared by two engines.
//!
//! * `fuzz/fuzz_targets/policy_loader.rs` — coverage-guided libFuzzer via
//!   `cargo fuzz` (nightly, Linux CI).
//! * `tests/fuzz_smoke.rs` — a deterministic mutation loop on stable Rust that
//!   runs on every `cargo test`.
//!
//! Both include this file, so the invariants are written once, exactly as
//! `dwk-proto` does it.
//!
//! # Why the policy loader is fuzzed at all
//!
//! Because M3c put a third-party parser inside the authority. The TOML chain
//! — `toml`, `toml_parser`, `winnow` — is the first code in the trusted
//! computing base that reads a file format it did not design
//! ([ADR-0035](../../../../docs/adr/0035-m3-authority-dependency-set.md)).
//! Policy is operator-owned rather than attacker-chosen, so this is not the
//! same threat model as DWKP decoding; it is still a parser in the process
//! that holds the capability key, and "we believe the input is trusted" is the
//! sentence that precedes most parser CVEs.
//!
//! Every target panics — the only signal a fuzzer understands — when an
//! invariant breaks.
//!
//! # What is NOT fuzzed here
//!
//! No I/O, because there is none to reach: [`load`] takes a string. Nothing
//! executes, because a policy file names no code. The loader is pure, so a
//! finding is a crash or a hang and never a side effect.

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwkd_authority::capability::{Capability, ConstraintSet, Namespace, Scope, Verb};
use dwkd_authority::policy::{
    CanonicalAction, Effect, Environment, Origin, PolicyContext, ProfileName, TaintLevel, compose,
    evaluate, limits, load,
};

/// The loader: never panics, always bounded, and an accepted policy always has
/// a denying, unconditional default as its last rule.
///
/// That last clause is the one worth fuzzing for. Everything else in the
/// loader can fail safe by refusing; a policy that loaded *without* a default
/// would be one where an unmatched action has no answer.
pub(crate) fn policy_loader(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        // Policy source is text. Invalid UTF-8 is the caller's problem, and
        // the API says so in its type.
        return;
    };

    // Bounded: the loader refuses oversized input rather than parsing it, so
    // feeding it a large mutant must be cheap.
    let Ok(profile) = load("fuzz.toml", text) else {
        return;
    };

    assert!(
        profile.rules().len() <= limits::MAX_RULES,
        "an accepted policy exceeded the rule bound"
    );
    assert!(
        profile.postconditions().len() <= limits::MAX_POSTCONDITIONS,
        "an accepted policy exceeded the postcondition bound"
    );

    // Every accepted profile has a name that renders and re-parses.
    assert!(
        ProfileName::new(profile.name().as_str()).is_ok(),
        "an accepted profile name must be a valid profile name"
    );

    // An accepted rule always names a real line in the source it came from.
    for rule in profile.rules() {
        assert!(rule.source().line() > 0, "a rule reported line zero");
        assert_eq!(rule.source().source(), "fuzz.toml");
        assert!(rule.id().as_str().len() <= limits::MAX_RULE_ID_CHARS);
        // A REQUIRE_APPROVAL always carries the shape that would satisfy it;
        // anything else never does.
        match rule.effect() {
            Effect::RequireApproval => assert!(rule.approval().is_some()),
            Effect::Allow | Effect::Deny => assert!(rule.approval().is_none()),
        }
    }

    // Every postcondition can only narrow.
    for post in profile.postconditions() {
        assert!(
            post.narrows(),
            "an accepted postcondition could widen a decision"
        );
    }

    // The root of a chain owns the default; an extender must not have one.
    if profile.extends().is_none() {
        let last = profile.rules().last().expect("a root profile has rules");
        assert!(last.is_default(), "the last rule must be the default");
        assert_eq!(last.effect(), Effect::Deny, "the default must deny");
        assert!(last.when().is_empty() && last.unless().is_empty());
    } else {
        assert!(
            !profile.rules().iter().any(|r| r.is_default()),
            "an extending profile must not declare a default"
        );
    }

    // Loading the same text twice gives the same policy. A parser with a
    // hidden dependence on allocation addresses or iteration order would fail
    // here rather than in production six months later.
    let again = load("fuzz.toml", text).expect("the same text must load twice");
    assert_eq!(profile, again, "loading was not deterministic");
}

/// Load, compose and evaluate: an accepted policy always decides, and the
/// decision always names a rule that is in it.
pub(crate) fn policy_evaluate(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(profile) = load("fuzz.toml", text) else {
        return;
    };
    // Only a standalone profile can be composed on its own.
    if profile.extends().is_some() {
        return;
    }
    let name = profile.name().clone();
    let Ok(policy) = compose(&name, &[profile]) else {
        return;
    };

    // One action per verb family the fuzzer can reach without a canonical
    // resource identity, in two contexts. The evaluator is total, so every
    // one of these must return.
    let contexts = [
        PolicyContext::new(Origin::Interactive, TaintLevel::None),
        PolicyContext::new(Origin::Scheduled, TaintLevel::ExternalUntrusted),
    ];
    for (namespace, action_name) in [
        (Namespace::Model, "call"),
        (Namespace::Memory, "read"),
        (Namespace::Network, "https"),
        (Namespace::Agent, "spawn"),
    ] {
        let Some(verb) = Verb::parse_action(namespace, action_name) else {
            continue;
        };
        let Ok(capability) =
            Capability::new(verb, Scope::Universal, ConstraintSet::unconstrained())
        else {
            continue;
        };
        let action = CanonicalAction::new(capability, Environment::Sandbox);
        for context in &contexts {
            let decision = evaluate(&policy, &action, context);
            assert!(
                decision.rule_source().line() > 0,
                "a decision reported line zero"
            );
            // The deciding rule is one of the policy's own -- a primary rule or
            // a postcondition -- and never something invented.
            let id = decision.rule_id();
            let known = policy.rules().iter().any(|r| r.id() == id)
                || policy.postconditions().iter().any(|p| p.id() == id);
            assert!(known, "a decision named a rule that is not in the policy");

            // Phase two never widens phase one.
            let provisional = policy
                .rules()
                .iter()
                .find(|r| r.id() == decision.primary_rule().id())
                .map(dwkd_authority::policy::Rule::effect);
            if let Some(provisional) = provisional {
                assert!(
                    decision.effect().narrower_or_equal(provisional),
                    "a postcondition widened a decision"
                );
            }

            // A denial offers no approval and carries no obligation: there is
            // nothing a human could click that would make a refusal proceed.
            if decision.effect() == Effect::Deny {
                assert!(decision.approval().is_none());
                assert!(decision.obligations().is_empty());
            }

            // Deterministic.
            assert_eq!(evaluate(&policy, &action, context), decision);
        }
    }
}
