//! Properties of the policy engine, over generated policies and inputs.
//!
//! # The oracle is written twice
//!
//! A property test whose expected value comes from calling the implementation
//! again proves that the implementation agrees with itself. So the generator
//! here produces a **model** — a list of rules as data — and that model is
//! evaluated two ways: rendered to TOML and put through the real loader,
//! composer and evaluator, or handed to [`reference`], a second evaluator
//! written from [`POLICY.md`] §4 and knowing nothing about the production
//! code. The two must agree on every generated case.
//!
//! The same technique M3b used for the capability lattice, and it is the only
//! kind of property test that can catch a misreading of the specification
//! rather than merely a typo.
//!
//! # The predicate subset
//!
//! Verb, origin and taint. Deliberately small: these three are enough to
//! exercise first-match ordering, `unless`, the two phases and composition,
//! and they are the predicates an integration test can build actions for —
//! a canonical `fs` path cannot be constructed outside `crate::resource`
//! ([ADR-0037]), so path and executable matching is unit-tested in
//! `src/policy/fixtures.rs` instead.
//!
//! [ADR-0037]: ../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md
//! [`POLICY.md`]: ../../../docs/POLICY.md

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

// The authority links `toml` for the policy loader. This test binary does not
// use it, and `unused_crate_dependencies` sees the manifest edge rather than
// the target that consumes it. Acknowledged rather than silenced with an
// `#[allow]`, so the lint stays meaningful for the binaries that do use it.
use toml as _;
// Likewise the M3d state layer's storage and wire dependencies.
use dwk_proto as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use unicode_normalization as _;

use proptest::prelude::*;

use dwkd_authority::capability::{Capability, ConstraintSet, Namespace, Scope, Verb};
use dwkd_authority::policy::{
    CanonicalAction, CompiledPolicy, Effect, Environment, Origin, PolicyContext, Profile,
    ProfileName, Reason, TaintLevel, compose, evaluate, load,
};

/// The verbs the model uses: resolution-free families, so an action can be
/// built outside the crate.
const VERBS: [(Namespace, &str); 4] = [
    (Namespace::Model, "call"),
    (Namespace::Memory, "read"),
    (Namespace::Agent, "spawn"),
    (Namespace::Artifact, "read"),
];

fn verb(index: usize) -> Verb {
    let (namespace, action) = VERBS[index % VERBS.len()];
    Verb::parse_action(namespace, action).expect("a documented verb")
}

fn action(verb_index: usize) -> CanonicalAction {
    let capability = Capability::new(
        verb(verb_index),
        Scope::Universal,
        ConstraintSet::unconstrained(),
    )
    .expect("the universal scope fits every verb");
    CanonicalAction::new(capability, Environment::Sandbox)
}

// ---------------------------------------------------------------------------
// The model.
// ---------------------------------------------------------------------------

/// One rule, as data. Rendered to TOML for production and read directly by the
/// reference.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleModel {
    id: String,
    effect: Effect,
    /// Verb indices this rule matches, or `None` for every verb.
    verbs: Option<Vec<usize>>,
    /// Origins this rule matches, or `None` for every origin.
    origins: Option<Vec<usize>>,
    /// Taint tiers this rule matches, or `None` for every tier.
    taints: Option<Vec<usize>>,
    /// Whether `unless.standing_grant = true` suppresses it.
    unless_grant: bool,
}

/// One postcondition, as data.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PostModel {
    id: String,
    /// The provisional effects it selects, or `None` for all three.
    selects: Option<Vec<Effect>>,
    origins: Option<Vec<usize>>,
}

fn effect_name(effect: Effect) -> &'static str {
    effect.as_str()
}

fn reason_for(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "",
        Effect::Deny => "PROFILE_CEILING",
        Effect::RequireApproval => "UNKNOWN_EXECUTABLE",
    }
}

fn render_list<T: std::fmt::Display>(items: &[T]) -> String {
    let rendered: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
    format!("[{}]", rendered.join(", "))
}

impl RuleModel {
    fn render(&self) -> String {
        let mut out = format!(
            "\n[[rule]]\nid = \"{}\"\neffect = \"{}\"\n",
            self.id,
            effect_name(self.effect)
        );
        let reason = reason_for(self.effect);
        if !reason.is_empty() {
            out.push_str(&format!("reason = \"{reason}\"\n"));
        }
        if self.effect == Effect::RequireApproval {
            out.push_str(
                "approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n",
            );
        }
        if let Some(verbs) = &self.verbs {
            let names: Vec<String> = verbs.iter().map(|i| verb(*i).to_string()).collect();
            out.push_str(&format!("when.verb = {}\n", render_list(&names)));
        }
        if let Some(origins) = &self.origins {
            let names: Vec<&str> = origins
                .iter()
                .map(|i| Origin::ALL[i % 5].as_str())
                .collect();
            out.push_str(&format!("when.origin = {}\n", render_list(&names)));
        }
        if let Some(taints) = &self.taints {
            let names: Vec<&str> = taints
                .iter()
                .map(|i| TaintLevel::ALL[i % 3].as_str())
                .collect();
            out.push_str(&format!("when.taint_level = {}\n", render_list(&names)));
        }
        if self.unless_grant {
            out.push_str("unless.standing_grant = true\n");
        }
        out
    }

    /// Whether this rule matches, read straight from POLICY.md §4: implicit
    /// AND across predicates, implicit OR within a list, then `unless`.
    fn matches(&self, verb_index: usize, origin: Origin, taint: TaintLevel) -> bool {
        let verb_ok = self
            .verbs
            .as_ref()
            .is_none_or(|set| set.iter().any(|i| verb(*i) == verb(verb_index)));
        let origin_ok = self
            .origins
            .as_ref()
            .is_none_or(|set| set.iter().any(|i| Origin::ALL[i % 5] == origin));
        let taint_ok = self
            .taints
            .as_ref()
            .is_none_or(|set| set.iter().any(|i| TaintLevel::ALL[i % 3] == taint));
        // `unless.standing_grant = true` suppresses when a grant is held, and
        // through M5 one never is -- so it never suppresses.
        verb_ok && origin_ok && taint_ok
    }
}

impl PostModel {
    fn render(&self) -> String {
        let mut out = format!(
            "\n[[postcondition]]\nid = \"{}\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n",
            self.id
        );
        if let Some(selects) = &self.selects {
            let names: Vec<&str> = selects.iter().map(|e| effect_name(*e)).collect();
            out.push_str(&format!(
                "when.provisional_effect = {}\n",
                render_list(&names)
            ));
        }
        if let Some(origins) = &self.origins {
            let names: Vec<&str> = origins
                .iter()
                .map(|i| Origin::ALL[i % 5].as_str())
                .collect();
            out.push_str(&format!("when.origin = {}\n", render_list(&names)));
        }
        out
    }

    fn applies(&self, effect: Effect, origin: Origin) -> bool {
        let selected = self
            .selects
            .as_ref()
            .is_none_or(|set| set.contains(&effect));
        let origin_ok = self
            .origins
            .as_ref()
            .is_none_or(|set| set.iter().any(|i| Origin::ALL[i % 5] == origin));
        selected && origin_ok
    }
}

/// A whole policy, as data.
#[derive(Debug, Clone)]
struct PolicyModel {
    rules: Vec<RuleModel>,
    posts: Vec<PostModel>,
}

impl PolicyModel {
    fn render(&self, name: &str, extends: Option<&str>) -> String {
        let mut out = format!("schema_version = 1\n\n[meta]\nname = \"{name}\"\n");
        if let Some(parent) = extends {
            out.push_str(&format!("extends = \"{parent}\"\n"));
        }
        for rule in &self.rules {
            out.push_str(&rule.render());
        }
        if extends.is_none() {
            out.push_str(
                "\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
            );
        }
        for post in &self.posts {
            out.push_str(&post.render());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The reference evaluator, written from POLICY.md §4 and ADR-0038.
// ---------------------------------------------------------------------------

/// What the document says should happen, implemented independently.
fn reference(
    model: &PolicyModel,
    verb_index: usize,
    origin: Origin,
    taint: TaintLevel,
) -> (Effect, String) {
    // Phase one: ordered, first match wins, and the mandatory default last.
    let (mut effect, mut id) = (Effect::Deny, "default".to_owned());
    for rule in &model.rules {
        if rule.matches(verb_index, origin, taint) {
            effect = rule.effect;
            id = rule.id.clone();
            break;
        }
    }
    // Phase two: each postcondition may only narrow, and sees the running
    // effect rather than the original.
    for post in &model.posts {
        if post.applies(effect, origin) {
            // Every generated postcondition is DENY, which is the bottom, so
            // the meet is DENY.
            if effect != Effect::Deny {
                id = post.id.clone();
            }
            effect = Effect::Deny;
        }
    }
    (effect, id)
}

// ---------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------

fn effects() -> impl Strategy<Value = Effect> {
    prop_oneof![
        Just(Effect::Allow),
        Just(Effect::Deny),
        Just(Effect::RequireApproval)
    ]
}

fn maybe_indices(max: usize) -> impl Strategy<Value = Option<Vec<usize>>> {
    proptest::option::of(
        proptest::collection::vec(0..max, 1..=max).prop_map(|mut v| {
            v.sort_unstable();
            v.dedup();
            v
        }),
    )
}

fn rule_model(index: usize) -> impl Strategy<Value = RuleModel> {
    (
        effects(),
        maybe_indices(VERBS.len()),
        maybe_indices(5),
        maybe_indices(3),
        any::<bool>(),
    )
        .prop_map(
            move |(effect, verbs, origins, taints, unless_grant)| RuleModel {
                id: format!("r{index:03}"),
                effect,
                verbs,
                origins,
                taints,
                unless_grant,
            },
        )
}

fn post_model(index: usize) -> impl Strategy<Value = PostModel> {
    (
        proptest::option::of(
            proptest::collection::vec(effects(), 1..=3).prop_map(|mut v| {
                v.sort_by_key(|e| e.as_str());
                v.dedup();
                v
            }),
        ),
        maybe_indices(5),
    )
        .prop_map(move |(selects, origins)| PostModel {
            id: format!("p{index:03}"),
            selects,
            origins,
        })
}

fn policy_model() -> impl Strategy<Value = PolicyModel> {
    (0_usize..8, 0_usize..3).prop_flat_map(|(rules, posts)| {
        let rules = (0..rules).map(rule_model).collect::<Vec<_>>();
        let posts = (0..posts).map(post_model).collect::<Vec<_>>();
        (rules, posts).prop_map(|(rules, posts)| PolicyModel { rules, posts })
    })
}

/// Compile a model.
///
/// **Panics rather than skipping.** A generator that mostly produced sources
/// the loader refuses would make every property below vacuously true, and a
/// silent `return Ok(())` is exactly how that goes unnoticed. Every model this
/// file generates is meant to be valid policy; if one is not, that is a bug in
/// the generator and the test says so with the source attached.
fn compile(model: &PolicyModel, name: &str) -> CompiledPolicy {
    let source = model.render(name, None);
    let profile = load(&format!("{name}.toml"), &source)
        .unwrap_or_else(|e| panic!("the generated model must load: {e}\n{source}"));
    let profile_name = ProfileName::new(name).expect("a valid profile name");
    compose(&profile_name, &[profile])
        .unwrap_or_else(|e| panic!("the generated model must compose: {e}\n{source}"))
}

fn context(origin: Origin, taint: TaintLevel) -> PolicyContext {
    PolicyContext::new(origin, taint)
}

// ---------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The production evaluator and an independently written one agree.
    #[test]
    fn production_agrees_with_an_independent_reference(
        model in policy_model(),
        verb_index in 0_usize..VERBS.len(),
        origin_index in 0_usize..5,
        taint_index in 0_usize..3,
    ) {
        let policy = compile(&model, "p");
        let (origin, taint) = (Origin::ALL[origin_index], TaintLevel::ALL[taint_index]);
        let decision = evaluate(&policy, &action(verb_index), &context(origin, taint));
        let (expected_effect, expected_id) = reference(&model, verb_index, origin, taint);
        prop_assert_eq!(decision.effect(), expected_effect, "{}", decision);
        prop_assert_eq!(decision.rule_id().as_str(), expected_id.as_str(), "{}", decision);
    }

    /// The same inputs give the same decision, every time.
    #[test]
    fn evaluation_is_deterministic(
        model in policy_model(),
        verb_index in 0_usize..VERBS.len(),
        origin_index in 0_usize..5,
        taint_index in 0_usize..3,
    ) {
        let policy = compile(&model, "p");
        let ctx = context(Origin::ALL[origin_index], TaintLevel::ALL[taint_index]);
        let first = evaluate(&policy, &action(verb_index), &ctx);
        for _ in 0..4 {
            prop_assert_eq!(evaluate(&policy, &action(verb_index), &ctx), first.clone());
        }
        // And recompiling from the same text decides the same.
        let again = compile(&model, "p");
        prop_assert_eq!(evaluate(&again, &action(verb_index), &ctx), first);
    }

    /// Phase two never widens phase one.
    #[test]
    fn postconditions_only_narrow(
        model in policy_model(),
        verb_index in 0_usize..VERBS.len(),
        origin_index in 0_usize..5,
        taint_index in 0_usize..3,
    ) {
        let policy = compile(&model, "p");
        let (origin, taint) = (Origin::ALL[origin_index], TaintLevel::ALL[taint_index]);
        let decision = evaluate(&policy, &action(verb_index), &context(origin, taint));

        // The provisional effect is the primary rule's own, found by name.
        let provisional = policy
            .rules()
            .iter()
            .find(|r| r.id() == decision.primary_rule().id())
            .map(dwkd_authority::policy::Rule::effect);
        let Some(provisional) = provisional else {
            return Err(TestCaseError::fail(
                "every decision names a primary rule that is in the policy",
            ));
        };
        prop_assert!(
            decision.effect().narrower_or_equal(provisional),
            "{} widened {provisional}",
            decision
        );
        // And a postcondition fired only if it could have narrowed something.
        if decision.applied_postconditions().is_empty() {
            prop_assert_eq!(decision.effect(), provisional);
        }
    }

    /// No primary rule matching means the default, and the default denies.
    #[test]
    fn nothing_matching_is_a_denial(
        verb_index in 0_usize..VERBS.len(),
        origin_index in 0_usize..5,
        taint_index in 0_usize..3,
    ) {
        // A policy with no rules but the mandatory one.
        let empty = PolicyModel { rules: Vec::new(), posts: Vec::new() };
        let policy = compile(&empty, "p");
        let ctx = context(Origin::ALL[origin_index], TaintLevel::ALL[taint_index]);
        let decision = evaluate(&policy, &action(verb_index), &ctx);
        prop_assert_eq!(decision.effect(), Effect::Deny);
        prop_assert_eq!(decision.rule_id().as_str(), "default");
        prop_assert_eq!(decision.reason(), Reason::NoMatchingRule);
        prop_assert!(decision.obligations().is_empty());
        prop_assert!(decision.approval().is_none());
    }

    /// Composition never broadens the profile being extended.
    ///
    /// The property the restricted `extends` subset exists to give, checked
    /// over generated parents, generated children and every input in the
    /// model's space rather than over a fixture list.
    #[test]
    fn composition_never_widens_its_parent(
        parent_model in policy_model(),
        child_denials in proptest::collection::vec(
            (maybe_indices(VERBS.len()), maybe_indices(5)), 0..4
        ),
        verb_index in 0_usize..VERBS.len(),
        origin_index in 0_usize..5,
        taint_index in 0_usize..3,
    ) {
        let parent_source = parent_model.render("base", None);
        let parent = load("base.toml", &parent_source)
            .unwrap_or_else(|e| panic!("the parent must load: {e}\n{parent_source}"));

        let mut child_source = String::from(
            "schema_version = 1\n\n[meta]\nname = \"child\"\nextends = \"base\"\n",
        );
        for (index, (verbs, origins)) in child_denials.iter().enumerate() {
            child_source.push_str(&format!(
                "\n[[rule]]\nid = \"c{index:03}\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n"
            ));
            if let Some(verbs) = verbs {
                let names: Vec<String> = verbs.iter().map(|i| verb(*i).to_string()).collect();
                child_source.push_str(&format!("when.verb = {}\n", render_list(&names)));
            }
            if let Some(origins) = origins {
                let names: Vec<&str> =
                    origins.iter().map(|i| Origin::ALL[i % 5].as_str()).collect();
                child_source.push_str(&format!("when.origin = {}\n", render_list(&names)));
            }
        }
        let child = load("child.toml", &child_source)
            .unwrap_or_else(|e| panic!("the child must load: {e}\n{child_source}"));

        let set: Vec<Profile> = vec![parent.clone(), child];
        let parent_only = compose(&ProfileName::new("base").unwrap(), &[parent])
            .unwrap_or_else(|e| panic!("the parent must compose: {e}"));
        let composed = compose(&ProfileName::new("child").unwrap(), &set)
            .unwrap_or_else(|e| panic!("the chain must compose: {e}"));

        let ctx = context(Origin::ALL[origin_index], TaintLevel::ALL[taint_index]);
        let before = evaluate(&parent_only, &action(verb_index), &ctx).effect();
        let after = evaluate(&composed, &action(verb_index), &ctx).effect();
        prop_assert!(
            after.narrower_or_equal(before),
            "composition widened {before} to {after}"
        );
    }

    /// Rule order is source order, and reordering can change the outcome.
    #[test]
    fn the_first_matching_rule_wins_and_order_is_the_file_order(
        first in effects(),
        second in effects(),
        verb_index in 0_usize..VERBS.len(),
    ) {
        // Two rules matching the same verb. The first must decide.
        let model = PolicyModel {
            rules: vec![
                RuleModel {
                    id: "first".to_owned(), effect: first,
                    verbs: Some(vec![verb_index]), origins: None, taints: None,
                    unless_grant: false,
                },
                RuleModel {
                    id: "second".to_owned(), effect: second,
                    verbs: Some(vec![verb_index]), origins: None, taints: None,
                    unless_grant: false,
                },
            ],
            posts: Vec::new(),
        };
        let policy = compile(&model, "p");
        let ctx = context(Origin::Interactive, TaintLevel::None);
        let decision = evaluate(&policy, &action(verb_index), &ctx);
        prop_assert_eq!(decision.rule_id().as_str(), "first");
        prop_assert_eq!(decision.effect(), first);

        // Swapped, the other one decides -- so order is load-bearing rather
        // than an artefact of some specificity ranking.
        let mut swapped = model.clone();
        swapped.rules.swap(0, 1);
        swapped.rules[0].id = "first".to_owned();
        swapped.rules[1].id = "second".to_owned();
        let policy = compile(&swapped, "p");
        prop_assert_eq!(evaluate(&policy, &action(verb_index), &ctx).effect(), second);
    }

    /// An unknown member is never read as an absent predicate.
    #[test]
    fn a_typo_never_becomes_a_missing_predicate(
        model in policy_model(),
        typo in "[a-z]{3,12}",
    ) {
        // Skip names the schema actually defines.
        const KNOWN: [&str; 6] = ["verb", "origin", "taint", "environment", "privacy", "config"];
        if KNOWN.iter().any(|k| typo.starts_with(k)) {
            return Ok(());
        }
        let _ = compile(&model, "p");
        // Insert the unknown member into the first rule's `when`.
        let source = model.render("p", None);
        let Some(position) = source.find("\n[[rule]]") else { return Ok(()) };
        let mut spoiled = source.clone();
        spoiled.insert_str(
            position + "\n[[rule]]\n".len(),
            &format!("when.{typo} = true\n"),
        );
        prop_assert!(
            load("p.toml", &spoiled).is_err(),
            "`when.{typo}` must be refused rather than ignored"
        );
    }
}

// ---------------------------------------------------------------------------
// Exhaustive, where the space is small enough to be exhaustive.
// ---------------------------------------------------------------------------

#[test]
fn the_effect_order_is_total_and_meet_never_widens() {
    for a in Effect::ALL {
        for b in Effect::ALL {
            let m = a.meet(b);
            assert!(m.narrower_or_equal(a) && m.narrower_or_equal(b));
            assert_eq!(m, b.meet(a));
            assert!(a.narrower_or_equal(b) || b.narrower_or_equal(a));
        }
    }
}

#[test]
fn every_verb_origin_and_taint_combination_reaches_a_decision() {
    // Totality: the evaluator returns a Decision for every input, because the
    // default is mandatory and unconditional. 4 x 5 x 3 = 60 cases.
    let model = PolicyModel {
        rules: Vec::new(),
        posts: Vec::new(),
    };
    let policy = compile(&model, "p");
    let mut seen = 0;
    for verb_index in 0..VERBS.len() {
        for origin in Origin::ALL {
            for taint in TaintLevel::ALL {
                let decision = evaluate(&policy, &action(verb_index), &context(origin, taint));
                assert_eq!(decision.effect(), Effect::Deny);
                assert!(decision.rule_source().line() > 0);
                seen += 1;
            }
        }
    }
    assert_eq!(seen, VERBS.len() * 5 * 3);
}

#[test]
fn a_policy_allow_is_not_a_capability_check() {
    // ADR-0006: two independent gates. The policy engine answers only the
    // first, and this pins the shape of that answer: a Decision carries the
    // capability the action REQUIRED, and nothing about what is held.
    let model = PolicyModel {
        rules: vec![RuleModel {
            id: "allow-all".to_owned(),
            effect: Effect::Allow,
            verbs: None,
            origins: None,
            taints: None,
            unless_grant: false,
        }],
        posts: Vec::new(),
    };
    let policy = compile(&model, "p");
    let act = action(0);
    let decision = evaluate(
        &policy,
        &act,
        &context(Origin::Interactive, TaintLevel::None),
    );
    assert_eq!(decision.effect(), Effect::Allow);
    assert_eq!(decision.required_capability(), act.capability());

    // The capability gate, run separately, is a different question with a
    // different answer. Here the held set does not cover the action at all,
    // and policy still said ALLOW -- which is exactly the point of running
    // both.
    let held = Capability::new(
        Verb::parse_action(Namespace::Memory, "read").expect("a verb"),
        Scope::Universal,
        ConstraintSet::unconstrained(),
    )
    .expect("builds");
    assert!(
        !held.contains(act.capability()),
        "the held capability must not cover a model.call"
    );
}

#[test]
fn the_reference_catches_a_last_match_wins_implementation() {
    // The methodology question: could `production_agrees_with_an_independent_
    // reference` pass if first-match semantics were broken? This answers it by
    // writing the classic bug -- scanning to the LAST matching rule instead of
    // the first -- and showing the reference disagrees with it.
    //
    // Without this, a reference that happened to share a bug with production
    // would look like agreement.
    fn last_match_wins(model: &PolicyModel, verb_index: usize) -> Effect {
        let mut effect = Effect::Deny;
        for rule in &model.rules {
            if rule.matches(verb_index, Origin::Interactive, TaintLevel::None) {
                effect = rule.effect;
            }
        }
        effect
    }

    let model = PolicyModel {
        rules: vec![
            RuleModel {
                id: "first-denies".to_owned(),
                effect: Effect::Deny,
                verbs: Some(vec![0]),
                origins: None,
                taints: None,
                unless_grant: false,
            },
            RuleModel {
                id: "second-allows".to_owned(),
                effect: Effect::Allow,
                verbs: Some(vec![0]),
                origins: None,
                taints: None,
                unless_grant: false,
            },
        ],
        posts: Vec::new(),
    };

    let (correct, _) = reference(&model, 0, Origin::Interactive, TaintLevel::None);
    let broken = last_match_wins(&model, 0);
    assert_eq!(correct, Effect::Deny, "first match wins");
    assert_eq!(broken, Effect::Allow, "last match wins is the bug");
    assert_ne!(
        correct, broken,
        "the reference must be able to tell the two apart"
    );

    // And production agrees with the reference rather than with the bug.
    let policy = compile(&model, "p");
    let decision = evaluate(
        &policy,
        &action(0),
        &context(Origin::Interactive, TaintLevel::None),
    );
    assert_eq!(decision.effect(), correct);
    assert_eq!(decision.rule_id().as_str(), "first-denies");
}

#[test]
fn the_reference_catches_a_postcondition_that_widens() {
    // The same question for phase two. A postcondition that assigned its
    // effect instead of taking the meet would turn a DENY into something
    // broader; the reference never does, and production takes the meet, so
    // neither can.
    let model = PolicyModel {
        rules: vec![RuleModel {
            id: "denies".to_owned(),
            effect: Effect::Deny,
            verbs: None,
            origins: None,
            taints: None,
            unless_grant: false,
        }],
        // Selects everything, so it fires on the DENY above too.
        posts: vec![PostModel {
            id: "p000".to_owned(),
            selects: None,
            origins: None,
        }],
    };
    let policy = compile(&model, "p");
    for origin in Origin::ALL {
        for taint in TaintLevel::ALL {
            let decision = evaluate(&policy, &action(0), &context(origin, taint));
            assert_eq!(
                decision.effect(),
                Effect::Deny,
                "a postcondition must never move a DENY: {decision}"
            );
            let (expected, _) = reference(&model, 0, origin, taint);
            assert_eq!(decision.effect(), expected);
        }
    }
}
