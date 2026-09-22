//! `extends`: what composes, and what must fail at load.
//!
//! [`POLICY.md`] §7: "A profile may only *narrow* the profile it `extends`.
//! Attempting to widen fails at load time with an error naming both rules."
//!
//! The V1 subset that makes that decidable is one sentence — **an extending
//! profile may only add `DENY` rules** — and its consequence is two lines:
//! first-match over the concatenated chain returns either a child rule, whose
//! effect is the bottom of the lattice and therefore `⊑` anything, or the
//! parent's own result unchanged. So `composed(a) ⊑ parent(a)` for every `a`,
//! quantified over the whole input space rather than over a fixture suite.
//!
//! This file checks the refusals. `policy_properties.rs` checks the
//! consequence over generated input.
//!
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
use sha2 as _;

// As above, for the property-test dev-dependency.
use proptest as _;

use dwkd_authority::policy::{Effect, PolicyLoadError, Profile, ProfileName, compose, load};

/// A parent with one denial, one allowance and the mandatory default.
const PARENT: &str = "\
schema_version = 1

[meta]
name = \"base\"

[[rule]]
id = \"base-deny-secrets\"
effect = \"DENY\"
reason = \"SENSITIVE_PATH\"
when.verb = [\"fs.read\"]
when.path_under = [\"~/.ssh\"]

[[rule]]
id = \"base-allow-model\"
effect = \"ALLOW\"
when.verb = \"model.call\"

[[rule]]
id = \"default\"
effect = \"DENY\"
reason = \"NO_MATCHING_RULE\"
";

/// A child extending `base` with `body`.
fn child(body: &str) -> String {
    format!("schema_version = 1\n\n[meta]\nname = \"child\"\nextends = \"base\"\n{body}")
}

fn profiles(child_body: &str) -> Vec<Profile> {
    vec![
        load("base.toml", PARENT).expect("the parent loads"),
        load("child.toml", &child(child_body)).expect("the child loads"),
    ]
}

fn name(text: &str) -> ProfileName {
    ProfileName::new(text).expect("a valid profile name")
}

fn compose_child(
    child_body: &str,
) -> Result<dwkd_authority::policy::CompiledPolicy, PolicyLoadError> {
    compose(&name("child"), &profiles(child_body))
}

// ---------------------------------------------------------------------------
// What composes.
// ---------------------------------------------------------------------------

#[test]
fn a_child_that_only_adds_denials_composes_child_first() {
    let policy = compose_child(
        "\n[[rule]]\nid = \"child-deny-exec\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
         when.verb = [\"process.exec\"]\n",
    )
    .expect("a narrowing extension composes");

    let ids: Vec<&str> = policy.rules().iter().map(|r| r.id().as_str()).collect();
    assert_eq!(
        ids,
        [
            "child-deny-exec",
            "base-deny-secrets",
            "base-allow-model",
            "default"
        ],
        "the child's rules evaluate first, then the parent's"
    );
    assert_eq!(
        policy
            .chain()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["child", "base"]
    );
    // The parent owns the default, and it is still last.
    assert!(policy.default_rule().is_some());
    assert_eq!(policy.rules().last().unwrap().effect(), Effect::Deny);
}

#[test]
fn a_child_may_add_a_narrowing_postcondition() {
    let policy = compose_child(
        "\n[[postcondition]]\nid = \"child-unattended\"\neffect = \"DENY\"\n\
         reason = \"NO_HUMAN_AVAILABLE\"\nwhen.provisional_effect = [\"REQUIRE_APPROVAL\"]\n",
    )
    .expect("a DENY postcondition composes");
    assert_eq!(policy.postconditions().len(), 1);
    assert_eq!(policy.postconditions()[0].effect(), Effect::Deny);
}

#[test]
fn an_extending_profile_may_add_nothing_but_postconditions() {
    // No `[[rule]]` array at all. Legal, because the default belongs to the
    // root of the chain and this profile adds only a phase-two narrowing.
    let source = child(
        "\n[[postcondition]]\nid = \"child-p\"\neffect = \"DENY\"\n\
         reason = \"NO_HUMAN_AVAILABLE\"\nwhen.provisional_effect = [\"REQUIRE_APPROVAL\"]\n",
    );
    let profile = load("child.toml", &source).expect("an extender needs no rules");
    assert!(profile.rules().is_empty());
    let set = vec![load("base.toml", PARENT).expect("loads"), profile];
    let policy = compose(&name("child"), &set).expect("composes");
    assert_eq!(policy.rules().len(), 3, "the parent's rules, unchanged");
    assert_eq!(policy.postconditions().len(), 1);
}

#[test]
fn a_profile_with_no_extends_composes_as_itself() {
    let base = load("base.toml", PARENT).expect("loads");
    let policy = compose(&name("base"), &[base]).expect("composes");
    assert_eq!(policy.chain().len(), 1);
    assert_eq!(policy.rules().len(), 3);
}

// ---------------------------------------------------------------------------
// Every widening attempt the brief names. All must fail at LOAD.
// ---------------------------------------------------------------------------

#[test]
fn a_child_allow_is_refused() {
    // "override parent DENY with ALLOW". The child cannot know whether its
    // rule shadows a parent denial, and the loader cannot decide it in
    // general, so the whole shape is refused.
    let error = compose_child(
        "\n[[rule]]\nid = \"child-allow-secrets\"\neffect = \"ALLOW\"\n\
         when.verb = [\"fs.read\"]\nwhen.path_under = [\"~/.ssh\"]\n",
    )
    .expect_err("a child ALLOW must be refused");
    match error {
        PolicyLoadError::WideningExtension { id, at, detail } => {
            assert_eq!(id, "child-allow-secrets");
            assert_eq!(at.source(), "child.toml");
            assert!(at.line() > 0);
            assert!(detail.contains("DENY"), "{detail}");
        }
        other => panic!("expected a widening refusal, got {other}"),
    }
}

#[test]
fn a_child_require_approval_is_refused() {
    // "override parent DENY with REQUIRE_APPROVAL". REQUIRE_APPROVAL is not
    // the bottom of the lattice, so it is not narrower than every result the
    // parent could return.
    let error = compose_child(
        "\n[[rule]]\nid = \"child-approve\"\neffect = \"REQUIRE_APPROVAL\"\n\
         reason = \"SENSITIVE_PATH\"\nwhen.verb = [\"fs.read\"]\nwhen.path_under = [\"~/.ssh\"]\n\
         approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n",
    )
    .expect_err("a child REQUIRE_APPROVAL must be refused");
    assert!(matches!(error, PolicyLoadError::WideningExtension { .. }));
}

#[test]
fn a_child_cannot_replace_the_default() {
    // "replace a restrictive default with ALLOW", and the narrower version of
    // the same thing: a child `default` at all, of any effect. The chain would
    // otherwise hold two rules each claiming to be the one that always
    // matches, and the second would be unreachable -- a denial an operator
    // believes is in force and is not.
    //
    // The refusal is at LOAD rather than at composition, because a profile
    // declaring `extends` is already known to be an extender without
    // resolving the chain. That is strictly earlier than the requirement asks
    // for, and it means a child default is refused even if it is never
    // composed with anything.
    for effect in ["ALLOW", "DENY", "REQUIRE_APPROVAL"] {
        let reason = match effect {
            "ALLOW" => String::new(),
            "DENY" => "reason = \"NO_MATCHING_RULE\"\n".to_owned(),
            _ => "reason = \"UNKNOWN_EXECUTABLE\"\napproval.scope = \"exact_action\"\n\
                  approval.ttl = \"1h\"\napproval.max_uses = 1\n"
                .to_owned(),
        };
        let source = child(&format!(
            "\n[[rule]]\nid = \"default\"\neffect = \"{effect}\"\n{reason}"
        ));
        match load("child.toml", &source) {
            Err(PolicyLoadError::ExtendsRedeclaresDefault { at }) => {
                assert_eq!(at.source(), "child.toml");
                assert!(at.line() > 0);
            }
            other => panic!("a child `default` of {effect} must be refused, got {other:?}"),
        }
    }

    // And the root of a chain still must have one.
    let rootless = "schema_version = 1\n\n[meta]\nname = \"base\"\n\
                    \n[[rule]]\nid = \"base-r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n";
    assert!(matches!(
        load("base.toml", rootless),
        Err(PolicyLoadError::DefaultRuleMissing { .. })
    ));
}

#[test]
fn a_child_cannot_shadow_a_parent_rule_id() {
    // "shadow a parent hard-denial". A child DENY could not widen anything,
    // but taking the parent's id would make an audit record name a rule the
    // reader looks up in the wrong file.
    let error = compose_child(
        "\n[[rule]]\nid = \"base-deny-secrets\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
         when.verb = [\"memory.read\"]\n",
    )
    .expect_err("shadowing an id must be refused");
    match error {
        PolicyLoadError::ExtendsShadowsRuleId { id, parent, .. } => {
            assert_eq!(id, "base-deny-secrets");
            assert_eq!(parent, "base");
        }
        other => panic!("expected a shadowing refusal, got {other}"),
    }
}

#[test]
fn there_is_no_syntax_for_removing_a_parent_rule() {
    // "remove a parent restriction". There is no `remove`, `disable`,
    // `override` or `delete` member at any level, so each of these is an
    // unknown field rather than an operation.
    for member in [
        "remove = [\"base-deny-secrets\"]",
        "disable = [\"base-deny-secrets\"]",
        "override = { \"base-deny-secrets\" = \"ALLOW\" }",
        "delete_rules = [\"base-deny-secrets\"]",
    ] {
        let source = child(&format!("{member}\n"));
        match load("child.toml", &source) {
            Err(PolicyLoadError::UnknownField { .. }) => {}
            other => panic!("{member} must be an unknown field, got {other:?}"),
        }
    }
}

#[test]
fn a_child_cannot_move_a_broader_rule_ahead_of_a_narrower_one() {
    // "move a broader rule ahead of a narrower one". Ordering is source order
    // within a file and child-then-parent across the chain; there is no
    // priority, weight or `before`/`after` member to reorder with, and the
    // only rules a child may place ahead of the parent's are denials.
    for member in [
        "priority = 1",
        "weight = 10",
        "before = \"base-deny-secrets\"",
        "order = 0",
    ] {
        let source = child(&format!(
            "\n[[rule]]\nid = \"child-x\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
             when.verb = [\"memory.read\"]\n{member}\n"
        ));
        assert!(
            matches!(
                load("child.toml", &source),
                Err(PolicyLoadError::UnknownField { .. })
            ),
            "{member} must be an unknown field"
        );
    }
}

// ---------------------------------------------------------------------------
// Chains.
// ---------------------------------------------------------------------------

#[test]
fn a_self_cycle_is_detected() {
    // No `default` here: a profile declaring `extends` must not carry one, and
    // the cycle is what this test is about.
    let source = "schema_version = 1\n\n[meta]\nname = \"loop\"\nextends = \"loop\"\n\
                  \n[[rule]]\nid = \"loop-r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
                  when.verb = \"memory.read\"\n";
    let profile = load("loop.toml", source).expect("loads");
    match compose(&name("loop"), &[profile]) {
        Err(PolicyLoadError::ExtendsCycle { chain }) => {
            assert_eq!(chain, ["loop", "loop"]);
        }
        other => panic!("expected a cycle, got {other:?}"),
    }
}

#[test]
fn a_longer_cycle_is_detected() {
    let make = |this: &str, parent: &str| {
        let source = format!(
            "schema_version = 1\n\n[meta]\nname = \"{this}\"\nextends = \"{parent}\"\n\
             \n[[rule]]\nid = \"{this}-r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"memory.read\"\n"
        );
        load(&format!("{this}.toml"), &source).expect("loads")
    };
    // a -> b -> c -> a
    let set = vec![make("a", "b"), make("b", "c"), make("c", "a")];
    match compose(&name("a"), &set) {
        Err(PolicyLoadError::ExtendsCycle { chain }) => {
            assert_eq!(chain.first().map(String::as_str), Some("a"));
            assert_eq!(chain.last().map(String::as_str), Some("a"));
            assert!(chain.len() >= 4, "{chain:?}");
        }
        other => panic!("expected a cycle, got {other:?}"),
    }
}

#[test]
fn a_chain_deeper_than_the_bound_is_refused() {
    let mut set = Vec::new();
    for index in 0..8 {
        let source = format!(
            "schema_version = 1\n\n[meta]\nname = \"p{index}\"\nextends = \"p{}\"\n\
             \n[[rule]]\nid = \"p{index}-r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"memory.read\"\n",
            index + 1
        );
        set.push(load(&format!("p{index}.toml"), &source).expect("loads"));
    }
    match compose(&name("p0"), &set) {
        Err(PolicyLoadError::ExtendsTooDeep { limit, chain }) => {
            assert!(chain.len() > limit, "{chain:?} vs {limit}");
        }
        other => panic!("expected a depth refusal, got {other:?}"),
    }
}

#[test]
fn extending_a_profile_the_load_was_not_given_is_refused() {
    let profile = load("child.toml", &child("")).expect("loads");
    match compose(&name("child"), &[profile]) {
        Err(PolicyLoadError::ExtendsUnknownProfile { name, .. }) => assert_eq!(name, "base"),
        other => panic!("expected an unknown-profile refusal, got {other:?}"),
    }
}

#[test]
fn composing_a_profile_that_was_not_supplied_is_refused() {
    match compose(&name("absent"), &[]) {
        Err(PolicyLoadError::ExtendsUnknownProfile { name, .. }) => assert_eq!(name, "absent"),
        other => panic!("expected an unknown-profile refusal, got {other:?}"),
    }
}

#[test]
fn a_chain_whose_root_has_no_default_is_refused() {
    let rootless = "schema_version = 1\n\n[meta]\nname = \"base\"\n\
                    \n[[rule]]\nid = \"base-r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"memory.read\"\n";
    // The loader refuses it on its own, before composition can see it: a
    // profile with no default is not a profile.
    assert!(matches!(
        load("base.toml", rootless),
        Err(PolicyLoadError::DefaultRuleMissing { .. })
    ));
}

// ---------------------------------------------------------------------------
// Determinism.
// ---------------------------------------------------------------------------

#[test]
fn composition_is_deterministic_and_independent_of_the_order_supplied() {
    let body = "\n[[rule]]\nid = \"child-deny\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
                when.verb = [\"process.exec\"]\n";
    let forward = compose(&name("child"), &profiles(body)).expect("composes");
    let mut reversed = profiles(body);
    reversed.reverse();
    let backward = compose(&name("child"), &reversed).expect("composes");
    assert_eq!(
        forward, backward,
        "the order profiles are handed in must not change the policy"
    );
    for _ in 0..8 {
        assert_eq!(
            compose(&name("child"), &profiles(body)).expect("composes"),
            forward
        );
    }
}
