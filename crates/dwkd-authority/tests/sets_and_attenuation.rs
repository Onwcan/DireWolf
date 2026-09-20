//! Capability sets, no-synthesis, and attenuation.
//!
//! The three claims here are the ones an escalation would break first:
//!
//! * `A ⊑ B` quantifies over **whole** parents, so fragments of two held
//!   capabilities never combine into a third.
//! * A successful attenuation is always contained by its parent.
//! * There is no widening operation, at any visibility.

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

mod common;

use common::{agent_spawn, constraints, fs_read, fs_write, host, plain, resolved};
use dwkd_authority::capability::{
    AttenuationError, Capability, CapabilitySet, ConstraintSet, Method, MethodSet, Narrowing,
    PrivacyClass, Scope, attenuate,
};

fn methods(list: &[Method]) -> MethodSet {
    MethodSet::new(list).expect("non-empty")
}

fn set(items: &[Capability]) -> CapabilitySet {
    CapabilitySet::from_capabilities(items.iter().cloned())
}

// ---------------------------------------------------------------------------
// The set itself.
// ---------------------------------------------------------------------------

#[test]
fn the_empty_set_is_the_bottom_of_the_lattice() {
    let empty = CapabilitySet::empty();
    assert!(empty.is_empty());
    for other in [
        CapabilitySet::empty(),
        set(&[plain(fs_read(), Scope::Universal)]),
        set(&[
            resolved("network.https:*.example.com"),
            plain(agent_spawn(), Scope::Universal),
        ]),
    ] {
        assert!(empty.is_contained_by(&other), "∅ ⊑ A must hold for every A");
    }
    // And nothing non-empty is contained by ∅.
    let something = set(&[plain(fs_read(), Scope::Universal)]);
    assert!(!something.is_contained_by(&CapabilitySet::empty()));
}

#[test]
fn set_equality_does_not_depend_on_insertion_order() {
    let a = resolved("network.https:api.example.com");
    let b = plain(fs_read(), Scope::Universal);
    let c = plain(agent_spawn(), Scope::Universal);

    let forwards = set(&[a.clone(), b.clone(), c.clone()]);
    let backwards = set(&[c, b, a]);
    assert_eq!(forwards, backwards);
    assert_eq!(
        forwards.to_canonical_string(),
        backwards.to_canonical_string()
    );
    assert_eq!(forwards.capabilities(), backwards.capabilities());
}

#[test]
fn identical_sets_contain_each_other() {
    let s = set(&[
        resolved("network.https:*.example.com?methods=GET"),
        resolved("secret.use:github-primary"),
    ]);
    assert!(s.is_contained_by(&s));
    assert!(s.contains_set(&s));
}

#[test]
fn a_subset_is_contained_and_a_superset_is_not() {
    let small = set(&[resolved("network.https:api.example.com?methods=GET")]);
    let large = set(&[
        resolved("network.https:*.example.com?methods=GET,POST"),
        resolved("agent.spawn:research*"),
    ]);
    assert!(small.is_contained_by(&large));
    assert!(!large.is_contained_by(&small));
}

#[test]
fn a_set_missing_one_verb_does_not_contain_a_set_that_has_it() {
    let with_network = set(&[
        plain(fs_read(), Scope::Universal),
        resolved("network.https:*.example.com"),
    ]);
    let without = set(&[plain(fs_read(), Scope::Universal)]);
    assert!(without.is_contained_by(&with_network));
    assert!(!with_network.is_contained_by(&without));
}

// ---------------------------------------------------------------------------
// No synthesis. §42's regression classes, as named tests.
// ---------------------------------------------------------------------------

#[test]
fn two_method_sets_do_not_combine_into_their_union() {
    // Class A. Holding GET on a host and POST on the same host is not holding
    // GET+POST: the requested capability must be covered by one parent, and
    // neither parent's method set is a superset of {GET, POST}.
    let held = set(&[
        resolved("network.https:api.example.com?methods=GET"),
        resolved("network.https:api.example.com?methods=POST"),
    ]);
    let wanted = resolved("network.https:api.example.com?methods=GET,POST");
    assert!(!held.covers(&wanted), "method sets must not union");

    // Each half is covered, which is what makes the union look reachable.
    assert!(held.covers(&resolved("network.https:api.example.com?methods=GET")));
    assert!(held.covers(&resolved("network.https:api.example.com?methods=POST")));

    // And a single parent that genuinely holds both does cover it.
    let genuine = set(&[resolved("network.https:api.example.com?methods=GET,POST")]);
    assert!(genuine.covers(&wanted));
}

#[test]
fn a_broad_scope_and_a_broad_constraint_do_not_combine() {
    // Class B. One parent has the wide scope, another has the wide method set,
    // and the request takes the wide half of each. Neither parent covers it:
    // parent A's methods are a proper subset of the request's, and parent B's
    // scope does not cover the request's.
    let held = set(&[
        resolved("network.https:*.example.com?methods=GET"),
        resolved("network.https:api.example.com?methods=GET,POST"),
    ]);
    let wanted = resolved("network.https:*.example.com?methods=GET,POST");
    assert!(
        !held.covers(&wanted),
        "scope and constraints must not cross"
    );

    // Independently: each parent fails for its own reason.
    let wide_scope = resolved("network.https:*.example.com?methods=GET");
    let wide_methods = resolved("network.https:api.example.com?methods=GET,POST");
    assert!(!wide_scope.contains(&wanted), "methods too wide");
    assert!(!wide_methods.contains(&wanted), "scope too wide");
}

#[test]
fn two_numeric_limits_do_not_combine_into_the_larger() {
    // The same attack on a counter rather than a set.
    let held = set(&[
        resolved("network.https:api.example.com?max_requests=10&methods=GET"),
        resolved("network.https:api.example.com?max_requests=100&methods=POST"),
    ]);
    let wanted = resolved("network.https:api.example.com?max_requests=100&methods=GET");
    assert!(!held.covers(&wanted), "limits must not cross capabilities");

    let genuine = set(&[resolved(
        "network.https:api.example.com?max_requests=100&methods=GET,POST",
    )]);
    assert!(genuine.covers(&wanted));
}

// ---------------------------------------------------------------------------
// Attenuation.
// ---------------------------------------------------------------------------

#[test]
fn attenuating_by_nothing_returns_the_same_authority() {
    let parent = resolved("network.https:*.example.com?methods=GET,POST");
    let child = attenuate(&parent, &Narrowing::none()).expect("identity narrowing");
    assert_eq!(child, parent);
    assert!(parent.contains(&child));
}

#[test]
fn attenuating_to_a_narrower_scope_succeeds() {
    let parent = resolved("network.https:*.example.com");
    let child = attenuate(&parent, &Narrowing::to_scope(host("api.example.com")))
        .expect("a subdomain is narrower");
    assert!(parent.contains(&child));
    assert_eq!(child.to_canonical_string(), "network.https:api.example.com");
}

#[test]
fn attenuating_to_a_wider_scope_is_refused() {
    let parent = resolved("network.https:api.example.com");
    assert_eq!(
        attenuate(&parent, &Narrowing::to_scope(host("*.example.com"))),
        Err(AttenuationError::WouldWiden)
    );
    assert_eq!(
        attenuate(&parent, &Narrowing::to_scope(Scope::Universal)),
        Err(AttenuationError::WouldWiden)
    );
}

#[test]
fn adding_a_constraint_the_parent_did_not_have_succeeds() {
    // Rule A, as an operation: the parent was unconstrained, so any limit is a
    // narrowing.
    let parent = resolved("network.https:api.example.com");
    let child = attenuate(
        &parent,
        &Narrowing::with_constraints(constraints(|c| c.max_requests = Some(10))),
    )
    .expect("adding a limit narrows");
    assert!(parent.contains(&child));
    assert_eq!(child.constraints().max_requests, Some(10));
}

#[test]
fn tightening_a_constraint_succeeds_and_loosening_one_is_refused() {
    let parent = resolved("network.https:api.example.com?max_requests=100");
    assert!(
        attenuate(
            &parent,
            &Narrowing::with_constraints(constraints(|c| c.max_requests = Some(10))),
        )
        .is_ok()
    );
    assert_eq!(
        attenuate(
            &parent,
            &Narrowing::with_constraints(constraints(|c| c.max_requests = Some(1000))),
        ),
        Err(AttenuationError::WouldWiden)
    );
}

#[test]
fn a_narrowing_cannot_drop_a_constraint_the_parent_had() {
    // There is no spelling for "remove this constraint": `Narrowing` carries
    // values to set, and an absent field means "leave the parent's". So the
    // only way to reach the wider capability is to build it and ask to
    // delegate, which is refused.
    let parent = resolved("network.https:api.example.com?max_requests=100");
    let wider = resolved("network.https:api.example.com");
    assert_eq!(
        dwkd_authority::capability::attenuate::delegate(&parent, &wider),
        Err(AttenuationError::WouldWiden)
    );
    // And attenuating with an empty narrowing keeps it.
    let same = attenuate(&parent, &Narrowing::none()).expect("identity");
    assert_eq!(same.constraints().max_requests, Some(100));
}

#[test]
fn attenuation_cannot_change_the_verb() {
    let parent = plain(fs_read(), Scope::Universal);
    let other = plain(fs_write(), Scope::Universal);
    assert_eq!(
        dwkd_authority::capability::attenuate::delegate(&parent, &other),
        Err(AttenuationError::VerbChanged)
    );
}

#[test]
fn attenuating_to_a_scope_from_the_wrong_family_is_invalid_not_merely_wider() {
    let parent = plain(fs_read(), Scope::Universal);
    let result = attenuate(&parent, &Narrowing::to_scope(host("example.com")));
    assert!(matches!(result, Err(AttenuationError::Invalid(_))));
}

#[test]
fn attenuation_is_idempotent_where_it_is_defined() {
    let parent = resolved("network.https:*.example.com?methods=GET,POST&max_requests=100");
    let narrowing = Narrowing {
        scope: Some(host("api.example.com")),
        constraints: constraints(|c| {
            c.methods = Some(methods(&[Method::Get]));
            c.max_requests = Some(10);
        }),
    };
    let once = attenuate(&parent, &narrowing).expect("first");
    let twice = attenuate(&once, &narrowing).expect("second");
    assert_eq!(once, twice);
    // And a third time, because "idempotent" should not mean "stable for one
    // extra step".
    assert_eq!(attenuate(&twice, &narrowing).expect("third"), once);
}

#[test]
fn a_long_chain_stays_contained_by_its_root() {
    // Chain monotonicity, by hand: eight steps, each independently a narrowing.
    let root = resolved("network.https:*.example.com");
    let steps: Vec<Narrowing> = vec![
        Narrowing::to_scope(host("*.api.example.com")),
        Narrowing::with_constraints(constraints(|c| c.max_requests = Some(1000))),
        Narrowing::to_scope(host("one.api.example.com")),
        Narrowing::with_constraints(constraints(|c| {
            c.methods = Some(methods(&[Method::Get, Method::Post, Method::Head]));
        })),
        Narrowing::with_constraints(constraints(|c| c.max_requests = Some(100))),
        Narrowing::with_constraints(constraints(|c| {
            c.methods = Some(methods(&[Method::Get, Method::Post]));
        })),
        Narrowing::with_constraints(constraints(|c| c.max_requests = Some(10))),
        Narrowing::with_constraints(constraints(|c| c.methods = Some(methods(&[Method::Get])))),
    ];

    let mut current = root.clone();
    for (index, step) in steps.iter().enumerate() {
        let next = attenuate(&current, step).unwrap_or_else(|e| panic!("step {index}: {e}"));
        assert!(current.contains(&next), "step {index} must narrow");
        assert!(root.contains(&next), "every link stays under the root");
        current = next;
    }
    assert!(root.contains(&current));
    assert!(!current.contains(&root));
    assert_eq!(
        current.to_canonical_string(),
        "network.https:one.api.example.com?methods=GET&max_requests=10"
    );
}

#[test]
fn attenuation_reaches_the_exact_boundary_and_stops_one_past_it() {
    let parent = Capability::new(
        fs_write(),
        Scope::Universal,
        constraints(|c| c.max_bytes = Some(100)),
    )
    .expect("valid");
    // Exactly equal is a narrowing (the reflexive case).
    assert!(
        attenuate(
            &parent,
            &Narrowing::with_constraints(constraints(|c| c.max_bytes = Some(100))),
        )
        .is_ok()
    );
    // One byte past it is not.
    assert_eq!(
        attenuate(
            &parent,
            &Narrowing::with_constraints(constraints(|c| c.max_bytes = Some(101))),
        ),
        Err(AttenuationError::WouldWiden)
    );
}

#[test]
fn every_constraint_can_be_tightened_and_none_can_be_loosened() {
    // One pass over all eight through the attenuation API rather than through
    // `contains`, because the API is what a caller reaches for.
    let cases: Vec<(Capability, ConstraintSet, ConstraintSet)> = vec![
        (
            Capability::new(
                fs_write(),
                Scope::Universal,
                constraints(|c| c.max_bytes = Some(100)),
            )
            .expect("valid"),
            constraints(|c| c.max_bytes = Some(10)),
            constraints(|c| c.max_bytes = Some(1000)),
        ),
        (
            resolved("network.https:h.example.com?methods=GET,POST"),
            constraints(|c| c.methods = Some(methods(&[Method::Get]))),
            constraints(|c| c.methods = Some(methods(&[Method::Get, Method::Post, Method::Put]))),
        ),
        (
            resolved("network.https:h.example.com?max_requests=100"),
            constraints(|c| c.max_requests = Some(10)),
            constraints(|c| c.max_requests = Some(1000)),
        ),
        (
            resolved("model.call:*?privacy_class=VENDOR_OK"),
            constraints(|c| c.privacy_class = Some(PrivacyClass::LocalOnly)),
            constraints(|c| c.privacy_class = Some(PrivacyClass::Any)),
        ),
        (
            resolved("agent.spawn:*?depth=4"),
            constraints(|c| c.depth = Some(1)),
            constraints(|c| c.depth = Some(8)),
        ),
        (
            resolved("agent.spawn:*?fanout=8"),
            constraints(|c| c.fanout = Some(2)),
            constraints(|c| c.fanout = Some(16)),
        ),
    ];
    for (parent, tighter, looser) in cases {
        assert!(
            attenuate(&parent, &Narrowing::with_constraints(tighter)).is_ok(),
            "tightening {parent} must succeed"
        );
        assert_eq!(
            attenuate(&parent, &Narrowing::with_constraints(looser)),
            Err(AttenuationError::WouldWiden),
            "loosening {parent} must be refused"
        );
    }
}

#[test]
fn a_set_built_from_attenuated_children_is_contained_by_the_parent_set() {
    let parents = set(&[
        resolved("network.https:*.example.com?methods=GET,POST"),
        resolved("agent.spawn:research*?depth=4"),
    ]);
    let children = set(&[
        resolved("network.https:api.example.com?methods=GET"),
        resolved("agent.spawn:researcher?depth=1"),
    ]);
    assert!(children.is_contained_by(&parents));
    assert!(!parents.is_contained_by(&children));
}
