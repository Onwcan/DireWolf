//! Scope and capability containment, including the two boundary confusions
//! that would be escalations: a domain suffix without label boundaries, and a
//! path prefix without component boundaries.

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

use common::{
    agent_pattern, channel, constraints, domain, fs_read, fs_write, handle, host, host_port,
    model_call, net_https, plain, provider_model, resolved,
};
use dwkd_authority::capability::{
    Action, Capability, CapabilityError, ConstraintSet, Namespace, Scope, Verb,
};

// ---------------------------------------------------------------------------
// The verb comes first.
// ---------------------------------------------------------------------------

#[test]
fn a_capability_contains_itself() {
    for c in [
        plain(fs_read(), Scope::Universal),
        resolved("network.https:*.example.com?methods=GET&max_requests=10"),
        resolved("model.call:anthropic/*?privacy_class=LOCAL_ONLY"),
        resolved("channel.send:telegram:<chat_id>"),
    ] {
        assert!(c.contains(&c), "{c}");
    }
}

#[test]
fn containment_never_crosses_a_verb() {
    // `fs.read:*` is universal within `fs.read` and covers no `fs.write` at
    // all. A universal scope is not universal authority.
    let read = plain(fs_read(), Scope::Universal);
    let write = plain(fs_write(), Scope::Universal);
    assert!(!read.contains(&write));
    assert!(!write.contains(&read));

    // Not even between actions that look adjacent.
    let stat = plain(common::verb(Namespace::Fs, Action::Stat), Scope::Universal);
    assert!(!read.contains(&stat));
}

#[test]
fn the_universal_scope_covers_everything_of_its_verb_and_is_covered_by_nothing_else() {
    // Over a family an integration test can build: `fs` and `process` need a
    // canonical identity, and this file cannot make one — which is the point of
    // ADR-0037's closeout. `resource_lattice.rs` covers the same rule for them.
    let universal = plain(net_https(), Scope::Universal);
    let specific = plain(net_https(), host("api.example.com"));
    assert!(universal.contains(&specific));
    assert!(!specific.contains(&universal));
    assert!(universal.contains(&universal));
}

// ---------------------------------------------------------------------------
// Paths: component boundaries, never string prefixes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Executables: identity, not path.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Hosts and domains: label boundaries.
// ---------------------------------------------------------------------------

#[test]
fn a_wildcard_host_covers_its_subdomains() {
    let parent = plain(net_https(), host("*.example.com"));
    for name in [
        "api.example.com",
        "a.b.example.com",
        "deep.nested.example.com",
    ] {
        let child = plain(net_https(), host(name));
        assert!(parent.contains(&child), "{name}");
    }
}

#[test]
fn a_wildcard_host_respects_label_boundaries() {
    // `ends_with("example.com")` would accept every one of these. Each is a
    // domain an attacker can register.
    let parent = plain(net_https(), host("*.example.com"));
    for name in [
        "evil-example.com",
        "notexample.com",
        "example.com.attacker.test",
        "example.com",
    ] {
        let child = plain(net_https(), host(name));
        assert!(!parent.contains(&child), "{name} must not be covered");
    }
}

#[test]
fn a_wildcard_host_covers_a_deeper_wildcard_and_not_a_shallower_one() {
    let wide = plain(net_https(), host("*.example.com"));
    let deep = plain(net_https(), host("*.api.example.com"));
    assert!(wide.contains(&deep));
    assert!(!deep.contains(&wide));
    // An exact host never covers a wildcard.
    let exact = plain(net_https(), host("api.example.com"));
    assert!(!exact.contains(&deep));
}

#[test]
fn an_exact_host_covers_only_itself() {
    let parent = plain(net_https(), host("api.example.com"));
    assert!(parent.contains(&plain(net_https(), host("api.example.com"))));
    assert!(!parent.contains(&plain(net_https(), host("other.example.com"))));
    assert!(!parent.contains(&plain(net_https(), host("deep.api.example.com"))));
}

#[test]
fn a_browser_domain_uses_the_same_label_rules() {
    let parent = plain(
        common::verb(Namespace::Browser, Action::Use),
        domain("*.github.com"),
    );
    let good = plain(
        common::verb(Namespace::Browser, Action::Use),
        domain("api.github.com"),
    );
    let bad = plain(
        common::verb(Namespace::Browser, Action::Use),
        domain("evil-github.com"),
    );
    assert!(parent.contains(&good));
    assert!(!parent.contains(&bad));
}

// ---------------------------------------------------------------------------
// Ports.
// ---------------------------------------------------------------------------

#[test]
fn an_unspecified_port_is_unconstrained_in_both_directions() {
    // The missing-constraint rules, applied to a scope. A parent that named no
    // port covers a child that names one; a parent that named 443 does not
    // cover a child that named none, because "any port" is wider.
    let any = plain(net_https(), host("api.example.com"));
    let http443 = plain(net_https(), host_port("api.example.com", 443));
    let http8443 = plain(net_https(), host_port("api.example.com", 8443));

    assert!(any.contains(&http443));
    assert!(!http443.contains(&any));
    assert!(http443.contains(&http443));
    assert!(!http443.contains(&http8443));
}

#[test]
fn a_wildcard_host_and_a_port_compose() {
    let parent = plain(net_https(), host_port("*.example.com", 443));
    assert!(parent.contains(&plain(net_https(), host_port("api.example.com", 443))));
    assert!(!parent.contains(&plain(net_https(), host_port("api.example.com", 80))));
    assert!(!parent.contains(&plain(net_https(), host("api.example.com"))));
}

// ---------------------------------------------------------------------------
// Patterns and exact-match families.
// ---------------------------------------------------------------------------

#[test]
fn a_trailing_wildcard_pattern_covers_by_prefix() {
    let parent = plain(common::agent_spawn(), agent_pattern("research*"));
    assert!(parent.contains(&plain(common::agent_spawn(), agent_pattern("researcher"))));
    assert!(parent.contains(&plain(common::agent_spawn(), agent_pattern("research*"))));
    assert!(parent.contains(&plain(
        common::agent_spawn(),
        agent_pattern("research-lead*")
    )));
    assert!(!parent.contains(&plain(common::agent_spawn(), agent_pattern("reviewer"))));
    // A literal never covers a pattern.
    let literal = plain(common::agent_spawn(), agent_pattern("researcher"));
    assert!(!literal.contains(&plain(common::agent_spawn(), agent_pattern("research*"))));
}

#[test]
fn a_provider_model_covers_by_provider_and_model_prefix() {
    let parent = plain(model_call(), provider_model("anthropic/*"));
    assert!(parent.contains(&plain(model_call(), provider_model("anthropic/claude-x"))));
    assert!(parent.contains(&plain(model_call(), provider_model("anthropic/*"))));
    // A different provider is a different authority, whatever the model.
    assert!(!parent.contains(&plain(model_call(), provider_model("other/claude-x"))));
}

#[test]
fn exact_match_families_cover_only_themselves() {
    let secret_use = common::verb(Namespace::Secret, Action::Use);
    let a = plain(secret_use, handle("github-primary"));
    assert!(a.contains(&plain(secret_use, handle("github-primary"))));
    assert!(!a.contains(&plain(secret_use, handle("github-secondary"))));

    let send = common::verb(Namespace::Channel, Action::Send);
    let t = plain(send, channel("telegram:<chat_id>"));
    assert!(t.contains(&plain(send, channel("telegram:<chat_id>"))));
    assert!(!t.contains(&plain(send, channel("telegram:<other>"))));
    assert!(!t.contains(&plain(send, channel("slack:<chat_id>"))));
}

// ---------------------------------------------------------------------------
// Transitivity, by construction.
// ---------------------------------------------------------------------------

#[test]
fn containment_is_transitive_down_a_hand_built_chain() {
    // Each step narrows in a way arithmetic and set theory settle without
    // consulting the implementation.
    let c0 = resolved("network.https:*.example.com");
    let c1 = resolved("network.https:*.api.example.com?max_requests=100");
    let c2 = resolved("network.https:one.api.example.com?max_requests=100&methods=GET,POST");
    let c3 = resolved("network.https:one.api.example.com?max_requests=10&methods=GET");

    assert!(c0.contains(&c1));
    assert!(c1.contains(&c2));
    assert!(c2.contains(&c3));
    assert!(c0.contains(&c2));
    assert!(c0.contains(&c3), "transitivity over the whole chain");
    assert!(!c3.contains(&c0));
}

// ---------------------------------------------------------------------------
// Hand-built capabilities are held to the same rules as parsed ones.
// ---------------------------------------------------------------------------

#[test]
fn a_scope_from_the_wrong_family_cannot_be_paired_with_a_verb() {
    // The parser cannot produce this; `Capability::new` is the other way in,
    // and it refuses too.
    let mismatched = Capability::new(
        fs_read(),
        host("example.com"),
        ConstraintSet::unconstrained(),
    );
    assert_eq!(mismatched, Err(CapabilityError::ScopeFamilyMismatch));

    let also = Capability::new(
        common::agent_spawn(),
        host("example.com"),
        ConstraintSet::unconstrained(),
    );
    assert_eq!(also, Err(CapabilityError::ScopeFamilyMismatch));
}

#[test]
fn a_constraint_from_the_wrong_verb_cannot_be_attached_by_hand() {
    let bad = Capability::new(
        model_call(),
        Scope::Universal,
        constraints(|c| c.max_bytes = Some(10)),
    );
    assert!(matches!(
        bad,
        Err(CapabilityError::ConstraintNotApplicable { .. })
    ));
}

#[test]
fn the_universal_scope_fits_every_verb() {
    for verb in Verb::ALL {
        assert!(
            Capability::new(*verb, Scope::Universal, ConstraintSet::unconstrained()).is_ok(),
            "{verb}"
        );
    }
}

// ---------------------------------------------------------------------------
// Determinism.
// ---------------------------------------------------------------------------

#[test]
fn the_same_question_always_gets_the_same_answer() {
    let parent = resolved("network.https:*.example.com?methods=GET,POST");
    let child = resolved("network.https:api.example.com?methods=GET");
    let first = parent.contains(&child);
    for _ in 0..1000 {
        assert_eq!(parent.contains(&child), first);
    }
    assert!(first);
}

#[test]
fn equality_and_ordering_depend_only_on_the_values() {
    let a = resolved("network.https:api.example.com?max_requests=5&methods=POST,GET");
    let b = resolved("network.https:api.example.com?methods=GET,POST&max_requests=5");
    assert_eq!(a, b);
    assert_eq!(a.cmp(&b), core::cmp::Ordering::Equal);
    assert_eq!(a.to_canonical_string(), b.to_canonical_string());
}

#[test]
fn a_capabilitys_canonical_form_is_idempotent() {
    for c in [
        plain(fs_read(), Scope::Universal),
        resolved("network.https:*.example.com?methods=GET,POST&max_requests=100"),
        resolved("agent.spawn:research*?depth=2&fanout=4"),
        resolved("secret.use:github-primary"),
    ] {
        let once = c.to_canonical_string();
        assert_eq!(once, c.to_canonical_string());
        assert!(!once.is_empty());
    }
}
