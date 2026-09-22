//! One named section per constraint.
//!
//! [`CAPABILITIES.md`] §2 promises "eight hand-written containment rules and
//! eight named tests", and that promise is the reason the set is closed rather
//! than a map. A single generic loop over all eight would give the coverage
//! number and lose the thing the number is for: a loop cannot notice that the
//! rule for `max_bytes` is the rule for `depth` written twice, or that one of
//! them is inverted.
//!
//! Every section covers the same seven cases: equal, narrower, wider, parent
//! missing, child missing, duplicate, and wrong verb.

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

mod common;

use common::{agent_spawn, cap, constraints, host, model_call, net_https, proc_exec};
use dwkd_authority::capability::{
    ArgvAllowlist, Capability, ConstraintSet, Method, MethodSet, NoSymlinkTargets, PrivacyClass,
    Scope, Verb, parse,
};

/// `child ⊑ parent`, over two constraint sets on the same verb and scope.
fn narrower(verb: Verb, scope: &Scope, child: ConstraintSet, parent: ConstraintSet) -> bool {
    let child = cap(verb, scope.clone(), child);
    let parent = cap(verb, scope.clone(), parent);
    parent.contains(&child)
}

/// The five cases every constraint must answer the same way.
///
/// `tighter` must be strictly narrower than `value`. The expectations are
/// written here, once, from the definition in `CAPABILITIES.md` §3 — not
/// derived from the implementation.
fn assert_ordering_rules<T: Clone>(
    verb: Verb,
    scope: &Scope,
    value: T,
    tighter: T,
    set: impl Fn(&mut ConstraintSet, T),
) {
    let with = |v: T| constraints(|c| set(c, v));
    let without = ConstraintSet::unconstrained;

    assert!(
        narrower(verb, scope, with(value.clone()), with(value.clone())),
        "equal values must be contained"
    );
    assert!(
        narrower(verb, scope, with(tighter.clone()), with(value.clone())),
        "a tighter child must be contained"
    );
    assert!(
        !narrower(verb, scope, with(value.clone()), with(tighter.clone())),
        "a looser child must NOT be contained"
    );
    // Rule A: a missing constraint on the parent is unconstrained, so the child
    // may add one.
    assert!(
        narrower(verb, scope, with(value.clone()), without()),
        "parent missing / child present is a narrowing and must be legal"
    );
    // Rule B: a missing constraint on the child is unconstrained, and therefore
    // WIDER. Getting this backwards is a silent privilege escalation.
    assert!(
        !narrower(verb, scope, without(), with(value)),
        "parent present / child missing is WIDER and must be refused"
    );
}

// ---------------------------------------------------------------------------
// 1. max_bytes — fs verbs, narrower is smaller.
// ---------------------------------------------------------------------------

#[test]
fn max_bytes_orders_by_magnitude_and_obeys_both_missing_rules() {
    assert_ordering_rules(
        common::fs_read(),
        &Scope::Universal,
        1000u64,
        100u64,
        |c, v| c.max_bytes = Some(v),
    );
}

#[test]
fn max_bytes_boundaries() {
    let scope = Scope::Universal;
    let verb = common::fs_read();
    let with = |v: u64| constraints(|c| c.max_bytes = Some(v));
    assert!(narrower(verb, &scope, with(0), with(u64::MAX)));
    assert!(!narrower(verb, &scope, with(u64::MAX), with(0)));
    assert!(narrower(verb, &scope, with(u64::MAX), with(u64::MAX)));
}

#[test]
fn max_bytes_is_rejected_on_a_verb_it_does_not_apply_to() {
    assert!(parse("model.call:*?max_bytes=10").is_err());
    assert!(
        Capability::new(
            model_call(),
            Scope::Universal,
            constraints(|c| c.max_bytes = Some(10)),
        )
        .is_err(),
        "the hand-built path enforces applicability too"
    );
}

#[test]
fn max_bytes_round_trips_and_refuses_a_duplicate() {
    let text = "fs.write:*?max_bytes=10485760";
    let spec = parse(text).expect("valid");
    assert_eq!(spec.to_canonical_string(), text);
    assert_eq!(parse(&spec.to_canonical_string()).expect("valid"), spec);
    assert!(parse("fs.write:/w?max_bytes=1&max_bytes=2").is_err());
}

// ---------------------------------------------------------------------------
// 2. no_symlink_targets — fs verbs, present is narrower than absent.
// ---------------------------------------------------------------------------

#[test]
fn no_symlink_targets_is_narrower_present_than_absent() {
    let scope = Scope::Universal;
    let verb = common::fs_write();
    let on = constraints(|c| c.no_symlink_targets = Some(NoSymlinkTargets));
    let off = ConstraintSet::unconstrained();

    // Equal.
    assert!(narrower(verb, &scope, on.clone(), on.clone()));
    // Rule A: the child adds it. Narrower, legal.
    assert!(narrower(verb, &scope, on.clone(), off.clone()));
    // Rule B: the parent has it, the child does not. Wider, refused -- this is
    // the one that would quietly let a delegate follow symlinks again.
    assert!(!narrower(verb, &scope, off, on));
}

#[test]
fn no_symlink_targets_has_no_false_and_no_wrong_verb() {
    assert!(parse("fs.write:/w?no_symlink_targets=false").is_err());
    assert!(parse("network.https:example.com?no_symlink_targets=true").is_err());
    assert!(parse("fs.write:/w?no_symlink_targets=true&no_symlink_targets=true").is_err());
    let text = "fs.write:*?no_symlink_targets=true";
    assert_eq!(parse(text).expect("valid").to_canonical_string(), text);
}

// ---------------------------------------------------------------------------
// 3. methods — network verbs, narrower is a subset.
// ---------------------------------------------------------------------------

fn methods(list: &[Method]) -> MethodSet {
    MethodSet::new(list).expect("non-empty")
}

#[test]
fn methods_orders_by_subset_and_obeys_both_missing_rules() {
    assert_ordering_rules(
        net_https(),
        &host("api.example.com"),
        methods(&[Method::Get, Method::Post]),
        methods(&[Method::Get]),
        |c, v| c.methods = Some(v),
    );
}

#[test]
fn methods_subset_relations_in_detail() {
    let verb = net_https();
    let scope = host("api.example.com");
    let with = |m: &[Method]| constraints(|c| c.methods = Some(methods(m)));

    // Proper subset.
    assert!(narrower(
        verb,
        &scope,
        with(&[Method::Get]),
        with(&[Method::Get, Method::Post, Method::Put])
    ));
    // Equal set, different input order -- the bitset has one representation.
    assert!(narrower(
        verb,
        &scope,
        with(&[Method::Post, Method::Get]),
        with(&[Method::Get, Method::Post])
    ));
    // Superset.
    assert!(!narrower(
        verb,
        &scope,
        with(&[Method::Get, Method::Post]),
        with(&[Method::Get])
    ));
    // Disjoint.
    assert!(!narrower(
        verb,
        &scope,
        with(&[Method::Delete]),
        with(&[Method::Get])
    ));
    // Overlapping but not contained.
    assert!(!narrower(
        verb,
        &scope,
        with(&[Method::Get, Method::Delete]),
        with(&[Method::Get, Method::Post])
    ));
}

#[test]
fn methods_parses_strictly_and_renders_canonically() {
    assert!(parse("network.https:example.com?methods=GET,GET").is_err());
    assert!(parse("network.https:example.com?methods=get").is_err());
    assert!(parse("fs.read:/w?methods=GET").is_err());
    assert_eq!(
        parse("network.https:example.com?methods=DELETE,GET,POST")
            .expect("valid")
            .to_canonical_string(),
        "network.https:example.com?methods=GET,POST,DELETE",
        "canonical order is the enum's, not the input's or the alphabet's"
    );
}

// ---------------------------------------------------------------------------
// 4. max_requests — network verbs, narrower is smaller.
// ---------------------------------------------------------------------------

#[test]
fn max_requests_orders_by_magnitude_and_obeys_both_missing_rules() {
    assert_ordering_rules(
        net_https(),
        &host("api.example.com"),
        100u32,
        10u32,
        |c, v| c.max_requests = Some(v),
    );
}

#[test]
fn max_requests_boundaries_and_applicability() {
    let verb = net_https();
    let scope = host("api.example.com");
    let with = |v: u32| constraints(|c| c.max_requests = Some(v));
    assert!(narrower(verb, &scope, with(0), with(u32::MAX)));
    assert!(!narrower(verb, &scope, with(u32::MAX), with(0)));
    assert!(parse("secret.use:handle?max_requests=1").is_err());
    assert!(parse("network.https:example.com?max_requests=1&max_requests=2").is_err());
    let text = "network.https:example.com?max_requests=100";
    assert_eq!(parse(text).expect("valid").to_canonical_string(), text);
}

// ---------------------------------------------------------------------------
// 5. argv_allowlist — process.exec only, narrower is a subset.
// ---------------------------------------------------------------------------

fn argv(tokens: &str) -> ArgvAllowlist {
    ArgvAllowlist::parse(tokens).expect("valid allowlist")
}

#[test]
fn argv_allowlist_orders_by_subset_and_obeys_both_missing_rules() {
    assert_ordering_rules(
        proc_exec(),
        &Scope::Universal,
        argv("status,diff,log"),
        argv("status,diff"),
        |c, v| c.argv_allowlist = Some(v),
    );
}

#[test]
fn argv_allowlist_subset_relations_in_detail() {
    let verb = proc_exec();
    let scope = Scope::Universal;
    let with = |t: &str| constraints(|c| c.argv_allowlist = Some(argv(t)));

    assert!(narrower(
        verb,
        &scope,
        with("status"),
        with("status,diff,log")
    ));
    // Same set, different order.
    assert!(narrower(verb, &scope, with("log,diff"), with("diff,log")));
    assert!(!narrower(
        verb,
        &scope,
        with("status,push"),
        with("status,diff")
    ));
    assert!(!narrower(verb, &scope, with("push"), with("status")));
}

#[test]
fn argv_allowlist_is_a_token_set_and_not_a_command_parser() {
    // No quoting, no globbing, no paths. The tokens are capability-level names
    // and M4/M5 decide how typed arguments bind to them.
    assert!(parse("process.exec:/bin/git?argv_allowlist=--no-pager").is_ok());
    assert!(parse("process.exec:/bin/git?argv_allowlist=st*tus").is_err());
    assert!(parse("process.exec:/bin/git?argv_allowlist=/usr/bin/x").is_err());
    assert!(parse("process.inspect:/bin/git?argv_allowlist=status").is_err());
    assert!(parse("process.exec:/bin/git?argv_allowlist=a&argv_allowlist=b").is_err());
    assert_eq!(
        parse("process.exec:*?argv_allowlist=log,diff,status")
            .expect("valid")
            .to_canonical_string(),
        "process.exec:*?argv_allowlist=diff,log,status"
    );
}

// ---------------------------------------------------------------------------
// 6. privacy_class — model.call only, narrower is stricter.
// ---------------------------------------------------------------------------

#[test]
fn privacy_class_orders_by_strictness_and_obeys_both_missing_rules() {
    assert_ordering_rules(
        model_call(),
        &Scope::Universal,
        PrivacyClass::Any,
        PrivacyClass::LocalOnly,
        |c, v| c.privacy_class = Some(v),
    );
}

#[test]
fn privacy_class_orders_all_nine_pairs() {
    // LOCAL_ONLY ⊑ VENDOR_OK ⊑ ANY, as a typed order rather than a lexical one.
    // Alphabetically `ANY` sorts first, so a string comparison would invert the
    // lattice and quietly let a run send local-only content to a vendor.
    use PrivacyClass::{Any, LocalOnly, VendorOk};
    let expected = [
        (LocalOnly, LocalOnly, true),
        (LocalOnly, VendorOk, true),
        (LocalOnly, Any, true),
        (VendorOk, LocalOnly, false),
        (VendorOk, VendorOk, true),
        (VendorOk, Any, true),
        (Any, LocalOnly, false),
        (Any, VendorOk, false),
        (Any, Any, true),
    ];
    let verb = model_call();
    let scope = Scope::Universal;
    for (child, parent, want) in expected {
        let got = narrower(
            verb,
            &scope,
            constraints(|c| c.privacy_class = Some(child)),
            constraints(|c| c.privacy_class = Some(parent)),
        );
        assert_eq!(got, want, "{child} ⊑ {parent}");
    }
}

#[test]
fn privacy_class_applicability_and_canonical_form() {
    assert!(parse("fs.read:/w?privacy_class=LOCAL_ONLY").is_err());
    assert!(parse("model.call:*?privacy_class=ANY&privacy_class=ANY").is_err());
    let text = "model.call:*?privacy_class=LOCAL_ONLY";
    assert_eq!(parse(text).expect("valid").to_canonical_string(), text);
}

// ---------------------------------------------------------------------------
// 7. depth — agent.spawn only, narrower is smaller.
// ---------------------------------------------------------------------------

#[test]
fn depth_orders_by_magnitude_and_obeys_both_missing_rules() {
    assert_ordering_rules(agent_spawn(), &Scope::Universal, 2u16, 1u16, |c, v| {
        c.depth = Some(v);
    });
}

#[test]
fn depth_boundaries_and_applicability() {
    let verb = agent_spawn();
    let scope = Scope::Universal;
    let with = |v: u16| constraints(|c| c.depth = Some(v));
    // Zero is a real depth: it means this run may spawn nothing.
    assert!(narrower(verb, &scope, with(0), with(1)));
    assert!(!narrower(verb, &scope, with(1), with(0)));
    assert!(parse("agent.message:*?depth=2").is_err());
    assert!(parse("agent.spawn:*?depth=1&depth=2").is_err());
    let text = "agent.spawn:*?depth=2";
    assert_eq!(parse(text).expect("valid").to_canonical_string(), text);
}

// ---------------------------------------------------------------------------
// 8. fanout — agent.spawn only, narrower is smaller.
// ---------------------------------------------------------------------------

#[test]
fn fanout_orders_by_magnitude_and_obeys_both_missing_rules() {
    assert_ordering_rules(agent_spawn(), &Scope::Universal, 4u16, 2u16, |c, v| {
        c.fanout = Some(v);
    });
}

#[test]
fn fanout_boundaries_and_applicability() {
    let verb = agent_spawn();
    let scope = Scope::Universal;
    let with = |v: u16| constraints(|c| c.fanout = Some(v));
    assert!(narrower(verb, &scope, with(0), with(u16::MAX)));
    assert!(!narrower(verb, &scope, with(u16::MAX), with(0)));
    assert!(parse("agent.cancel:*?fanout=2").is_err());
    assert!(parse("agent.spawn:*?fanout=1&fanout=2").is_err());
    let text = "agent.spawn:*?depth=2&fanout=4";
    assert_eq!(parse(text).expect("valid").to_canonical_string(), text);
}

// ---------------------------------------------------------------------------
// Across the whole set.
// ---------------------------------------------------------------------------

#[test]
fn every_constraint_is_covered_by_a_named_test_above() {
    // The list is the compiler's, so a ninth constraint fails here until
    // somebody writes its section. `ConstraintName::ALL` is what canonical
    // rendering iterates, so it cannot drift from the struct.
    use dwkd_authority::capability::ConstraintName;
    assert_eq!(ConstraintName::ALL.len(), 8);
    let named = [
        "max_bytes",
        "no_symlink_targets",
        "methods",
        "max_requests",
        "argv_allowlist",
        "privacy_class",
        "depth",
        "fanout",
    ];
    for name in ConstraintName::ALL {
        assert!(
            named.contains(&name.as_str()),
            "{name} has no named section"
        );
    }
}

#[test]
fn a_child_narrowing_several_dimensions_at_once_is_still_narrower() {
    let child = parse("network.https:api.example.com?methods=GET&max_requests=10").expect("child");
    let parent =
        parse("network.https:*.example.com?methods=GET,POST&max_requests=100").expect("parent");
    assert!(
        parent
            .resolve()
            .expect("syntactic")
            .contains(&child.resolve().expect("syntactic"))
    );
}

#[test]
fn one_wider_dimension_is_enough_to_refuse_the_whole_capability() {
    // Narrower scope, narrower method set, and one loosened counter. The
    // conjunction is what makes containment safe: a capability is contained
    // only if it is contained in every dimension.
    let child = parse("network.https:api.example.com?methods=GET&max_requests=1000").expect("c");
    let parent = parse("network.https:*.example.com?methods=GET,POST&max_requests=100").expect("p");
    assert!(
        !parent
            .resolve()
            .expect("syntactic")
            .contains(&child.resolve().expect("syntactic"))
    );
}
