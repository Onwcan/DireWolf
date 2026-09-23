//! The eight algebraic properties [`CAPABILITIES.md`] §3 requires, over
//! generated input.
//!
//! # Why there is a second implementation in this file
//!
//! A property test that asks the implementation whether it agrees with itself
//! proves that it is consistent, not that it is right. `attenuate` already ends
//! by calling `contains`, so "every successful attenuation is contained by its
//! parent" is very nearly a tautology if `contains` is the only oracle.
//!
//! So this file carries a **small independent reference implementation** of the
//! lattice — [`reference`] — written from the prose of `CAPABILITIES.md` §3,
//! over a deliberately restricted model, in a different style: explicit
//! ancestor tables instead of structural comparison, and `Option` matching
//! spelled out per constraint. The properties below are then *differential*:
//! production and reference must agree on every generated pair, and every other
//! property is asserted against the reference's verdict.
//!
//! The restriction is the price. The model covers four verbs, two scope
//! families, and all eight constraints; it does not cover every scope family,
//! and the direct tests in `containment.rs` are what cover those.
//!
//! The model's path ladder deliberately includes `/workspaceX`, because the
//! reference table says plainly that `/workspace` is not its ancestor, and a
//! production implementation using `starts_with` would disagree here on the
//! first generated pair that reached it.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

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

mod common;

use dwkd_authority::capability::{
    Capability, CapabilitySet, ConstraintSet, Method, MethodSet, Narrowing, PrivacyClass, Scope,
    attenuate,
};
use proptest::prelude::*;

// ===========================================================================
// The model: what a generated capability can be.
// ===========================================================================

/// Which shape a generated capability takes. One per constraint family, so all
/// eight constraints are reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `network.https` — host scope, `methods`, `max_requests`.
    Network,
    /// `fs.write` — universal scope, `max_bytes`, `no_symlink_targets`. The
    /// scope is `*` because a canonical path cannot be built outside
    /// `crate::resource`; the path lattice is a unit test (ADR-0037).
    Fs,
    /// `agent.spawn` — pattern scope, `depth`, `fanout`.
    Agent,
    /// `model.call` — provider/model scope, `privacy_class`.
    Model,
}

/// The hosts the generator draws from, widest first.
const HOSTS: &[&str] = &[
    "*.example.com",
    "*.api.example.com",
    "one.api.example.com",
    "two.api.example.com",
    // The string-confusion trap. It ends with "example.com" as *text* and is a
    // different registrable domain, so an implementation comparing suffixes
    // without label boundaries disagrees with the table below on the first
    // generated pair that reaches it. (The path ladder used to carry this role
    // with /workspaceX; since ADR-0037's closeout a canonical path cannot be
    // built outside `crate::resource`, so the trap lives in a family an
    // integration test can construct, and the path version moved to
    // `src/capability/resource_lattice.rs`.)
    "evil-example.com",
];

/// For each host, the indices of the hosts that contain it — **written out**,
/// not computed. `example.com` is absent from every list on purpose: a wildcard
/// does not cover its own apex.
const HOST_ANCESTORS: &[&[usize]] = &[&[0], &[0, 1], &[0, 1, 2], &[0, 1, 3], &[4]];

/// Agent profile patterns, and the indices that contain each.
const AGENTS: &[&str] = &["research*", "researcher", "reviewer"];
const AGENT_ANCESTORS: &[&[usize]] = &[&[0], &[0, 1], &[2]];

/// Provider/model patterns, and the indices that contain each.
const MODELS: &[&str] = &["anthropic/*", "anthropic/claude-x", "other/*"];
const MODEL_ANCESTORS: &[&[usize]] = &[&[0], &[0, 1], &[2]];

/// The method pool, as a bitmask over `[GET, POST, PUT]`.
const METHOD_POOL: &[Method] = &[Method::Get, Method::Post, Method::Put];

/// One generated capability, in model form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Model {
    shape: Shape,
    scope: usize,
    /// `methods`, as a non-zero mask over `METHOD_POOL`; `None` is absent.
    methods: Option<u8>,
    max_requests: Option<u32>,
    max_bytes: Option<u64>,
    no_symlink: bool,
    depth: Option<u16>,
    fanout: Option<u16>,
    privacy: Option<u8>,
}

impl Model {
    fn scope_ancestors(&self) -> &'static [usize] {
        match self.shape {
            Shape::Network => HOST_ANCESTORS[self.scope],
            Shape::Fs => &[0],
            Shape::Agent => AGENT_ANCESTORS[self.scope],
            Shape::Model => MODEL_ANCESTORS[self.scope],
        }
    }

    /// Build the production value this model describes.
    fn build(&self) -> Capability {
        let mut c = ConstraintSet::unconstrained();
        let (verb, scope) = match self.shape {
            Shape::Network => {
                c.methods = self.methods.map(mask_to_methods);
                c.max_requests = self.max_requests;
                (common::net_https(), common::host(HOSTS[self.scope]))
            }
            Shape::Fs => {
                c.max_bytes = self.max_bytes;
                if self.no_symlink {
                    c.no_symlink_targets = Some(dwkd_authority::capability::NoSymlinkTargets);
                }
                (common::fs_write(), Scope::Universal)
            }
            Shape::Agent => {
                c.depth = self.depth;
                c.fanout = self.fanout;
                (
                    common::agent_spawn(),
                    common::agent_pattern(AGENTS[self.scope]),
                )
            }
            Shape::Model => {
                c.privacy_class = self.privacy.map(|p| PrivacyClass::ALL[usize::from(p)]);
                (
                    common::model_call(),
                    common::provider_model(MODELS[self.scope]),
                )
            }
        };
        common::cap(verb, scope, c)
    }
}

fn mask_to_methods(mask: u8) -> MethodSet {
    let chosen: Vec<Method> = METHOD_POOL
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, m)| *m)
        .collect();
    MethodSet::new(&chosen).expect("mask is non-zero by construction")
}

// ===========================================================================
// The reference implementation.
// ===========================================================================

mod reference {
    use super::Model;

    /// One dimension of the constraint rule, from `CAPABILITIES.md` §3:
    ///
    /// * `∀ k ∈ constraints(parent)` — the child must have `k` and be narrower.
    /// * `∀ k ∈ constraints(child) \ constraints(parent)` — always fine.
    ///
    /// Written as four explicit cases rather than as a helper, so the two
    /// subtleties the document singles out are visible rather than inferred.
    fn dimension<T: PartialOrd>(
        child: Option<T>,
        parent: Option<T>,
        narrower: impl Fn(T, T) -> bool,
    ) -> bool {
        match (child, parent) {
            (_, None) => true,        // parent unconstrained: anything goes
            (None, Some(_)) => false, // child unconstrained: WIDER
            (Some(c), Some(p)) => narrower(c, p),
        }
    }

    /// `child ⊑ parent`, derived from the document rather than from the code
    /// under test.
    pub(super) fn contains(parent: &Model, child: &Model) -> bool {
        if parent.shape != child.shape {
            return false;
        }
        // Scope: the parent must appear in the child's ancestor list, which is
        // a table somebody wrote down, not a computation.
        if !child.scope_ancestors().contains(&parent.scope) {
            return false;
        }
        // methods: subset. Spelled as "every bit the child has, the parent has".
        if !dimension(child.methods, parent.methods, |c, p| c & !p == 0) {
            return false;
        }
        if !dimension(child.max_requests, parent.max_requests, |c, p| c <= p) {
            return false;
        }
        if !dimension(child.max_bytes, parent.max_bytes, |c, p| c <= p) {
            return false;
        }
        // no_symlink_targets: present is narrower than absent, and there is no
        // `false`, so the rule is "if the parent asked for it, the child must".
        if parent.no_symlink && !child.no_symlink {
            return false;
        }
        if !dimension(child.depth, parent.depth, |c, p| c <= p) {
            return false;
        }
        if !dimension(child.fanout, parent.fanout, |c, p| c <= p) {
            return false;
        }
        // privacy_class: index into LOCAL_ONLY < VENDOR_OK < ANY.
        if !dimension(child.privacy, parent.privacy, |c, p| c <= p) {
            return false;
        }
        true
    }
}

// ===========================================================================
// Generators. Valid structures only, per §27; the malformed corpus is in
// `parse.rs`, where it belongs.
// ===========================================================================

fn shape_and_scope() -> impl Strategy<Value = (Shape, usize)> {
    prop_oneof![
        (0..HOSTS.len()).prop_map(|s| (Shape::Network, s)),
        Just((Shape::Fs, 0)),
        (0..AGENTS.len()).prop_map(|s| (Shape::Agent, s)),
        (0..MODELS.len()).prop_map(|s| (Shape::Model, s)),
    ]
}

prop_compose! {
    /// A valid capability, in model form. The numeric domains are tiny on
    /// purpose: a free triple has to hit `a ⊑ b ⊑ c` often enough for
    /// transitivity to test anything, and a 64-bit domain never would.
    fn arb_model()(
        (shape, scope) in shape_and_scope(),
        methods in prop_oneof![Just(None), (1u8..8).prop_map(Some)],
        max_requests in prop_oneof![Just(None), (0u32..4).prop_map(Some)],
        max_bytes in prop_oneof![Just(None), (0u64..4).prop_map(Some)],
        no_symlink in any::<bool>(),
        depth in prop_oneof![Just(None), (0u16..4).prop_map(Some)],
        fanout in prop_oneof![Just(None), (0u16..4).prop_map(Some)],
        privacy in prop_oneof![Just(None), (0u8..3).prop_map(Some)],
    ) -> Model {
        // Keep only the constraints the shape's verb accepts; the others are
        // not narrowings on it, they are parse errors.
        Model {
            shape,
            scope,
            methods: if shape == Shape::Network { methods } else { None },
            max_requests: if shape == Shape::Network { max_requests } else { None },
            max_bytes: if shape == Shape::Fs { max_bytes } else { None },
            no_symlink: shape == Shape::Fs && no_symlink,
            depth: if shape == Shape::Agent { depth } else { None },
            fanout: if shape == Shape::Agent { fanout } else { None },
            privacy: if shape == Shape::Model { privacy } else { None },
        }
    }
}

/// A narrowing of `parent`, in model form, with the direction the *test* knows
/// it has. Returns the child and whether the reference says it is narrower.
fn narrow_model(parent: &Model, seed: u32) -> Model {
    let mut child = parent.clone();
    match seed % 6 {
        // Descend the scope ladder by one, when there is anywhere to go.
        0 => child.scope = next_narrower_scope(parent).unwrap_or(parent.scope),
        1 => child.max_requests = Some(parent.max_requests.unwrap_or(3).saturating_sub(1)),
        2 => child.max_bytes = Some(parent.max_bytes.unwrap_or(3).saturating_sub(1)),
        3 => child.depth = Some(parent.depth.unwrap_or(3).saturating_sub(1)),
        4 => child.fanout = Some(parent.fanout.unwrap_or(3).saturating_sub(1)),
        _ => {
            child.no_symlink = parent.shape == Shape::Fs;
            child.privacy = Some(parent.privacy.unwrap_or(2).saturating_sub(1));
            child.methods = parent.methods.map(lowest_bit).or(Some(0b001));
        }
    }
    // Constraints only apply where the shape accepts them.
    normalise(&mut child);
    child
}

fn lowest_bit(mask: u8) -> u8 {
    for bit in 0..3u8 {
        if mask & (1 << bit) != 0 {
            return 1 << bit;
        }
    }
    0b001
}

fn normalise(model: &mut Model) {
    if model.shape != Shape::Network {
        model.methods = None;
        model.max_requests = None;
    }
    if model.shape != Shape::Fs {
        model.max_bytes = None;
        model.no_symlink = false;
    }
    if model.shape != Shape::Agent {
        model.depth = None;
        model.fanout = None;
    }
    if model.shape != Shape::Model {
        model.privacy = None;
    }
}

/// The next scope down the ladder, if the model's family has one.
fn next_narrower_scope(model: &Model) -> Option<usize> {
    let table: &[&[usize]] = match model.shape {
        Shape::Network => HOST_ANCESTORS,
        Shape::Fs => &[&[0]],
        Shape::Agent => AGENT_ANCESTORS,
        Shape::Model => MODEL_ANCESTORS,
    };
    table
        .iter()
        .enumerate()
        .find(|(index, ancestors)| *index != model.scope && ancestors.contains(&model.scope))
        .map(|(index, _)| index)
}

// ===========================================================================
// Property 0 — production and the reference agree.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The differential test everything else rests on. If these two disagree
    /// anywhere, one of them is wrong, and the reference is the one derived
    /// from the document.
    #[test]
    fn production_containment_matches_the_reference(a in arb_model(), b in arb_model()) {
        let (ca, cb) = (a.build(), b.build());
        prop_assert_eq!(
            ca.contains(&cb),
            reference::contains(&a, &b),
            "parent {:?} child {:?}", a, b
        );
        prop_assert_eq!(
            cb.contains(&ca),
            reference::contains(&b, &a),
            "reversed"
        );
    }
}

// ===========================================================================
// Properties 1–8.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// 1. Reflexivity: `a ⊑ a`.
    #[test]
    fn reflexivity(a in arb_model()) {
        let c = a.build();
        prop_assert!(c.contains(&c));
        prop_assert!(reference::contains(&a, &a));
    }

    /// 2. Transitivity: `a ⊑ b ∧ b ⊑ c ⟹ a ⊑ c`.
    ///
    /// Free triples, filtered. The tiny value domains are what make the
    /// antecedent fire often enough to matter; `transitivity_is_actually_exercised`
    /// below measures how often, so this cannot quietly become vacuous.
    #[test]
    fn transitivity(a in arb_model(), b in arb_model(), c in arb_model()) {
        let (ca, cb, cc) = (a.build(), b.build(), c.build());
        if cc.contains(&cb) && cb.contains(&ca) {
            prop_assert!(cc.contains(&ca), "{:?} ⊑ {:?} ⊑ {:?}", a, b, c);
        }
    }

    /// 3. Attenuation soundness, against the reference rather than against
    ///    `contains`: the result must be narrower by the document's rules.
    #[test]
    fn attenuation_soundness(parent in arb_model(), seed in any::<u32>()) {
        let child = narrow_model(&parent, seed);
        let (cp, cc) = (parent.build(), child.build());
        let narrowing = Narrowing {
            scope: Some(cc.scope().clone()),
            constraints: cc.constraints().clone(),
        };
        match attenuate(&cp, &narrowing) {
            Ok(result) => {
                // The reference agrees it is a narrowing...
                prop_assert!(
                    reference::contains(&parent, &child),
                    "accepted a widening: {:?} -> {:?}", parent, child
                );
                // ...and the result is the capability that was asked for.
                prop_assert!(cp.contains(&result));
                prop_assert_eq!(result, cc);
            }
            Err(_) => {
                prop_assert!(
                    !reference::contains(&parent, &child),
                    "refused a narrowing: {:?} -> {:?}", parent, child
                );
            }
        }
    }

    /// 4. Attenuation idempotence: `attenuate(attenuate(c,r),r) == attenuate(c,r)`.
    #[test]
    fn attenuation_idempotence(parent in arb_model(), seed in any::<u32>()) {
        let child = narrow_model(&parent, seed);
        let cp = parent.build();
        let narrowing = Narrowing {
            scope: Some(child.build().scope().clone()),
            constraints: child.build().constraints().clone(),
        };
        if let Ok(once) = attenuate(&cp, &narrowing) {
            let twice = attenuate(&once, &narrowing).expect("re-applying a narrowing must hold");
            prop_assert_eq!(&once, &twice);
            let thrice = attenuate(&twice, &narrowing).expect("still");
            prop_assert_eq!(once, thrice);
        }
    }

    /// 5. Empty is bottom: `∅ ⊑ A`.
    #[test]
    fn empty_is_bottom(members in prop::collection::vec(arb_model(), 0..6)) {
        let set = CapabilitySet::from_capabilities(members.iter().map(Model::build));
        prop_assert!(CapabilitySet::empty().is_contained_by(&set));
    }

    /// 6. No synthesis: a set covers a capability only if a **single** member
    ///    does. The reference decides which members those are.
    #[test]
    fn no_synthesis(
        members in prop::collection::vec(arb_model(), 1..5),
        wanted in arb_model(),
    ) {
        let set = CapabilitySet::from_capabilities(members.iter().map(Model::build));
        let covered_by_one = members.iter().any(|m| reference::contains(m, &wanted));
        prop_assert_eq!(
            set.covers(&wanted.build()),
            covered_by_one,
            "set {:?} wanted {:?}", members, wanted
        );
    }

    /// 7. Chain monotonicity: for a delegation chain `c₀ … cₙ`, `cₙ ⊑ c₀`.
    #[test]
    fn chain_monotonicity(root in arb_model(), seeds in prop::collection::vec(any::<u32>(), 1..8)) {
        let mut current = root.build();
        let first = current.clone();
        let mut model = root;
        for seed in seeds {
            let next_model = narrow_model(&model, seed);
            let next = next_model.build();
            let narrowing = Narrowing {
                scope: Some(next.scope().clone()),
                constraints: next.constraints().clone(),
            };
            if let Ok(result) = attenuate(&current, &narrowing) {
                prop_assert!(current.contains(&result), "a step must narrow");
                prop_assert!(first.contains(&result), "every link stays under the root");
                current = result;
                model = next_model;
            }
        }
        prop_assert!(first.contains(&current));
    }

    /// 8a. Canonical-form stability: `canon(canon(p)) == canon(p)`, and equal
    ///     capabilities render identically.
    #[test]
    fn canonical_form_is_idempotent(a in arb_model(), b in arb_model()) {
        let (ca, cb) = (a.build(), b.build());
        let once = ca.to_canonical_string();
        prop_assert_eq!(&once, &ca.to_canonical_string());
        prop_assert_eq!(ca == cb, once == cb.to_canonical_string());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// 8b. The text round trip, for the families that have a request spelling.
    ///     `fs` and `process` are excluded because their canonical rendering is
    ///     a *resolved identity*, which is deliberately not a request form.
    #[test]
    fn canonical_text_round_trips(a in arb_model()) {
        prop_assume!(a.shape != Shape::Fs);
        let capability = a.build();
        let text = capability.to_canonical_string();
        let reparsed = dwkd_authority::capability::parse(&text)
            .expect("canonical text must parse")
            .resolve()
            .expect("these families need no resolver");
        prop_assert_eq!(&capability, &reparsed);
        prop_assert_eq!(text, reparsed.to_canonical_string());
    }
}

// ===========================================================================
// The tests that keep the tests honest.
// ===========================================================================

#[test]
fn transitivity_is_actually_exercised_and_not_vacuous() {
    // A filtered property that never fires is a green test that proves nothing.
    // This walks the model space exhaustively over one shape and counts the
    // triples that satisfy the antecedent.
    let mut models = Vec::new();
    for scope in 0..HOSTS.len() {
        for methods in [None, Some(0b001), Some(0b011), Some(0b111)] {
            for max_requests in [None, Some(0u32), Some(2)] {
                models.push(Model {
                    shape: Shape::Network,
                    scope,
                    methods,
                    max_requests,
                    max_bytes: None,
                    no_symlink: false,
                    depth: None,
                    fanout: None,
                    privacy: None,
                });
            }
        }
    }
    let built: Vec<Capability> = models.iter().map(Model::build).collect();
    let mut fired = 0usize;
    let mut checked = 0usize;
    for i in 0..models.len() {
        for j in 0..models.len() {
            for k in 0..models.len() {
                checked += 1;
                if built[k].contains(&built[j]) && built[j].contains(&built[i]) {
                    fired += 1;
                    assert!(built[k].contains(&built[i]), "transitivity");
                }
            }
        }
    }
    assert_eq!(checked, models.len().pow(3));
    println!("transitivity: {fired} non-vacuous triples of {checked}");
    // Measured at 3,200 firings in 110,592 triples (2.9%) for this model space.
    // The floor sits below that and far above zero: it catches a generator that
    // stops producing comparable capabilities — which would leave the property
    // green and meaningless — without breaking on a small change to the ladder.
    assert!(
        fired > 2_000,
        "the antecedent fired only {fired} times in {checked} triples; \
         the generators have drifted and transitivity is close to vacuous"
    );
}

#[test]
fn the_reference_and_production_disagree_about_nothing_in_the_whole_small_space() {
    // The differential property samples; this is exhaustive over the network
    // shape, which is small enough to enumerate. 48 models, 2304 ordered pairs.
    let mut models = Vec::new();
    for scope in 0..HOSTS.len() {
        for methods in [None, Some(0b001), Some(0b011), Some(0b111)] {
            for max_requests in [None, Some(0u32), Some(1), Some(2)] {
                models.push(Model {
                    shape: Shape::Network,
                    scope,
                    methods,
                    max_requests,
                    max_bytes: None,
                    no_symlink: false,
                    depth: None,
                    fanout: None,
                    privacy: None,
                });
            }
        }
    }
    let mut pairs = 0usize;
    for parent in &models {
        for child in &models {
            pairs += 1;
            assert_eq!(
                parent.build().contains(&child.build()),
                reference::contains(parent, child),
                "{parent:?} vs {child:?}"
            );
        }
    }
    assert_eq!(pairs, models.len() * models.len());
    assert!(pairs >= 2304, "the exhaustive space shrank to {pairs}");
}

#[test]
fn the_reference_catches_a_suffix_confusion_implementation() {
    // The oracle has to be able to fail. `evil-example.com` is in the host
    // ladder precisely so that an implementation comparing suffixes as text
    // rather than as labels would disagree with the table here on the first
    // pair that reached it.
    let parent = Model {
        shape: Shape::Network,
        scope: 0, // *.example.com
        methods: None,
        max_requests: None,
        max_bytes: None,
        no_symlink: false,
        depth: None,
        fanout: None,
        privacy: None,
    };
    let trap = Model {
        scope: 4,
        ..parent.clone()
    }; // evil-example.com
    assert!(!reference::contains(&parent, &trap), "the table says no");
    assert!(
        !parent.build().contains(&trap.build()),
        "and so does the implementation"
    );
    assert!(
        HOSTS[4].ends_with("example.com") && HOSTS[4] != "example.com",
        "the trap must remain a text suffix of the wildcard's domain, or it          stops being a trap"
    );
    // The same class over paths -- /workspace vs /workspaceX -- is covered in
    // `src/capability/resource_lattice.rs`, because a canonical path cannot be
    // constructed from an integration test (ADR-0037).
}

#[test]
fn every_shape_and_every_constraint_is_reachable_from_the_generators() {
    // A generator that never produces a dangerous case is a property test that
    // measures nothing. This asserts each shape can carry each of its own
    // constraints and that the built capability really holds them.
    let net = Model {
        shape: Shape::Network,
        scope: 0,
        methods: Some(0b011),
        max_requests: Some(2),
        max_bytes: None,
        no_symlink: false,
        depth: None,
        fanout: None,
        privacy: None,
    }
    .build();
    assert!(net.constraints().methods.is_some() && net.constraints().max_requests.is_some());

    let fs = Model {
        shape: Shape::Fs,
        scope: 0,
        methods: None,
        max_requests: None,
        max_bytes: Some(3),
        no_symlink: true,
        depth: None,
        fanout: None,
        privacy: None,
    }
    .build();
    assert!(fs.constraints().max_bytes.is_some() && fs.constraints().no_symlink_targets.is_some());

    let agent = Model {
        shape: Shape::Agent,
        scope: 0,
        methods: None,
        max_requests: None,
        max_bytes: None,
        no_symlink: false,
        depth: Some(2),
        fanout: Some(3),
        privacy: None,
    }
    .build();
    assert!(agent.constraints().depth.is_some() && agent.constraints().fanout.is_some());

    let model = Model {
        shape: Shape::Model,
        scope: 0,
        methods: None,
        max_requests: None,
        max_bytes: None,
        no_symlink: false,
        depth: None,
        fanout: None,
        privacy: Some(0),
    }
    .build();
    assert_eq!(
        model.constraints().privacy_class,
        Some(PrivacyClass::LocalOnly)
    );

    // And `argv_allowlist`, the one constraint no shape carries, is covered by
    // its named section in `constraints.rs` -- recorded here so the gap is
    // deliberate rather than forgotten.
    let _ = Scope::Universal;
}
