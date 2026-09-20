//! The delegation-chain evidence campaign.
//!
//! `CAPABILITIES.md` §3 states the target: **10⁶ generated delegation chains
//! with zero escalations.** This is that campaign, and it is `#[ignore]`d so
//! that `make check` stays fast; `make capability-evidence` runs it.
//!
//! # What makes it evidence rather than a long test
//!
//! * It drives the **production** API — `attenuate` and `Capability::contains` —
//!   with no test-only entry point and no bypass.
//! * Chains are **multi-step**: a million reflexivity checks would satisfy the
//!   number and none of the claim.
//! * Every step's direction is decided by the campaign *before* the production
//!   code is asked, from arithmetic and set theory over the model in
//!   `properties.rs`. A step the campaign knows is a widening must be refused;
//!   one it knows is a narrowing must be accepted. So an escalation is a
//!   disagreement with an independent expectation, not with the implementation
//!   itself.
//! * Roughly a third of the steps are deliberate widening attempts. A campaign
//!   that only ever asked for narrowings could not find the bug it exists to
//!   look for.
//! * It is seeded and reproducible: the seed is printed, and
//!   `DW_EVIDENCE_SEED` replays one.
//!
//! On the first escalation it prints the chain, the step and both capabilities,
//! and fails.

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

use std::time::Instant;

use dwkd_authority::capability::attenuate::delegate;
use dwkd_authority::capability::{
    Capability, ConstraintSet, Method, MethodSet, Narrowing, NoSymlinkTargets, PrivacyClass, Scope,
    attenuate,
};

/// How many chains a full campaign runs.
const TARGET_CHAINS: u64 = 1_000_000;

/// Steps per chain, inclusive.
const MIN_STEPS: u32 = 2;
const MAX_STEPS: u32 = 6;

/// The default seed. Fixed, so an unattended run is reproducible without
/// anybody having recorded anything.
const DEFAULT_SEED: u64 = 0x5DEE_CE66_D1A1_CAFE;

// ---------------------------------------------------------------------------
// A deterministic generator. xorshift64*, which needs no dependency and whose
// only requirement here is that it is reproducible from its seed.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { DEFAULT_SEED } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// An index into a slice of `len` elements. `u64::try_from` rather than
    /// `as`: the workspace warns on silent conversions, and a test harness that
    /// truncated a length would pick the wrong element and still look fine.
    fn index(&mut self, len: usize) -> usize {
        let len = u64::try_from(len).unwrap_or(1).max(1);
        usize::try_from(self.below(len)).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// The model. A capability the campaign can reason about without asking the
// implementation anything.
// ---------------------------------------------------------------------------

/// Host ladder, widest first, with the ancestors written out.
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
const HOST_ANCESTORS: &[&[usize]] = &[&[0], &[0, 1], &[0, 1, 2], &[0, 1, 3], &[4]];

const METHOD_POOL: &[Method] = &[Method::Get, Method::Post, Method::Put];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Network,
    Fs,
    Agent,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Model {
    shape: Shape,
    scope: usize,
    methods: Option<u8>,
    max_requests: Option<u32>,
    max_bytes: Option<u64>,
    no_symlink: bool,
    depth: Option<u16>,
    fanout: Option<u16>,
    privacy: Option<u8>,
}

impl Model {
    fn random(rng: &mut Rng) -> Self {
        let shape = match rng.below(4) {
            0 => Shape::Network,
            1 => Shape::Fs,
            2 => Shape::Agent,
            _ => Shape::Model,
        };
        let scope_count = match shape {
            Shape::Network => HOSTS.len(),
            Shape::Fs => 1,
            _ => 3,
        };
        let opt = |rng: &mut Rng, max: u64| -> Option<u64> {
            if rng.below(3) == 0 {
                None
            } else {
                Some(rng.below(max))
            }
        };
        let mut model = Self {
            shape,
            scope: rng.index(scope_count),
            methods: (rng.below(3) != 0).then(|| u8::try_from(1 + rng.below(7)).unwrap_or(1)),
            max_requests: opt(rng, 8).map(|v| u32::try_from(v).unwrap_or(0)),
            max_bytes: opt(rng, 8),
            no_symlink: rng.below(2) == 0,
            depth: opt(rng, 6).map(|v| u16::try_from(v).unwrap_or(0)),
            fanout: opt(rng, 6).map(|v| u16::try_from(v).unwrap_or(0)),
            privacy: opt(rng, 3).map(|v| u8::try_from(v).unwrap_or(0)),
        };
        model.normalise();
        model
    }

    /// Drop constraints the shape's verb does not accept.
    fn normalise(&mut self) {
        if self.shape != Shape::Network {
            self.methods = None;
            self.max_requests = None;
        }
        if self.shape != Shape::Fs {
            self.max_bytes = None;
            self.no_symlink = false;
        }
        if self.shape != Shape::Agent {
            self.depth = None;
            self.fanout = None;
        }
        if self.shape != Shape::Model {
            self.privacy = None;
        }
    }

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
                    c.no_symlink_targets = Some(NoSymlinkTargets);
                }
                (common::fs_write(), Scope::Universal)
            }
            Shape::Agent => {
                c.depth = self.depth;
                c.fanout = self.fanout;
                let names = ["research*", "researcher", "reviewer"];
                (
                    common::agent_spawn(),
                    common::agent_pattern(names[self.scope]),
                )
            }
            Shape::Model => {
                c.privacy_class = self.privacy.map(|p| PrivacyClass::ALL[usize::from(p)]);
                let names = ["anthropic/*", "anthropic/claude-x", "other/*"];
                (
                    common::model_call(),
                    common::provider_model(names[self.scope]),
                )
            }
        };
        common::cap(verb, scope, c)
    }

    /// Scopes strictly below this one on the ladder.
    fn narrower_scopes(&self) -> Vec<usize> {
        let table: &[&[usize]] = match self.shape {
            Shape::Network => HOST_ANCESTORS,
            Shape::Fs => &[&[0]],
            Shape::Agent => &[&[0], &[0, 1], &[2]],
            Shape::Model => &[&[0], &[0, 1], &[2]],
        };
        table
            .iter()
            .enumerate()
            .filter(|(i, anc)| *i != self.scope && anc.contains(&self.scope))
            .map(|(i, _)| i)
            .collect()
    }

    /// Scopes strictly above this one.
    fn wider_scopes(&self) -> Vec<usize> {
        let table: &[&[usize]] = match self.shape {
            Shape::Network => HOST_ANCESTORS,
            Shape::Fs => &[&[0]],
            Shape::Agent => &[&[0], &[0, 1], &[2]],
            Shape::Model => &[&[0], &[0, 1], &[2]],
        };
        table[self.scope]
            .iter()
            .copied()
            .filter(|i| *i != self.scope)
            .collect()
    }
}

fn mask_to_methods(mask: u8) -> MethodSet {
    let chosen: Vec<Method> = METHOD_POOL
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, m)| *m)
        .collect();
    MethodSet::new(&chosen).unwrap_or_else(|| MethodSet::new(&[Method::Get]).expect("non-empty"))
}

// ---------------------------------------------------------------------------
// Steps, with the direction the campaign knows before it asks.
// ---------------------------------------------------------------------------

/// A proposed step: the child it asks for, and whether the campaign's own
/// arithmetic says that is a narrowing.
///
/// `overlay` records whether the step is also expressible as a [`Narrowing`].
/// Dropping a constraint is not: a `Narrowing` carries values to *set*, and an
/// absent field means "keep the parent's". That is the design — there is no
/// spelling for "remove this constraint" — so a drop is requested the only way
/// it can be, by naming the whole child through `delegate`. The campaign
/// discovered this by reporting itself for an escalation that was its own
/// mistake, which is the behaviour a detector should have.
struct Step {
    child: Model,
    expected_ok: bool,
    overlay: bool,
    label: &'static str,
}

fn propose(rng: &mut Rng, parent: &Model) -> Step {
    // Roughly one step in three is a deliberate widening attempt.
    let widen = rng.below(3) == 0;
    let mut child = parent.clone();
    let label;
    let mut expected_ok = !widen;
    let mut overlay = true;

    if widen {
        match rng.below(7) {
            0 => {
                label = "widen scope";
                match parent.wider_scopes().first().copied() {
                    Some(wider) => child.scope = wider,
                    // Already at the top: nothing to widen, so this step is a
                    // no-op and must be accepted.
                    None => expected_ok = true,
                }
            }
            1 => {
                label = "loosen max_requests";
                match parent.max_requests {
                    Some(v) => child.max_requests = Some(v.saturating_add(1)),
                    None => expected_ok = true,
                }
            }
            2 => {
                label = "loosen max_bytes";
                match parent.max_bytes {
                    Some(v) => child.max_bytes = Some(v.saturating_add(1)),
                    None => expected_ok = true,
                }
            }
            3 => {
                label = "drop a constraint";
                // Not expressible as an overlay; see `Step::overlay`.
                overlay = false;
                // Rule 2: a missing constraint on the child is unconstrained,
                // and therefore wider. This is the escalation the whole
                // campaign is looking for.
                let dropped = match parent.shape {
                    Shape::Network if parent.max_requests.is_some() => {
                        child.max_requests = None;
                        true
                    }
                    Shape::Network if parent.methods.is_some() => {
                        child.methods = None;
                        true
                    }
                    Shape::Fs if parent.max_bytes.is_some() => {
                        child.max_bytes = None;
                        true
                    }
                    Shape::Fs if parent.no_symlink => {
                        child.no_symlink = false;
                        true
                    }
                    Shape::Agent if parent.depth.is_some() => {
                        child.depth = None;
                        true
                    }
                    Shape::Model if parent.privacy.is_some() => {
                        child.privacy = None;
                        true
                    }
                    _ => false,
                };
                expected_ok = !dropped;
            }
            4 => {
                label = "grow the method set";
                match parent.methods {
                    Some(v) if v != 0b111 => {
                        child.methods = Some(v | (v << 1) | 0b001 | 0b010 | 0b100)
                    }
                    _ => expected_ok = true,
                }
            }
            5 => {
                label = "loosen privacy_class";
                match parent.privacy {
                    Some(v) if v < 2 => child.privacy = Some(v + 1),
                    _ => expected_ok = true,
                }
            }
            _ => {
                label = "loosen fanout";
                match parent.fanout {
                    Some(v) => child.fanout = Some(v.saturating_add(1)),
                    None => expected_ok = true,
                }
            }
        }
    } else {
        match rng.below(7) {
            0 => {
                label = "narrow scope";
                let options = parent.narrower_scopes();
                if !options.is_empty() {
                    child.scope = options[rng.index(options.len())];
                }
            }
            1 => {
                label = "tighten max_requests";
                child.max_requests = Some(parent.max_requests.unwrap_or(4).saturating_sub(1));
            }
            2 => {
                label = "tighten max_bytes";
                child.max_bytes = Some(parent.max_bytes.unwrap_or(4).saturating_sub(1));
            }
            3 => {
                label = "add no_symlink_targets";
                child.no_symlink = true;
            }
            4 => {
                label = "shrink the method set";
                child.methods = Some(lowest_bit(parent.methods.unwrap_or(0b111)));
            }
            5 => {
                label = "tighten privacy_class";
                child.privacy = Some(parent.privacy.unwrap_or(2).saturating_sub(1));
            }
            _ => {
                label = "tighten depth and fanout";
                child.depth = Some(parent.depth.unwrap_or(4).saturating_sub(1));
                child.fanout = Some(parent.fanout.unwrap_or(4).saturating_sub(1));
            }
        }
    }

    child.normalise();
    // A step that could not change anything is a no-op, and a no-op is the
    // reflexive case: accepted.
    if child == *parent {
        expected_ok = true;
    }
    Step {
        child,
        expected_ok,
        overlay,
        label,
    }
}

fn lowest_bit(mask: u8) -> u8 {
    for bit in 0..3u8 {
        if mask & (1 << bit) != 0 {
            return 1 << bit;
        }
    }
    0b001
}

// ---------------------------------------------------------------------------
// The campaign.
// ---------------------------------------------------------------------------

struct Outcome {
    chains: u64,
    steps: u64,
    accepted: u64,
    refused: u64,
    widening_attempts: u64,
    escalations: Vec<String>,
}

fn run(chains: u64, seed: u64) -> Outcome {
    let mut rng = Rng::new(seed);
    let mut outcome = Outcome {
        chains: 0,
        steps: 0,
        accepted: 0,
        refused: 0,
        widening_attempts: 0,
        escalations: Vec::new(),
    };

    for chain in 0..chains {
        let root_model = Model::random(&mut rng);
        let root = root_model.build();
        let mut current_model = root_model;
        let mut current = root.clone();
        let step_count =
            MIN_STEPS + u32::try_from(rng.below(u64::from(MAX_STEPS - MIN_STEPS + 1))).unwrap_or(0);

        for step_index in 0..step_count {
            let step = propose(&mut rng, &current_model);
            let candidate = step.child.build();
            if !step.expected_ok {
                outcome.widening_attempts += 1;
            }
            outcome.steps += 1;

            // `delegate` names the whole child, so it can express every step
            // including a dropped constraint. Where the step is also an
            // overlay, `attenuate` is asked the same question and the two must
            // agree -- a disagreement would mean one of the two ways into the
            // narrowing API is looser than the other.
            if step.overlay {
                let narrowing = Narrowing {
                    scope: Some(candidate.scope().clone()),
                    constraints: candidate.constraints().clone(),
                };
                let by_overlay = attenuate(&current, &narrowing).is_ok();
                let by_delegate = delegate(&current, &candidate).is_ok();
                if by_overlay != by_delegate {
                    outcome.escalations.push(format!(
                        "chain {chain} step {step_index} ({}): attenuate and delegate disagree
                           parent: {current}
  child:  {candidate}",
                        step.label
                    ));
                }
            }

            match delegate(&current, &candidate) {
                Ok(result) => {
                    outcome.accepted += 1;
                    if !step.expected_ok {
                        outcome.escalations.push(format!(
                            "chain {chain} step {step_index} ({}): a widening was ACCEPTED\n  \
                             parent: {current}\n  child:  {result}",
                            step.label
                        ));
                    }
                    // The chain invariant, checked at every link rather than
                    // only at the end: cₙ ⊑ c₀, and cₙ ⊑ cₙ₋₁.
                    if !current.contains(&result) {
                        outcome.escalations.push(format!(
                            "chain {chain} step {step_index}: result not contained by its parent\n  \
                             parent: {current}\n  child:  {result}"
                        ));
                    }
                    if !root.contains(&result) {
                        outcome.escalations.push(format!(
                            "chain {chain} step {step_index}: result escaped the ROOT\n  \
                             root:  {root}\n  child: {result}"
                        ));
                    }
                    current = result;
                    current_model = step.child;
                }
                Err(_) => {
                    outcome.refused += 1;
                    if step.expected_ok {
                        outcome.escalations.push(format!(
                            "chain {chain} step {step_index} ({}): a narrowing was REFUSED\n  \
                             parent: {current}\n  child:  {candidate}",
                            step.label
                        ));
                    }
                }
            }
            if !outcome.escalations.is_empty() {
                // Stop at the first finding: a campaign that keeps running
                // after one buries it under a million lines.
                outcome.chains = chain + 1;
                return outcome;
            }
        }
        // And once more at the end of the chain.
        if !root.contains(&current) {
            outcome.escalations.push(format!(
                "chain {chain}: end escaped the root\n  root: {root}\n  end:  {current}"
            ));
            outcome.chains = chain + 1;
            return outcome;
        }
        outcome.chains = chain + 1;
    }
    outcome
}

fn seed_from_environment() -> u64 {
    std::env::var("DW_EVIDENCE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

fn chains_from_environment(default: u64) -> u64 {
    std::env::var("DW_EVIDENCE_CHAINS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn report(outcome: &Outcome, seed: u64, elapsed: std::time::Duration) {
    println!("--- capability delegation-chain evidence ---");
    println!("seed:               {seed} (DW_EVIDENCE_SEED to replay)");
    println!("chains:             {}", outcome.chains);
    println!("attenuation steps:  {}", outcome.steps);
    println!("  accepted:         {}", outcome.accepted);
    println!("  refused:          {}", outcome.refused);
    println!("widening attempts:  {}", outcome.widening_attempts);
    println!("escalations:        {}", outcome.escalations.len());
    println!("wall time:          {:.2}s", elapsed.as_secs_f64());
    for finding in &outcome.escalations {
        println!("ESCALATION: {finding}");
    }
}

/// The full campaign. Ignored by default; `make capability-evidence` runs it.
#[test]
#[ignore = "the 10^6-chain evidence campaign; run with `make capability-evidence`"]
fn one_million_delegation_chains_with_zero_escalations() {
    let seed = seed_from_environment();
    let chains = chains_from_environment(TARGET_CHAINS);
    let started = Instant::now();
    let outcome = run(chains, seed);
    let elapsed = started.elapsed();
    report(&outcome, seed, elapsed);

    assert!(
        outcome.escalations.is_empty(),
        "{} escalation(s); see above",
        outcome.escalations.len()
    );
    assert_eq!(outcome.chains, chains, "every chain must have run");
    assert!(
        outcome.steps >= chains * u64::from(MIN_STEPS),
        "chains must be multi-step: {} steps over {} chains",
        outcome.steps,
        outcome.chains
    );
    // The guard exists to stop the campaign quietly becoming all-narrowing,
    // which would make "zero escalations" mean nothing. Measured at 378,009 of
    // 4,001,205 steps (9.4%) for this model; the floor is 5%, comfortably below
    // that and far above a generator that had stopped proposing widenings. It
    // moved once already: the Fs shape's scope ladder became a single `*` when
    // canonical paths stopped being constructible from an integration test
    // (ADR-0037), so its "widen scope" steps became no-ops.
    assert!(
        outcome.widening_attempts * 20 > outcome.steps,
        "too few widening attempts ({} of {} steps) for this to be evidence",
        outcome.widening_attempts,
        outcome.steps
    );
}

/// A thousand chains, in the ordinary test run.
///
/// The full campaign is the evidence; this is the regression that keeps the
/// campaign's machinery working between runs of it, so `make capability-evidence`
/// never fails for a reason that has nothing to do with the lattice.
#[test]
fn a_thousand_delegation_chains_in_the_fast_suite() {
    let seed = seed_from_environment();
    let started = Instant::now();
    let outcome = run(1_000, seed);
    report(&outcome, seed, started.elapsed());
    assert!(outcome.escalations.is_empty());
    assert_eq!(outcome.chains, 1_000);
    assert!(outcome.widening_attempts > 0);
    assert!(
        outcome.refused > 0,
        "some widening must actually be refused"
    );
}

#[test]
fn the_campaign_can_fail() {
    // An evidence run that cannot report an escalation is a progress bar. This
    // proves the detector fires: a step the campaign believes is a widening,
    // accepted, is reported.
    let parent = common::resolved("network.https:api.example.com?max_requests=10");
    let wider = common::resolved("network.https:api.example.com?max_requests=100");
    let narrowing = Narrowing {
        scope: Some(wider.scope().clone()),
        constraints: wider.constraints().clone(),
    };
    // The production code refuses it -- which is why the campaign finds
    // nothing -- and the refusal is what the campaign would have flagged had it
    // been an acceptance.
    assert!(attenuate(&parent, &narrowing).is_err());
    assert!(!parent.contains(&wider));

    // And the reverse direction is accepted, so the detector is not simply
    // refusing everything.
    let narrower = common::resolved("network.https:api.example.com?max_requests=1");
    let ok = Narrowing {
        scope: Some(narrower.scope().clone()),
        constraints: narrower.constraints().clone(),
    };
    assert!(attenuate(&parent, &ok).is_ok());
    let _ = Scope::Universal;
}
