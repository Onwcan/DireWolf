//! The partition is held to the production evaluator, not to an argument
//! about it (F-17, ADR-0061, Proposed).
//!
//! * `the_partition_decides_every_address_as_the_evaluator_does`: random
//!   policies -- rules and postconditions in random order, with nested,
//!   overlapping, duplicated and whole-space ranges of both families,
//!   obligations, taint, novelty and host predicates -- and for every
//!   address tried (random, and every boundary of every range, and the
//!   IPv4-mapped form of each IPv4 one), the decision at the address equals
//!   the decision at its piece's representative.
//! * `a_decision_that_needs_no_address_holds_for_every_address`: the
//!   shortcut the egress decision takes.
//! * `the_brokers_lookup_finds_the_partitions_piece`: the one lookup the
//!   broker uses (`dwk-proto`'s `WorkloadEgress::piece`), over the ranges the
//!   authority sends, puts every address in the piece the partition does.
//! * The premise of the proof -- `address_in` is the one reader of the
//!   address -- is held to the source by
//!   `tests/architecture/test_f17_partition_premise.py`: the policy core does
//!   no IO, its tests included (TX004).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_push_string,
    reason = "test assertions"
)]

use proptest::prelude::*;

use super::super::action::{CanonicalAction, Environment, IpAddress, Novelty};
use super::super::context::{Origin, PolicyContext, TaintLevel};
use super::super::predicate::Unevaluable;
use super::super::rule::CompiledPolicy;
use super::super::testing::syntactic_capability;
use super::super::value::Cidr;
use super::super::{compose, evaluate, load, profiles};
use super::{MAX_PARTITION_RANGES, NetworkPartition, PIECE_V4_OTHER, PIECE_V6_OTHER, TooFine};

/// Ranges that nest, overlap, repeat and cover everything, in both families.
const POOL: &[&str] = &[
    "0.0.0.0/0",
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.1.2.0/24",
    "10.1.2.3/32",
    "10.128.0.0/9",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.168.1.0/24",
    "93.184.216.0/24",
    "93.184.216.34/32",
    "0000:0000:0000:0000:0000:0000:0000:0000/0",
    "2000:0000:0000:0000:0000:0000:0000:0000/3",
    "2001:0db8:0000:0000:0000:0000:0000:0000/32",
    "2001:0db8:0001:0000:0000:0000:0000:0000/48",
    "fc00:0000:0000:0000:0000:0000:0000:0000/7",
    "0000:0000:0000:0000:0000:ffff:0000:0000/96",
    "0000:0000:0000:0000:0000:0000:0000:0001/128",
];

const VERBS: &[&str] = &[
    r#"when.verb = ["network.https"]"#,
    r#"when.verb = ["network.http", "network.https"]"#,
    r#"when.verb = ["network.http"]"#,
    r#"when.verb = ["fs.read"]"#,
    "",
];

#[derive(Debug, Clone)]
struct RuleModel {
    effect: usize,
    verb: usize,
    ranges: Vec<usize>,
    taint: Option<usize>,
    novel: Option<bool>,
    host: Option<bool>,
    bound: Option<u32>,
}

#[derive(Debug, Clone)]
struct PostModel {
    selects: usize,
    ranges: Vec<usize>,
    taint: Option<usize>,
}

fn rule_model() -> impl Strategy<Value = RuleModel> {
    (
        0_usize..3,
        0..VERBS.len(),
        prop::collection::vec(0..POOL.len(), 0..4),
        prop::option::of(0_usize..3),
        prop::option::of(any::<bool>()),
        prop::option::of(any::<bool>()),
        prop::option::of(1_u32..100_000),
    )
        .prop_map(
            |(effect, verb, ranges, taint, novel, host, bound)| RuleModel {
                effect,
                verb,
                ranges,
                taint,
                novel,
                host,
                bound,
            },
        )
}

fn post_model() -> impl Strategy<Value = PostModel> {
    (
        0_usize..2,
        prop::collection::vec(0..POOL.len(), 1..4),
        prop::option::of(0_usize..3),
    )
        .prop_map(|(selects, ranges, taint)| PostModel {
            selects,
            ranges,
            taint,
        })
}

const TAINTS: [&str; 3] = ["NONE", "LOCAL_UNVERIFIED", "EXTERNAL_UNTRUSTED"];

fn list(indices: &[usize]) -> String {
    let mut seen: Vec<usize> = Vec::new();
    for index in indices {
        if !seen.contains(index) {
            seen.push(*index);
        }
    }
    seen.iter()
        .map(|i| format!("\"{}\"", POOL[*i]))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The policy a model describes, as an operator would write it.
fn text(rules: &[RuleModel], posts: &[PostModel]) -> String {
    let mut out = String::from("schema_version = 1\n\n[meta]\nname = \"p\"\n");
    for (index, rule) in rules.iter().enumerate() {
        let (effect, extra) = match rule.effect {
            0 => (
                "ALLOW",
                rule.bound
                    .map(|b| format!("obligations = [\"max_output_bytes={b}\"]\n"))
                    .unwrap_or_default(),
            ),
            1 => ("DENY", "reason = \"PROFILE_CEILING\"\n".to_owned()),
            _ => (
                "REQUIRE_APPROVAL",
                "reason = \"UNTRUSTED_CONTENT_IN_RUN\"\napproval.scope = \"exact_action\"\n\
                 approval.ttl = \"10m\"\napproval.max_uses = 1\n"
                    .to_owned(),
            ),
        };
        // A network predicate needs a rule that names a network verb (the
        // loader's applicability check): the first three verb lists do.
        let networked = !rule.ranges.is_empty() || rule.novel.is_some() || rule.host.is_some();
        let verb = if networked { rule.verb % 3 } else { rule.verb };
        out.push_str(&format!(
            "\n[[rule]]\nid = \"r{index}\"\neffect = \"{effect}\"\n{extra}{}\n",
            VERBS[verb]
        ));
        if !rule.ranges.is_empty() {
            out.push_str(&format!("when.ip_in = [{}]\n", list(&rule.ranges)));
        }
        if let Some(taint) = rule.taint {
            out.push_str(&format!("when.taint_level = [\"{}\"]\n", TAINTS[taint]));
        }
        if let Some(novel) = rule.novel {
            out.push_str(&format!("when.destination_novel = {novel}\n"));
        }
        if let Some(host) = rule.host {
            let pattern = if host {
                "api.example.com"
            } else {
                "other.example.com"
            };
            out.push_str(&format!("when.host_matches = [\"{pattern}\"]\n"));
        }
    }
    out.push_str(
        "\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
    );
    for (index, post) in posts.iter().enumerate() {
        let selects = ["ALLOW", "REQUIRE_APPROVAL"][post.selects];
        out.push_str(&format!(
            "\n[[postcondition]]\nid = \"p{index}\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.provisional_effect = [\"{selects}\"]\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [{}]\n",
            list(&post.ranges)
        ));
        if let Some(taint) = post.taint {
            out.push_str(&format!("when.taint_level = [\"{}\"]\n", TAINTS[taint]));
        }
    }
    out
}

fn compile(text: &str) -> CompiledPolicy {
    let profile = load("p.toml", text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    let name = profile.name().clone();
    compose(&name, &[profile]).unwrap_or_else(|e| panic!("{e}\n{text}"))
}

fn pack(file: &str) -> CompiledPolicy {
    let (_, text) = profiles::ALL
        .into_iter()
        .find(|(name, _)| *name == file)
        .unwrap();
    compile(text)
}

fn cidr(text: &str) -> Cidr {
    Cidr::parse(text).unwrap()
}

fn as_u128(address: &IpAddress) -> (bool, u128) {
    match address {
        IpAddress::V4(o) => (false, u128::from(u32::from_be_bytes(*o))),
        IpAddress::V6(o) => (true, u128::from_be_bytes(*o)),
    }
}

fn from_u128(v6: bool, value: u128) -> IpAddress {
    if v6 {
        IpAddress::V6(value.to_be_bytes())
    } else {
        IpAddress::V4(u32::try_from(value & 0xFFFF_FFFF).unwrap().to_be_bytes())
    }
}

/// Every boundary of every pool range: its first and last address, and one
/// either side, in its own family -- and each IPv4 one IPv4-mapped.
fn boundaries() -> Vec<IpAddress> {
    let mut out = Vec::new();
    for text in POOL {
        let range = cidr(text);
        let (v6, start) = as_u128(&range.network());
        let bits: u32 = if v6 { 128 } else { 32 };
        let span = if range.prefix() == 0 {
            if v6 { u128::MAX } else { 0xFFFF_FFFF }
        } else {
            (1u128 << (bits - range.prefix())) - 1
        };
        let max = if v6 { u128::MAX } else { 0xFFFF_FFFF };
        for value in [
            Some(start),
            start.checked_sub(1),
            start.checked_add(span),
            start.checked_add(span).and_then(|v| v.checked_add(1)),
        ]
        .into_iter()
        .flatten()
        .filter(|v| *v <= max)
        {
            out.push(from_u128(v6, value));
            if !v6 {
                out.push(IpAddress::V6(
                    (0x0000_0000_0000_0000_0000_ffff_0000_0000u128 | value).to_be_bytes(),
                ));
            }
        }
    }
    out
}

fn context(origin: usize, taint: usize) -> PolicyContext {
    let origin = [Origin::Interactive, Origin::Scheduled][origin];
    PolicyContext::new(origin, TaintLevel::ALL[taint])
}

fn action(novelty: bool) -> CanonicalAction {
    CanonicalAction::new(
        syntactic_capability("network.https:api.example.com:443"),
        Environment::Sandbox,
    )
    .with_destination_novelty(if novelty {
        Novelty::Novel
    } else {
        Novelty::Seen
    })
}

/// The decision at `address` equals the decision at its piece's
/// representative -- effect, deciding and primary rule, obligations.
fn holds_at(
    policy: &CompiledPolicy,
    partition: &NetworkPartition,
    (base, context): (&CanonicalAction, &PolicyContext),
    address: IpAddress,
) {
    let piece = partition.piece_of(&address);
    let Some(representative) = partition.representative(piece) else {
        panic!("{address} is in piece {piece}, which has no representative");
    };
    assert_eq!(
        partition.piece_of(&representative),
        piece,
        "the representative of piece {piece} lies in another"
    );
    let at = evaluate(policy, &base.clone().with_destination_ip(address), context);
    let there = evaluate(
        policy,
        &base.clone().with_destination_ip(representative),
        context,
    );
    assert_eq!(
        at, there,
        "{address} (piece {piece}) and its representative {representative} are decided apart"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(384))]

    #[test]
    fn the_partition_decides_every_address_as_the_evaluator_does(
        rules in prop::collection::vec(rule_model(), 1..10),
        posts in prop::collection::vec(post_model(), 0..3),
        novelty in any::<bool>(),
        origin in 0_usize..2,
        taint in 0_usize..3,
        randoms in prop::collection::vec((any::<bool>(), any::<u128>()), 24),
    ) {
        let policy = compile(&text(&rules, &posts));
        let partition = NetworkPartition::of(&policy).unwrap();
        let (base, context) = (action(novelty), context(origin, taint));
        let mut addresses = boundaries();
        addresses.extend(randoms.iter().map(|(v6, value)| {
            from_u128(*v6, if *v6 { *value } else { value & 0xFFFF_FFFF })
        }));
        for address in addresses {
            holds_at(&policy, &partition, (&base, &context), address);
        }
    }

    #[test]
    fn the_brokers_lookup_finds_the_partitions_piece(
        picked in prop::collection::btree_set(0..POOL.len(), 0..POOL.len()),
        randoms in prop::collection::vec((any::<bool>(), any::<u128>()), 24),
    ) {
        let ranges: Vec<Cidr> = picked.iter().map(|i| cidr(POOL[*i])).collect();
        let partition = NetworkPartition::from_ranges(ranges.clone());
        let egress = shared_lookup(&ranges);
        prop_assert_eq!(egress.pieces(), partition.pieces());
        let mut addresses = boundaries();
        addresses.extend(randoms.iter().map(|(v6, value)| {
            from_u128(*v6, if *v6 { *value } else { value & 0xFFFF_FFFF })
        }));
        for address in addresses {
            prop_assert_eq!(
                egress.piece(&wire(&address)),
                partition.piece_of(&address),
                "{}",
                address
            );
        }
    }

    #[test]
    fn a_decision_that_needs_no_address_holds_for_every_address(
        rules in prop::collection::vec(rule_model(), 1..10),
        posts in prop::collection::vec(post_model(), 0..3),
        novelty in any::<bool>(),
        taint in 0_usize..3,
        randoms in prop::collection::vec((any::<bool>(), any::<u128>()), 16),
    ) {
        let policy = compile(&text(&rules, &posts));
        let (base, context) = (action(novelty), context(0, taint));
        let without = evaluate(&policy, &base, &context);
        prop_assume!(without.unevaluable() != Some(Unevaluable::ResolvedAddress));
        let mut addresses = boundaries();
        addresses.extend(randoms.iter().map(|(v6, value)| {
            from_u128(*v6, if *v6 { *value } else { value & 0xFFFF_FFFF })
        }));
        for address in addresses {
            let at = evaluate(&policy, &base.clone().with_destination_ip(address), &context);
            prop_assert_eq!(&at, &without, "{}", address);
        }
    }
}

/// An address as the wire carries it.
fn wire(address: &IpAddress) -> dwk_proto::wire::guard::Address {
    match address {
        IpAddress::V4(o) => dwk_proto::wire::guard::Address::V4(*o),
        IpAddress::V6(o) => dwk_proto::wire::guard::Address::V6(*o),
    }
}

/// An authorisation over `ranges`, as the authority would send it: the
/// broker's lookup is its `piece`.
fn shared_lookup(ranges: &[Cidr]) -> dwk_proto::brokerp::egress::WorkloadEgress {
    use dwk_proto::brokerp::egress::{EgressPrefix, EgressPrefixes, WorkloadEgress};
    let mut egress = WorkloadEgress::uniform(&[("example.com", 443)], false, false).unwrap();
    egress.prefixes = EgressPrefixes::new(
        ranges
            .iter()
            .map(|c| {
                EgressPrefix::of(&wire(&c.network()), u8::try_from(c.prefix()).unwrap()).unwrap()
            })
            .collect(),
    )
    .unwrap();
    egress
}

#[test]
fn a_representative_lies_in_its_range_and_in_none_of_its_sub_ranges() {
    let ranges: Vec<Cidr> = POOL.iter().map(|t| cidr(t)).collect();
    let partition = NetworkPartition::from_ranges(ranges.clone());
    assert_eq!(partition.pieces(), POOL.len() + 2);
    for (index, range) in ranges.iter().enumerate() {
        let piece = index + 2;
        let Some(rep) = partition.representative(piece) else {
            continue;
        };
        assert!(range.contains(&rep), "{range:?} {rep}");
        for (other, inner) in ranges.iter().enumerate() {
            if other != index && inner.prefix() > range.prefix() && range.contains(&inner.network())
            {
                assert!(
                    !inner.contains(&rep),
                    "{rep} is in {inner:?}, inside {range:?}"
                );
            }
        }
        assert_eq!(partition.piece_of(&rep), piece);
    }
    // Both whole spaces are ranges here, so no address is in "no range":
    // those pieces are empty.
    assert_eq!(partition.representative(PIECE_V4_OTHER), None);
    assert_eq!(partition.representative(PIECE_V6_OTHER), None);
    // A /32 has its one address; a range wholly covered by its sub-ranges
    // has none.
    let covered = NetworkPartition::from_ranges(vec![
        cidr("10.0.0.0/31"),
        cidr("10.0.0.0/32"),
        cidr("10.0.0.1/32"),
    ]);
    assert_eq!(covered.representative(2), None);
    assert_eq!(
        covered.representative(3),
        Some(IpAddress::V4([10, 0, 0, 0]))
    );
    assert_eq!(
        covered.representative(4),
        Some(IpAddress::V4([10, 0, 0, 1]))
    );
    assert!(covered.representative(PIECE_V4_OTHER).is_some());
    assert!(covered.representative(PIECE_V6_OTHER).is_some());
}

#[test]
fn power_is_partitioned_by_its_internal_ranges_and_decided_by_them() {
    let policy = pack("power.toml");
    let partition = NetworkPartition::of(&policy).unwrap();
    assert_eq!(partition.ranges().len(), 9);
    let context = context(0, 0);
    let base = action(false);
    // An address in an internal range is denied by deny-internal-ranges; one
    // outside every range is allowed by allow-https-egress.
    let inside = partition
        .representative(partition.piece_of(&IpAddress::V4([10, 9, 9, 9])))
        .unwrap();
    let outside = partition.representative(PIECE_V4_OTHER).unwrap();
    let decided = |address| {
        evaluate(
            &policy,
            &base.clone().with_destination_ip(address),
            &context,
        )
    };
    assert_eq!(decided(inside).rule_id().as_str(), "deny-internal-ranges");
    assert_eq!(decided(outside).rule_id().as_str(), "allow-https-egress");
    // Without an address POWER cannot be decided at all: the reason a
    // partition is needed.
    assert_eq!(
        evaluate(&policy, &base, &context).unevaluable(),
        Some(Unevaluable::ResolvedAddress)
    );
}

#[test]
fn balanced_needs_no_address() {
    let policy = pack("balanced.toml");
    let partition = NetworkPartition::of(&policy).unwrap();
    assert!(partition.ranges().is_empty());
    assert_eq!(partition.pieces(), 2);
    let decided = evaluate(&policy, &action(true), &context(0, 0));
    assert_eq!(decided.unevaluable(), None);
}

#[test]
fn a_policy_with_more_ranges_than_the_bound_has_no_partition() {
    let ranges = |n: usize| {
        (0..n)
            .map(|i| format!("\"10.{}.{}.0/24\"", i >> 8, i % 256))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let policy_with = |n: usize| {
        compile(&format!(
            "schema_version = 1\n\n[meta]\nname = \"p\"\n\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [{}]\n\n[[rule]]\nid = \"b\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [{}]\n\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
            ranges(n.min(64)),
            ranges(n).replace("\"10.", "\"11.")
        ))
    };
    // Lists are bounded at 64 entries, so the count comes from several
    // rules: here up to 64 + 64.
    assert!(NetworkPartition::of(&policy_with(64)).is_ok());
    let mut text = String::from("schema_version = 1\n\n[meta]\nname = \"p\"\n");
    for rule in 0..5 {
        text.push_str(&format!(
            "\n[[rule]]\nid = \"r{rule}\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [{}]\n",
            (0..52)
                .map(|i| format!("\"{}.{}.0.0/16\"", 20 + rule, i))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    text.push_str(
        "\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
    );
    // 5 x 52 = 260 distinct ranges: past the bound.
    assert_eq!(NetworkPartition::of(&compile(&text)), Err(TooFine));
    // Exactly the bound is a partition.
    let mut exact = String::from("schema_version = 1\n\n[meta]\nname = \"p\"\n");
    for rule in 0..4 {
        exact.push_str(&format!(
            "\n[[rule]]\nid = \"r{rule}\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [{}]\n",
            (0..64)
                .map(|i| format!("\"{}.{}.0.0/16\"", 20 + rule, i))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    exact.push_str(
        "\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
    );
    let partition = NetworkPartition::of(&compile(&exact)).unwrap();
    assert_eq!(partition.ranges().len(), MAX_PARTITION_RANGES);
    // One range past the bound is past it: refused, never cut to the bound
    // or let through (ADR-0061, P-5).
    let one_more = exact.replace(
        "\n[[rule]]\nid = \"default\"\n",
        "\n[[rule]]\nid = \"r-one-more\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = [\"network.https\"]\nwhen.ip_in = [\"30.0.0.0/16\"]\n\n[[rule]]\nid = \"default\"\n",
    );
    assert_eq!(NetworkPartition::of(&compile(&one_more)), Err(TooFine));
    // Ranges only a rule for another verb names do not count.
    let other = text.replace("network.https", "network.http");
    assert!(
        NetworkPartition::of(&compile(&other))
            .unwrap()
            .ranges()
            .is_empty()
    );
}
