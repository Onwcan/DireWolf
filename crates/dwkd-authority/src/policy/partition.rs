//! The address dimension of a network decision, decided ahead of the address
//! (F-17, ADR-0061, Proposed).
//!
//! A sandboxed workload's tunnel is decided when the workload starts, but its
//! address is known only when the broker resolves the name for that tunnel.
//! Policy may turn on the address (`when.ip_in`), and an action with no
//! address is unevaluable at such a rule. So the decision is made **for
//! every address at once**, exactly, by cutting the address space into the
//! pieces on which policy cannot tell two addresses apart and evaluating the
//! production evaluator once per piece.
//!
//! # Why it is exact
//!
//! 1. Within `crate::policy`, the only reader of an action's address is the
//!    `ip_in` predicate (`predicate::address_in`), and it asks one thing:
//!    whether the address lies in each range the rule names
//!    (`Cidr::contains`). `unless` reads only the context. So, with every
//!    other fact fixed, the decision is a function of the vector "is the
//!    address in range c" over the ranges R the policy names. A test holds
//!    the first sentence to the source (`only_address_in_reads_the_address`).
//! 2. Two prefix ranges of one family are nested or disjoint, and a range of
//!    one family holds no address of the other. So that vector is fixed by
//!    the address's **most specific** range in R -- or by "none", per
//!    family: all its ancestors hold it, nothing else does.
//! 3. So the decision is constant on each piece "addresses whose most
//!    specific range is L" (and "in no range" per family), and evaluating it
//!    at any one address of the piece gives it for the whole piece --
//!    first-match order, postconditions, the mandatory `default`, deciding
//!    rule and obligations included, because the evaluator itself is what
//!    runs.
//!
//! A piece can be empty (its range's sub-ranges cover it): it has no
//! representative and no address can be in it.
//!
//! R is every range in every rule and postcondition whose verb can match a
//! `network.https` action, by the rule's own verb matcher. Any larger set
//! would do as well; this one keeps the count down. More than
//! [`MAX_PARTITION_RANGES`] and there is no partition: a decision that needs
//! the address is then refused, never approximated.

use crate::capability::{Action, Namespace, Verb};

use super::action::IpAddress;
use super::rule::CompiledPolicy;
use super::value::Cidr;

/// The most ranges a partition is made of: the egress authorisation's own
/// bound (`dwk_proto::brokerp::egress::MAX_EGRESS_PREFIXES`).
pub const MAX_PARTITION_RANGES: usize = 256;

/// Piece 0: the IPv4 addresses in no range.
pub const PIECE_V4_OTHER: usize = 0;
/// Piece 1: the IPv6 addresses in no range.
pub const PIECE_V6_OTHER: usize = 1;

/// Why a policy has no partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooFine;

/// The active policy's network ranges, and an address of each piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPartition {
    /// Distinct, in the order the policy first names them.
    ranges: Vec<Cidr>,
    /// One per piece -- `[v4 other, v6 other, range 0, range 1, ...]` -- or
    /// `None` for a piece no address is in.
    representatives: Vec<Option<IpAddress>>,
}

/// An address as a family and a number: `bits` wide, `value` its high bits
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Numbered {
    v6: bool,
    value: u128,
}

impl Numbered {
    fn of(address: &IpAddress) -> Self {
        match address {
            IpAddress::V4(o) => Self {
                v6: false,
                value: u128::from(u32::from_be_bytes(*o)),
            },
            IpAddress::V6(o) => Self {
                v6: true,
                value: u128::from_be_bytes(*o),
            },
        }
    }

    const fn bits(self) -> u32 {
        if self.v6 { 128 } else { 32 }
    }

    fn address(self) -> Option<IpAddress> {
        if self.v6 {
            Some(IpAddress::V6(self.value.to_be_bytes()))
        } else {
            u32::try_from(self.value)
                .ok()
                .map(|v| IpAddress::V4(v.to_be_bytes()))
        }
    }
}

/// A range as a family, a first address and a length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    start: Numbered,
    length: u32,
}

impl Block {
    fn of(cidr: &Cidr) -> Self {
        Self {
            start: Numbered::of(&cidr.network()),
            length: cidr.prefix(),
        }
    }

    const fn whole(v6: bool) -> Self {
        Self {
            start: Numbered { v6, value: 0 },
            length: 0,
        }
    }

    /// The first `length` bits of `value`, the rest zero.
    fn masked(value: u128, length: u32, bits: u32) -> u128 {
        if length == 0 {
            return 0;
        }
        let host = bits.saturating_sub(length);
        let mask = u128::MAX
            .checked_shl(host)
            .unwrap_or(0)
            .checked_shl(128 - bits)
            .map_or(0, |m| m >> (128 - bits));
        value & mask
    }

    /// Whether this block holds every address of `other`.
    fn holds(self, other: Self) -> bool {
        self.start.v6 == other.start.v6
            && self.length <= other.length
            && Self::masked(other.start.value, self.length, self.start.bits()) == self.start.value
    }

    /// The two halves, if the block is wider than one address.
    fn halves(self) -> Option<(Self, Self)> {
        let bits = self.start.bits();
        if self.length >= bits {
            return None;
        }
        let length = self.length + 1;
        let high = 1u128.checked_shl(bits - length)?;
        Some((
            Self {
                start: self.start,
                length,
            },
            Self {
                start: Numbered {
                    v6: self.start.v6,
                    value: self.start.value | high,
                },
                length,
            },
        ))
    }
}

/// An address of `within` that no block of `inside` holds, if there is one.
/// Every block of `inside` lies strictly within `within` or apart from it.
fn free_address(within: Block, inside: &[Block]) -> Option<Numbered> {
    let touching: Vec<Block> = inside
        .iter()
        .copied()
        .filter(|b| b.holds(within) || within.holds(*b))
        .collect();
    if touching.is_empty() {
        return Some(within.start);
    }
    if touching.iter().any(|b| b.holds(within)) {
        return None;
    }
    let (low, high) = within.halves()?;
    free_address(low, &touching).or_else(|| free_address(high, &touching))
}

/// Whether a rule whose verb predicate is `verb` can match `network.https`.
fn names_network_https(verb: Option<&super::predicate::MatchValue<Verb>>) -> bool {
    Verb::new(Namespace::Network, Action::Https)
        .is_some_and(|https| verb.is_none_or(|named| named.matches(&https)))
}

impl NetworkPartition {
    /// The partition of `policy`'s network ranges.
    ///
    /// # Errors
    ///
    /// [`TooFine`] when the policy names more than [`MAX_PARTITION_RANGES`]
    /// distinct ranges a `network.https` action could be judged by.
    pub fn of(policy: &CompiledPolicy) -> Result<Self, TooFine> {
        let mut ranges: Vec<Cidr> = Vec::new();
        let named = policy.rules().iter().map(super::rule::Rule::when).chain(
            policy
                .postconditions()
                .iter()
                .map(super::rule::Postcondition::when),
        );
        for when in named {
            if !names_network_https(when.verb.as_ref()) {
                continue;
            }
            let Some(ip_in) = &when.ip_in else {
                continue;
            };
            for cidr in ip_in.values() {
                if !ranges.contains(cidr) {
                    if ranges.len() >= MAX_PARTITION_RANGES {
                        return Err(TooFine);
                    }
                    ranges.push(*cidr);
                }
            }
        }
        Ok(Self::from_ranges(ranges))
    }

    /// The partition `ranges` make. They must be distinct.
    #[must_use]
    pub fn from_ranges(ranges: Vec<Cidr>) -> Self {
        let blocks: Vec<Block> = ranges.iter().map(Block::of).collect();
        let mut representatives = Vec::with_capacity(blocks.len().saturating_add(2));
        for v6 in [false, true] {
            let family: Vec<Block> = blocks
                .iter()
                .copied()
                .filter(|b| b.start.v6 == v6)
                .collect();
            representatives
                .push(free_address(Block::whole(v6), &family).and_then(Numbered::address));
        }
        for (index, block) in blocks.iter().enumerate() {
            let inside: Vec<Block> = blocks
                .iter()
                .enumerate()
                .filter(|(other, b)| *other != index && block.holds(**b))
                .map(|(_, b)| *b)
                .collect();
            representatives.push(free_address(*block, &inside).and_then(Numbered::address));
        }
        Self {
            ranges,
            representatives,
        }
    }

    /// The ranges, in order: range `i` is piece `2 + i`.
    #[must_use]
    pub fn ranges(&self) -> &[Cidr] {
        &self.ranges
    }

    /// How many pieces there are.
    #[must_use]
    pub fn pieces(&self) -> usize {
        self.representatives.len()
    }

    /// An address of piece `piece`, or `None` when no address is in it.
    #[must_use]
    pub fn representative(&self, piece: usize) -> Option<IpAddress> {
        self.representatives.get(piece).copied().flatten()
    }

    /// The piece `address` is in: its most specific range, or its family's
    /// "in no range" piece.
    #[must_use]
    pub fn piece_of(&self, address: &IpAddress) -> usize {
        let mut best: Option<(usize, u32)> = None;
        for (index, range) in self.ranges.iter().enumerate() {
            if range.contains(address) && best.is_none_or(|(_, length)| range.prefix() > length) {
                best = Some((index, range.prefix()));
            }
        }
        match (best, address) {
            (Some((index, _)), _) => index.saturating_add(2),
            (None, IpAddress::V4(_)) => PIECE_V4_OTHER,
            (None, IpAddress::V6(_)) => PIECE_V6_OTHER,
        }
    }
}

#[cfg(test)]
#[path = "partition_tests.rs"]
mod tests;
