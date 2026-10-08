//! The address guard: the **one** judgement of which resolved addresses
//! DireWolf may connect to (`NETWORK_SECURITY.md` §3; ADR-0048 §6; ADR-0050
//! §6). The broker's CONNECT proxy, the broker's `net.http` client and the
//! authority's decision on a `net.http` hop all call this module, so the two
//! daemons cannot disagree about an address, and there is no second table to
//! drift from it.
//!
//! IPv4: loopback, this-network, RFC 1918, CGNAT, link-local (cloud
//! metadata), the special-use and documentation blocks, the 6to4 relay
//! anycast, benchmarking, multicast, reserved and broadcast are blocked.
//!
//! IPv6 is judged the other way round — only global unicast (`2000::/3`) may
//! be reached at all — and within it the documentation, discard, IETF
//! protocol (`2001::/23`, Teredo included) and local-use NAT64 blocks are
//! blocked. Addresses that embed an IPv4 address are judged by it: NAT64
//! (`64:ff9b::/96`) and 6to4 (`2002::/16`) are blocked when what they embed
//! is. IPv4-mapped and IPv4-compatible addresses are blocked outright: an
//! answer naming one is never an ordinary answer.
//!
//! An answer with any blocked address is refused **whole**: all blocked is
//! [`Verdict::Blocked`]; blocked and allowed together is [`Verdict::Mixed`],
//! because a name that resolves to both public and private addresses is the
//! shape of a rebinding attack, not a set to filter (`NETWORK_SECURITY.md`
//! "DNS rebinding"). There is no unblocking in production: the only
//! exceptions anywhere are the evidence-only resolver's, and they are passed
//! in by its caller.
//!
//! The cloud metadata names are blocked by name, before any resolution.
//!
//! Pure functions over octets: no `std::net` (TX002), no resolution, no I/O.

/// Names refused before resolution, whatever they would resolve to: cloud
/// metadata services (`NETWORK_SECURITY.md` §3).
pub const METADATA_NAMES: [&str; 3] =
    ["metadata.google.internal", "metadata.goog", "instance-data"];

/// Whether `host` is a metadata name, or a name under one.
#[must_use]
pub fn name_blocked(host: &str) -> bool {
    METADATA_NAMES.iter().any(|name| {
        host == *name
            || host
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// A resolved address, as octets in network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

impl Address {
    /// The address's octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8] {
        match self {
            Self::V4(octets) => octets,
            Self::V6(octets) => octets,
        }
    }
}

/// Whether the IPv4 address `octets` is in `base/bits`.
fn v4_in(octets: [u8; 4], base: [u8; 4], bits: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    u32::from_be_bytes(octets) & mask == u32::from_be_bytes(base) & mask
}

/// The 128-bit value of eight IPv6 groups.
fn v6_value(groups: [u16; 8]) -> u128 {
    groups
        .iter()
        .fold(0u128, |value, group| (value << 16) | u128::from(*group))
}

/// Whether the IPv6 address `octets` is in `base/bits`.
fn v6_in(octets: [u8; 16], base: [u16; 8], bits: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    u128::from_be_bytes(octets) & mask == v6_value(base) & mask
}

/// Whether an IPv4 address is blocked.
#[must_use]
pub fn v4_blocked(octets: [u8; 4]) -> bool {
    [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .into_iter()
    .any(|(base, bits)| v4_in(octets, base, bits))
}

/// Whether an IPv6 address is blocked.
#[must_use]
pub fn v6_blocked(octets: [u8; 16]) -> bool {
    // NAT64's well-known prefix embeds an IPv4 address in its low 32 bits:
    // judge that.
    if v6_in(octets, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        let [.., a, b, c, d] = octets;
        return v4_blocked([a, b, c, d]);
    }
    // Only global unicast is reachable at all.
    if !v6_in(octets, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        return true;
    }
    // 6to4 embeds an IPv4 address in bits 16..48.
    if v6_in(octets, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        let [_, _, a, b, c, d, ..] = octets;
        return v4_blocked([a, b, c, d]);
    }
    [
        // IETF protocol assignments, Teredo (2001::/32) and benchmarking in it.
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        // Documentation.
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    ]
    .into_iter()
    .any(|(base, bits)| v6_in(octets, base, bits))
}

/// Whether an address is blocked.
#[must_use]
pub fn blocked(address: Address) -> bool {
    match address {
        Address::V4(octets) => v4_blocked(octets),
        Address::V6(octets) => v6_blocked(octets),
    }
}

/// How a whole answer was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every address may be reached.
    Allowed,
    /// The answer named no address.
    Empty,
    /// Every address is blocked.
    Blocked,
    /// Some addresses are blocked and some are not: a rebinding's shape.
    Mixed,
}

/// Judge a whole answer. `exceptions` are addresses let through although
/// blocked: in production there are none, and only the evidence-only
/// resolver's caller ever passes any.
#[must_use]
pub fn judge(answer: &[Address], exceptions: &[Address]) -> Verdict {
    if answer.is_empty() {
        return Verdict::Empty;
    }
    let refused = answer
        .iter()
        .filter(|address| blocked(**address) && !exceptions.contains(address))
        .count();
    if refused == answer.len() {
        Verdict::Blocked
    } else if refused > 0 {
        Verdict::Mixed
    } else {
        Verdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    // The full range table is exercised address by address through the
    // broker's adapter (`dwkd-broker`'s `egress::guard` tests parse text with
    // `std::net`, which this crate may not name). These cover the octet
    // arithmetic and the whole-answer rule directly.

    use super::{Address, Verdict, blocked, judge, name_blocked, v4_blocked, v6_blocked};

    fn v6(groups: [u16; 8]) -> [u8; 16] {
        let mut octets = [0u8; 16];
        for (pair, group) in octets.as_chunks_mut::<2>().0.iter_mut().zip(groups) {
            *pair = group.to_be_bytes();
        }
        octets
    }

    #[test]
    fn ipv4_edges() {
        for blocked4 in [
            [127, 0, 0, 1],
            [169, 254, 169, 254],
            [10, 255, 255, 255],
            [100, 64, 0, 0],
            [100, 127, 255, 255],
            [172, 31, 255, 255],
            [192, 168, 0, 1],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            [224, 0, 0, 1],
        ] {
            assert!(v4_blocked(blocked4), "{blocked4:?}");
        }
        for public in [
            [1, 1, 1, 1],
            [100, 63, 255, 255],
            [100, 128, 0, 0],
            [172, 15, 255, 255],
            [172, 32, 0, 0],
            [223, 255, 255, 255],
        ] {
            assert!(!v4_blocked(public), "{public:?}");
        }
    }

    #[test]
    fn ipv6_embedded_and_global() {
        // ::1, ::ffff:1.1.1.1 (mapped: blocked outright), fe80::1, fc00::1.
        assert!(v6_blocked(v6([0, 0, 0, 0, 0, 0, 0, 1])));
        assert!(v6_blocked(v6([0, 0, 0, 0, 0, 0xffff, 0x0101, 0x0101])));
        assert!(v6_blocked(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1])));
        assert!(v6_blocked(v6([0xfc00, 0, 0, 0, 0, 0, 0, 1])));
        // NAT64 of 127.0.0.1 blocked; of 1.1.1.1 allowed.
        assert!(v6_blocked(v6([0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1])));
        assert!(!v6_blocked(v6([0x64, 0xff9b, 0, 0, 0, 0, 0x0101, 0x0101])));
        // 6to4 of 169.254.169.254 blocked; of 1.1.1.1 allowed.
        assert!(v6_blocked(v6([0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 1])));
        assert!(!v6_blocked(v6([0x2002, 0x0101, 0x0101, 0, 0, 0, 0, 1])));
        // Documentation and Teredo blocked; ordinary global unicast allowed.
        assert!(v6_blocked(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(v6_blocked(v6([
            0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2
        ])));
        assert!(!v6_blocked(v6([
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ])));
    }

    #[test]
    fn a_whole_answer_is_judged_and_a_mixture_is_refused() {
        let public = Address::V4([151, 101, 0, 223]);
        let public6 = Address::V6(v6([0x2a04, 0x4e42, 0, 0, 0, 0, 0, 0x223]));
        let metadata = Address::V4([169, 254, 169, 254]);
        let loopback = Address::V4([127, 0, 0, 1]);
        assert!(!blocked(public) && !blocked(public6) && blocked(metadata));
        assert_eq!(judge(&[public, public6], &[]), Verdict::Allowed);
        assert_eq!(judge(&[], &[]), Verdict::Empty);
        assert_eq!(judge(&[metadata, loopback], &[]), Verdict::Blocked);
        assert_eq!(judge(&[public, metadata], &[]), Verdict::Mixed);
        assert_eq!(judge(&[loopback], &[loopback]), Verdict::Allowed);
        assert_eq!(judge(&[loopback, metadata], &[loopback]), Verdict::Mixed);
    }

    #[test]
    fn metadata_names() {
        assert!(name_blocked("metadata.google.internal"));
        assert!(name_blocked("x.metadata.goog"));
        assert!(!name_blocked("notmetadata.goog"));
        assert!(!name_blocked("instance-data.example"));
    }
}
