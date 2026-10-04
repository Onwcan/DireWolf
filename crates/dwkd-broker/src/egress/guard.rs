//! The IP guard (M5b, ADR-0048; `NETWORK_SECURITY.md` §3): which resolved
//! addresses a tunnel may reach, judged on the **whole** answer.
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
//! `ADDRESS_BLOCKED`; blocked and allowed together is `ADDRESS_MIXED`,
//! because a name that resolves to both public and private addresses is the
//! shape of a rebinding attack, not a set to filter (`NETWORK_SECURITY.md`
//! "DNS rebinding"). There is no unblocking in production; the evidence
//! harness's loopback origin is the only exception, and only the
//! evidence-only resolver carries one ([`super::resolve`]).
//!
//! The cloud metadata names are blocked by name, before any resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dwk_proto::brokerp::egress::EgressDisposition;

/// Names refused before resolution, whatever they would resolve to: cloud
/// metadata services (`NETWORK_SECURITY.md` §3).
const BLOCKED_NAMES: [&str; 3] = ["metadata.google.internal", "metadata.goog", "instance-data"];

/// Whether `host` is a metadata name, or a name under one.
pub(crate) fn name_blocked(host: &str) -> bool {
    BLOCKED_NAMES.iter().any(|name| {
        host == *name
            || host
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Whether an IPv4 address is in `base/bits`.
fn v4_in(address: Ipv4Addr, base: [u8; 4], bits: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    u32::from(address) & mask == u32::from(Ipv4Addr::from(base)) & mask
}

/// Whether an IPv6 address is in `base/bits`.
fn v6_in(address: Ipv6Addr, base: [u16; 8], bits: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    u128::from(address) & mask == u128::from(Ipv6Addr::from(base)) & mask
}

/// Whether an IPv4 address is blocked.
pub(crate) fn v4_blocked(address: Ipv4Addr) -> bool {
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
    .any(|(base, bits)| v4_in(address, base, bits))
}

/// The IPv4 address in the low 32 bits of an IPv6 address.
fn low_v4(address: Ipv6Addr) -> Ipv4Addr {
    let [.., a, b, c, d] = address.octets();
    Ipv4Addr::new(a, b, c, d)
}

/// Whether an IPv6 address is blocked.
pub(crate) fn v6_blocked(address: Ipv6Addr) -> bool {
    // NAT64's well-known prefix embeds an IPv4 address: judge that.
    if v6_in(address, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        return v4_blocked(low_v4(address));
    }
    // Only global unicast is reachable at all.
    if !v6_in(address, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        return true;
    }
    // 6to4 embeds an IPv4 address in bits 16..48.
    if v6_in(address, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        let [_, _, a, b, c, d, ..] = address.octets();
        return v4_blocked(Ipv4Addr::new(a, b, c, d));
    }
    [
        // IETF protocol assignments, Teredo (2001::/32) and benchmarking in it.
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        // Documentation.
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    ]
    .into_iter()
    .any(|(base, bits)| v6_in(address, base, bits))
}

/// Whether an address is blocked.
pub(crate) fn blocked(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => v6_blocked(v6),
    }
}

/// Judge a whole answer. `exceptions` are addresses the guard lets through
/// although blocked: none in production.
///
/// # Errors
///
/// `RESOLUTION_FAILED` for an empty answer; `ADDRESS_BLOCKED` when every
/// address is blocked; `ADDRESS_MIXED` when some are.
pub(crate) fn judge(
    answer: &[IpAddr],
    exceptions: &[IpAddr],
) -> Result<Vec<IpAddr>, EgressDisposition> {
    if answer.is_empty() {
        return Err(EgressDisposition::ResolutionFailed);
    }
    let refused = answer
        .iter()
        .filter(|a| blocked(**a) && !exceptions.contains(a))
        .count();
    if refused == answer.len() {
        Err(EgressDisposition::AddressBlocked)
    } else if refused > 0 {
        Err(EgressDisposition::AddressMixed)
    } else {
        Ok(answer.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use dwk_proto::brokerp::egress::EgressDisposition as D;

    use super::{blocked, judge, name_blocked};

    fn ip(text: &str) -> IpAddr {
        text.parse()
            .unwrap_or_else(|_| IpAddr::from([255, 255, 255, 255]))
    }

    #[test]
    fn every_documented_range_is_blocked() {
        for address in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "169.254.7.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.168.65.254",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.251",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:1.1.1.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::a00:1",
            "64:ff9b:1::1.1.1.1",
            "100::1",
            "fc00::1",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
            "2002:c0a8:101::1",
        ] {
            assert!(blocked(ip(address)), "{address}");
        }
    }

    #[test]
    fn public_addresses_are_not() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "151.101.0.223",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a04:4e42::223",
            "64:ff9b::101:101",
            "2002:101:101::1",
        ] {
            assert!(!blocked(ip(address)), "{address}");
        }
    }

    #[test]
    fn a_whole_answer_is_judged_and_a_mixture_is_refused() {
        let public = ip("151.101.0.223");
        let public6 = ip("2a04:4e42::223");
        let metadata = ip("169.254.169.254");
        let loopback = ip("127.0.0.1");
        assert_eq!(judge(&[public, public6], &[]), Ok(vec![public, public6]));
        assert_eq!(judge(&[], &[]), Err(D::ResolutionFailed));
        assert_eq!(judge(&[metadata], &[]), Err(D::AddressBlocked));
        assert_eq!(judge(&[metadata, loopback], &[]), Err(D::AddressBlocked));
        assert_eq!(judge(&[public, metadata], &[]), Err(D::AddressMixed));
        assert_eq!(judge(&[loopback, public], &[]), Err(D::AddressMixed));
        // An exception lets exactly its address through, and nothing more.
        assert_eq!(judge(&[loopback], &[loopback]), Ok(vec![loopback]));
        assert_eq!(
            judge(&[loopback, metadata], &[loopback]),
            Err(D::AddressMixed)
        );
    }

    #[test]
    fn metadata_names_are_blocked_by_name() {
        for name in [
            "metadata.google.internal",
            "metadata.goog",
            "instance-data",
            "x.metadata.google.internal",
        ] {
            assert!(name_blocked(name), "{name}");
        }
        for name in [
            "pypi.org",
            "notmetadata.goog",
            "metadata.google",
            "instance-data.example",
        ] {
            assert!(!name_blocked(name), "{name}");
        }
    }
}
