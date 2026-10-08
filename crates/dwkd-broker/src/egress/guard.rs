//! The IP guard (M5b, ADR-0048; `NETWORK_SECURITY.md` §3), as the broker
//! calls it: an adapter from `std::net` addresses to the **one** guard in
//! `dwk_proto::wire::guard`, which the `net.http` client and the authority's
//! `net.http` decision call too (ADR-0050 §6). The table lives there and only
//! there; this file converts types and maps a verdict to a disposition.
//!
//! An answer with any blocked address is refused **whole**: all blocked is
//! `ADDRESS_BLOCKED`; blocked and allowed together is `ADDRESS_MIXED`, because
//! a name that resolves to both public and private addresses is the shape of a
//! rebinding attack, not a set to filter (`NETWORK_SECURITY.md` "DNS
//! rebinding"). There is no unblocking in production; the evidence harness's
//! loopback origin is the only exception, and only the evidence-only resolver
//! carries one ([`super::resolve`]).

use std::net::IpAddr;

use dwk_proto::brokerp::egress::EgressDisposition;
use dwk_proto::wire::guard::{self, Address, Verdict};

/// An address as the shared guard takes it.
pub(crate) fn address(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(v4) => Address::V4(v4.octets()),
        IpAddr::V6(v6) => Address::V6(v6.octets()),
    }
}

/// Whether `host` is a metadata name, or a name under one.
pub(crate) fn name_blocked(host: &str) -> bool {
    guard::name_blocked(host)
}

/// Whether an address is blocked.
#[cfg(test)]
pub(crate) fn blocked(ip: IpAddr) -> bool {
    guard::blocked(address(ip))
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
    let shared: Vec<Address> = answer.iter().copied().map(address).collect();
    let allowed: Vec<Address> = exceptions.iter().copied().map(address).collect();
    match guard::judge(&shared, &allowed) {
        Verdict::Allowed => Ok(answer.to_vec()),
        Verdict::Empty => Err(EgressDisposition::ResolutionFailed),
        Verdict::Blocked => Err(EgressDisposition::AddressBlocked),
        Verdict::Mixed => Err(EgressDisposition::AddressMixed),
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
