//! The probe's network measurements (M5b, ADR-0048): what the namespace's
//! interfaces and routes are, and what happens when a process inside tries
//! to leave it.
//!
//! The probe **attempts**; it does not trust a route table alone. Every
//! destination is a constant of the profile, plus the nameservers the
//! environment's own `/etc/resolv.conf` names (at most eight, addresses only)
//! — which can only add attempts that must fail, never remove one — and the
//! only bytes it sends are a fixed CONNECT to the proxy for a reserved
//! `.invalid` name, and a fixed DNS question. It reads at most a status line
//! back. It reports a verdict per invariant and nothing else: the errno of
//! each attempt is not in the report (the evidence fixture reports those).
//!
//! What counts as refused is **no route**: `ENETUNREACH`, `EHOSTUNREACH`, a
//! permission or family the kernel will not give. A connection is a failure,
//! and so is silence — a connect that times out, or a remote reset
//! (`ECONNREFUSED` from anywhere but the namespace's own loopback) — because
//! either means a route exists and something past it decided. The topology
//! must leave nothing to decide.

use std::fs;
use std::os::fd::OwnedFd;
use std::time::Duration;

use dwk_proto::brokerp::sandbox::Verdict;
use dwk_sandbox_profile::{
    DIRECT_DNS_V4, DIRECT_DNS_V6, DIRECT_TCP_V4, DIRECT_TCP_V6, PROXY_ADDRESS,
    PROXY_DECISION_HEADER, PROXY_OTHER_PORTS, PROXY_PORT, PROXY_PROBE_HOST,
};
use rustix::io::Errno;
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, Ipv4Addr, Ipv6Addr, RecvFlags, SendFlags, SocketAddrV4, SocketAddrV6,
    SocketType, connect, ipproto, recv, send, sendto, socket,
};

use super::{all, pass_if};

/// The longest one connection attempt is allowed: a refusal by the topology
/// is immediate, so anything slower is a route that dropped the packet.
const ATTEMPT: Duration = Duration::from_secs(2);
/// The longest the probe waits for a DNS answer that must not come.
const ANSWER: Duration = Duration::from_secs(1);
/// The longest the probe waits for the proxy's answer.
const PROXY_ANSWER: Duration = Duration::from_secs(5);
/// How long the probe waits for the relay to listen, at most: it is started
/// immediately before the measurement, and binds within milliseconds.
const RELAY_READY: Duration = Duration::from_secs(4);
/// Between two attempts while the relay is not yet listening.
const RELAY_RETRY: Duration = Duration::from_millis(100);
/// The most nameservers taken from `/etc/resolv.conf`.
const MAX_NAMESERVERS: usize = 8;
/// `RTF_REJECT`: a route that exists only to refuse.
const RTF_REJECT: u32 = 0x0200;

/// Whether an errno is a refusal by the topology or the kernel's policy: no
/// route, no such family, no permission.
const fn no_path(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::NETUNREACH
            | Errno::HOSTUNREACH
            | Errno::ACCESS
            | Errno::PERM
            | Errno::ADDRNOTAVAIL
            | Errno::AFNOSUPPORT
    )
}

fn timed(fd: &OwnedFd, limit: Duration) -> bool {
    set_socket_timeout(fd, Timeout::Send, Some(limit)).is_ok()
        && set_socket_timeout(fd, Timeout::Recv, Some(limit)).is_ok()
}

/// A TCP connection attempt: `Ok(())` connected, `Err(errno)` otherwise.
fn tcp(address: Address) -> Result<OwnedFd, Errno> {
    let family = address.family();
    let fd = socket(family, SocketType::STREAM, None)?;
    if !timed(&fd, ATTEMPT) {
        return Err(Errno::IO);
    }
    match address {
        Address::V4(a) => connect(&fd, &a)?,
        Address::V6(a) => connect(&fd, &a)?,
    }
    Ok(fd)
}

/// A destination the probe tries.
#[derive(Clone, Copy)]
enum Address {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl Address {
    fn v4(octets: [u8; 4], port: u16) -> Self {
        Self::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
    }

    fn v6(segments: [u16; 8], port: u16) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        Self::V6(SocketAddrV6::new(
            Ipv6Addr::new(a, b, c, d, e, f, g, h),
            port,
            0,
            0,
        ))
    }

    const fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::INET,
            Self::V6(_) => AddressFamily::INET6,
        }
    }
}

/// A UDP datagram attempt: whether it was refused before leaving.
fn udp_refused(address: Address, payload: &[u8]) -> Verdict {
    let Ok(fd) = socket(address.family(), SocketType::DGRAM, None) else {
        // No datagram socket at all: nothing can be sent.
        return Verdict::Pass;
    };
    let sent = match address {
        Address::V4(a) => sendto(&fd, payload, SendFlags::empty(), &a),
        Address::V6(a) => sendto(&fd, payload, SendFlags::empty(), &a),
    };
    match sent {
        Err(errno) if no_path(errno) => Verdict::Pass,
        // Sent: a route exists.
        Ok(_) => Verdict::Fail,
        Err(_) => Verdict::Unobservable,
    }
}

// ---------------------------------------------------------------------------
// CONTAINER_NETWORK_ISOLATED
// ---------------------------------------------------------------------------

/// Loopback only; no IPv4 route in the main table; no IPv6 route that is not
/// a refusal or that leaves loopback; no virtual socket.
pub(crate) fn isolated() -> Verdict {
    let interfaces = match fs::read_to_string("/proc/net/dev") {
        Ok(text) => {
            let names: Vec<&str> = text
                .lines()
                .skip(2)
                .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim()))
                .collect();
            pass_if(names == ["lo"])
        }
        Err(_) => Verdict::Unobservable,
    };
    let routes_v4 = match fs::read_to_string("/proc/net/route") {
        // The header, and nothing else.
        Ok(text) => pass_if(text.lines().skip(1).all(|l| l.trim().is_empty())),
        Err(_) => Verdict::Unobservable,
    };
    let routes_v6 = match fs::read_to_string("/proc/net/ipv6_route") {
        Ok(text) => pass_if(text.lines().all(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(flags), Some(device)) = (fields.get(8), fields.get(9)) else {
                return line.trim().is_empty();
            };
            let reject = u32::from_str_radix(flags, 16).is_ok_and(|f| f & RTF_REJECT != 0);
            reject || *device == "lo"
        })),
        // No IPv6 at all: no IPv6 route.
        Err(_) => Verdict::Pass,
    };
    all(&[interfaces, routes_v4, routes_v6, vsock_refused()])
}

/// A virtual socket is not confined by the network namespace: it reaches the
/// hypervisor host. Creating one must be refused (the profile's `AF_VSOCK`
/// rule), or be impossible on this kernel.
fn vsock_refused() -> Verdict {
    match socket(AddressFamily::VSOCK, SocketType::STREAM, None) {
        Ok(_) => Verdict::Fail,
        // EPERM is the profile's refusal; any other failure also means there
        // is no virtual socket to connect with.
        Err(_) => Verdict::Pass,
    }
}

// ---------------------------------------------------------------------------
// CONTAINER_PROXY_REACHABLE
// ---------------------------------------------------------------------------

/// The proxy endpoint accepts, and answers the probe's request for a name no
/// grant can hold with DireWolf's own refusal: the peer is the proxy, not
/// merely something listening.
pub(crate) fn proxy_reachable() -> Verdict {
    // Only "nothing listens yet" is waited out, and only for a bounded time:
    // no route, or anything else, is an answer at once.
    let started = std::time::Instant::now();
    let fd = loop {
        match tcp(Address::v4(PROXY_ADDRESS, PROXY_PORT)) {
            Ok(fd) => break fd,
            Err(Errno::CONNREFUSED) if started.elapsed() < RELAY_READY => {
                std::thread::sleep(RELAY_RETRY);
            }
            Err(_) => return Verdict::Fail,
        }
    };
    if !timed(&fd, PROXY_ANSWER) {
        return Verdict::Unobservable;
    }
    let request =
        format!("CONNECT {PROXY_PROBE_HOST}:443 HTTP/1.1\r\nHost: {PROXY_PROBE_HOST}:443\r\n\r\n");
    if send(&fd, request.as_bytes(), SendFlags::empty()) != Ok(request.len()) {
        return Verdict::Fail;
    }
    let mut answer = [0u8; 512];
    let mut read = 0usize;
    while read < answer.len() {
        let Some(window) = answer.get_mut(read..) else {
            break;
        };
        match recv(&fd, window, RecvFlags::empty()) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => read = read.saturating_add(n),
        }
    }
    let text = String::from_utf8_lossy(answer.get(..read).unwrap_or_default());
    pass_if(
        text.starts_with("HTTP/1.1 403 ")
            && text.contains(&format!(
                "\r\n{PROXY_DECISION_HEADER}: TARGET_NOT_GRANTED\r\n"
            )),
    )
}

// ---------------------------------------------------------------------------
// CONTAINER_DIRECT_EGRESS_REFUSED
// ---------------------------------------------------------------------------

/// Every direct path out refused by the topology.
pub(crate) fn direct_egress_refused() -> Verdict {
    let mut verdicts = Vec::new();
    let remote = |address: Address| match tcp(address) {
        Ok(_) => Verdict::Fail,
        Err(errno) if no_path(errno) => Verdict::Pass,
        // A timeout or a remote reset: a route exists.
        Err(_) => Verdict::Fail,
    };
    for (octets, port, _) in DIRECT_TCP_V4 {
        verdicts.push(remote(Address::v4(*octets, *port)));
        verdicts.push(udp_refused(Address::v4(*octets, *port), b"direwolf"));
    }
    for (segments, port, _) in DIRECT_TCP_V6 {
        verdicts.push(remote(Address::v6(*segments, *port)));
        verdicts.push(udp_refused(Address::v6(*segments, *port), b"direwolf"));
    }
    // The proxy's own address, on any other port: nothing answers there.
    for port in PROXY_OTHER_PORTS {
        verdicts.push(match tcp(Address::v4(PROXY_ADDRESS, *port)) {
            Ok(_) => Verdict::Fail,
            Err(Errno::CONNREFUSED) => Verdict::Pass,
            Err(errno) if no_path(errno) => Verdict::Pass,
            Err(_) => Verdict::Fail,
        });
    }
    all(&verdicts)
}

// ---------------------------------------------------------------------------
// CONTAINER_DIRECT_DNS_REFUSED
// ---------------------------------------------------------------------------

/// A fixed question: `A example.com`, recursion desired.
const QUESTION: &[u8] = &[
    0x44, 0x57, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
];

/// The nameservers `/etc/resolv.conf` names, as addresses on port 53.
fn configured() -> Vec<Address> {
    let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| {
            let host = rest.trim();
            host.parse::<Ipv4Addr>()
                .map(|a| Address::V4(SocketAddrV4::new(a, 53)))
                .or_else(|_| {
                    host.parse::<Ipv6Addr>()
                        .map(|a| Address::V6(SocketAddrV6::new(a, 53, 0, 0)))
                })
                .ok()
        })
        .take(MAX_NAMESERVERS)
        .collect()
}

/// A DNS question over UDP and over TCP to `server`: refused, or no answer.
fn no_answer(server: Address) -> Verdict {
    let udp = match socket(server.family(), SocketType::DGRAM, None) {
        Err(_) => Verdict::Pass,
        Ok(fd) if !timed(&fd, ANSWER) => Verdict::Unobservable,
        Ok(fd) => {
            let sent = match server {
                Address::V4(a) => sendto(&fd, QUESTION, SendFlags::empty(), &a),
                Address::V6(a) => sendto(&fd, QUESTION, SendFlags::empty(), &a),
            };
            match sent {
                Err(errno) if no_path(errno) => Verdict::Pass,
                Err(_) => Verdict::Unobservable,
                Ok(_) => {
                    let mut answer = [0u8; 512];
                    match recv(&fd, &mut answer, RecvFlags::empty()) {
                        // Any answer at all is a resolver this process reached.
                        Ok(_) => Verdict::Fail,
                        // No listener (`ECONNREFUSED` from loopback), or silence.
                        Err(_) => Verdict::Pass,
                    }
                }
            }
        }
    };
    let tcp = match tcp(server) {
        Ok(_) => Verdict::Fail,
        Err(Errno::CONNREFUSED) => Verdict::Pass,
        Err(errno) if no_path(errno) => Verdict::Pass,
        Err(_) => Verdict::Fail,
    };
    all(&[udp, tcp])
}

/// No DNS question leaves: to the configured resolvers and to the well-known.
pub(crate) fn direct_dns_refused() -> Verdict {
    let mut servers = configured();
    servers.extend(
        DIRECT_DNS_V4
            .iter()
            .map(|(octets, _)| Address::v4(*octets, 53)),
    );
    servers.extend(
        DIRECT_DNS_V6
            .iter()
            .map(|(segments, _)| Address::v6(*segments, 53)),
    );
    let verdicts: Vec<Verdict> = servers.into_iter().map(no_answer).collect();
    all(&verdicts)
}

// ---------------------------------------------------------------------------
// CONTAINER_RAW_SOCKETS_REFUSED
// ---------------------------------------------------------------------------

/// No raw or packet socket; an ICMP socket, where the kernel gives one,
/// reaches nothing.
pub(crate) fn raw_sockets_refused() -> Verdict {
    let refused = |family, kind, protocol| pass_if(socket(family, kind, protocol).is_err());
    let raw_v4 = refused(AddressFamily::INET, SocketType::RAW, Some(ipproto::ICMP));
    let raw_v6 = refused(AddressFamily::INET6, SocketType::RAW, Some(ipproto::ICMPV6));
    let packet = refused(AddressFamily::PACKET, SocketType::RAW, None);
    // An unprivileged ICMP ("ping") socket exists where the namespace's
    // `ping_group_range` admits the user; it must still reach nothing.
    let ping = match socket(AddressFamily::INET, SocketType::DGRAM, Some(ipproto::ICMP)) {
        Err(_) => Verdict::Pass,
        Ok(fd) => {
            // Echo request: type 8, code 0, checksum left to the kernel.
            let echo = [8u8, 0, 0, 0, 0, 1, 0, 1];
            let target = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 0);
            match sendto(&fd, &echo, SendFlags::empty(), &target) {
                Err(errno) if no_path(errno) => Verdict::Pass,
                Ok(_) => Verdict::Fail,
                Err(_) => Verdict::Unobservable,
            }
        }
    };
    all(&[raw_v4, raw_v6, packet, ping])
}

#[cfg(test)]
mod tests {
    use super::{QUESTION, no_path};
    use rustix::io::Errno;

    #[test]
    fn only_a_missing_path_counts_as_refused() {
        for errno in [
            Errno::NETUNREACH,
            Errno::HOSTUNREACH,
            Errno::ACCESS,
            Errno::PERM,
        ] {
            assert!(no_path(errno), "{errno:?}");
        }
        // A timeout or a reset is a route something answered or dropped on.
        for errno in [
            Errno::TIMEDOUT,
            Errno::CONNREFUSED,
            Errno::INPROGRESS,
            Errno::AGAIN,
        ] {
            assert!(!no_path(errno), "{errno:?}");
        }
    }

    #[test]
    fn the_question_is_one_well_formed_a_query() {
        // Header (12) + "example.com" (13) + type and class (4).
        assert_eq!(QUESTION.len(), 29);
        assert_eq!(QUESTION.get(4..6), Some(&[0u8, 1][..]));
        assert_eq!(QUESTION.last(), Some(&1u8));
    }
}
