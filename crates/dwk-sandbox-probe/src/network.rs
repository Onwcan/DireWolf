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
//! What counts as refused is **no path**: the kernel refusing the attempt
//! before anything leaves — `ENETUNREACH`, a permission or a family it will
//! not give. Anything else means a route exists, and is a failure whether or
//! not anything ever replies: a connection; a datagram the kernel accepted; a
//! connect still pending when its time runs out; a reset (`ECONNREFUSED`)
//! from anywhere but the namespace's own loopback; a neighbour that never
//! answered (`EHOSTUNREACH`). A path that drops packets is still a path. The
//! topology must leave nothing to decide.
//!
//! **Bounded, however the namespace routes.** In the strict topology every
//! attempt is answered at once — no route, or the namespace's own loopback.
//! In a namespace that does route (a weakened or drifted one) a destination
//! may stay silent, and an attempt would wait out its whole time. So each
//! invariant's attempts share one deadline ([`PROXY_BUDGET`],
//! [`EGRESS_BUDGET`], [`DNS_BUDGET`]: together well inside the broker's
//! [`PROBE_STEP_SECONDS`], so the report always arrives); the cheapest proof
//! goes first (a datagram the kernel accepts proves a route without waiting
//! on anyone); and the first failure decides the invariant — one path out is
//! enough. A deadline that passes before an invariant is decided makes it
//! `UNOBSERVABLE`, never `PASS`.

use std::fs;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::sandbox::Verdict;
use dwk_sandbox_profile::{
    DIRECT_DNS_V4, DIRECT_DNS_V6, DIRECT_TCP_V4, DIRECT_TCP_V6, PROBE_STEP_SECONDS, PROXY_ADDRESS,
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
/// The longest the probe waits for a DNS answer from the namespace's own
/// loopback, where something listening could answer.
const ANSWER: Duration = Duration::from_secs(1);
/// The longest the probe waits for the proxy's answer.
const PROXY_ANSWER: Duration = Duration::from_secs(5);
/// How long the probe waits for the relay to listen, at most: it is started
/// immediately before the measurement, and binds within milliseconds.
const RELAY_READY: Duration = Duration::from_secs(4);
/// Between two attempts while the relay is not yet listening.
const RELAY_RETRY: Duration = Duration::from_millis(100);
/// Everything `CONTAINER_PROXY_REACHABLE` may wait for, together.
const PROXY_BUDGET: Duration = Duration::from_secs(8);
/// Everything `CONTAINER_DIRECT_EGRESS_REFUSED` may wait for, together.
const EGRESS_BUDGET: Duration = Duration::from_secs(5);
/// Everything `CONTAINER_DIRECT_DNS_REFUSED` may wait for, together.
const DNS_BUDGET: Duration = Duration::from_secs(5);
/// The most nameservers taken from `/etc/resolv.conf`.
const MAX_NAMESERVERS: usize = 8;
/// `RTF_REJECT`: a route that exists only to refuse.
const RTF_REJECT: u32 = 0x0200;

// Every network attempt together takes at most two thirds of the broker's
// step, so the report is printed in time even when every one of them waits
// out its deadline; and the relay is waited for within the proxy's own.
const _: () = assert!(
    (PROXY_BUDGET.as_secs() + EGRESS_BUDGET.as_secs() + DNS_BUDGET.as_secs()) * 3
        <= PROBE_STEP_SECONDS * 2
);
const _: () = assert!(RELAY_READY.as_secs() + ATTEMPT.as_secs() < PROXY_BUDGET.as_secs());

/// Whether an errno is the kernel refusing an attempt before anything left:
/// no route, no such family, no permission. `EHOSTUNREACH` is not: it is
/// what a route to a neighbour that never answered gives, as well as a
/// remote router's word that it could go no further — either way, a path.
const fn no_path(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::NETUNREACH | Errno::ACCESS | Errno::PERM | Errno::ADDRNOTAVAIL | Errno::AFNOSUPPORT
    )
}

/// When an invariant's attempts must stop.
#[derive(Debug, Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(budget: Duration) -> Self {
        Self(Instant::now() + budget)
    }

    /// The time left, at most `cap`; `None` once the deadline has passed.
    fn left(self, cap: Duration) -> Option<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(cap))
    }
}

/// Try each of `items` in order, giving each what is left of `deadline`, at
/// most `cap`. The first `FAIL` is the verdict at once: one path out is
/// enough, and trying more destinations would only spend the probe's time.
/// A deadline that passes before every item was tried is `UNOBSERVABLE` —
/// never `PASS`. Otherwise every verdict together.
fn until_failure<T>(
    items: &[T],
    deadline: Deadline,
    cap: Duration,
    mut attempt: impl FnMut(&T, Duration) -> Verdict,
) -> Verdict {
    let mut verdicts = Vec::with_capacity(items.len());
    for item in items {
        let Some(limit) = deadline.left(cap) else {
            return Verdict::Unobservable;
        };
        let verdict = attempt(item, limit);
        if verdict == Verdict::Fail {
            return Verdict::Fail;
        }
        verdicts.push(verdict);
    }
    all(&verdicts)
}

fn timed(fd: &OwnedFd, limit: Duration) -> bool {
    set_socket_timeout(fd, Timeout::Send, Some(limit)).is_ok()
        && set_socket_timeout(fd, Timeout::Recv, Some(limit)).is_ok()
}

/// A TCP connection attempt, waiting at most `limit`: the connection, or
/// why there is none (a connect still pending when `limit` passes is
/// `EINPROGRESS`).
fn tcp(address: Address, limit: Duration) -> Result<OwnedFd, Errno> {
    let fd = socket(address.family(), SocketType::STREAM, None)?;
    if !timed(&fd, limit) {
        return Err(Errno::IO);
    }
    match address {
        Address::V4(a) => connect(&fd, &a)?,
        Address::V6(a) => connect(&fd, &a)?,
    }
    Ok(fd)
}

/// A TCP attempt's verdict. Only no path, or a reset by the namespace's own
/// loopback (`local`: nothing listens there), is refused; a connection, a
/// connect still pending, a remote reset or any other error is a path.
fn tcp_verdict(attempt: Result<(), Errno>, local: bool) -> Verdict {
    match attempt {
        Err(errno) if no_path(errno) => Verdict::Pass,
        Err(Errno::CONNREFUSED) if local => Verdict::Pass,
        Ok(()) | Err(_) => Verdict::Fail,
    }
}

/// A datagram's verdict: refused before it left, or a route.
fn udp_verdict(sent: Result<usize, Errno>) -> Verdict {
    match sent {
        Err(errno) if no_path(errno) => Verdict::Pass,
        // The kernel took it: a route exists, whoever is at the far end.
        Ok(_) => Verdict::Fail,
        Err(_) => Verdict::Unobservable,
    }
}

/// A destination the probe tries.
#[derive(Debug, Clone, Copy)]
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

    /// Whether this is the namespace's own loopback, where a reset or a
    /// silence means nothing listens, not that something past a route
    /// decided.
    fn loopback(self) -> bool {
        match self {
            Self::V4(a) => a.ip().is_loopback(),
            Self::V6(a) => a.ip().is_loopback(),
        }
    }
}

/// One attempt to leave the namespace.
#[derive(Debug, Clone, Copy)]
enum Attempt {
    /// A datagram to a destination outside it.
    Udp(Address),
    /// A TCP connection; `local` when a reset there is the namespace's own
    /// address with nothing listening.
    Tcp { address: Address, local: bool },
    /// A DNS question over UDP to a resolver.
    Dns(Address),
}

impl Attempt {
    fn verdict(self, limit: Duration) -> Verdict {
        match self {
            Self::Udp(address) => udp(address, b"direwolf"),
            Self::Tcp { address, local } => tcp_verdict(tcp(address, limit).map(drop), local),
            Self::Dns(server) => dns_udp(server, limit),
        }
    }
}

/// A datagram attempt.
fn udp(address: Address, payload: &[u8]) -> Verdict {
    let fd = match socket(address.family(), SocketType::DGRAM, None) {
        Ok(fd) => fd,
        // No datagram socket of this family, or none permitted: nothing can
        // be sent. Any other failure proves nothing either way.
        Err(errno) if no_path(errno) => return Verdict::Pass,
        Err(_) => return Verdict::Unobservable,
    };
    udp_verdict(match address {
        Address::V4(a) => sendto(&fd, payload, SendFlags::empty(), &a),
        Address::V6(a) => sendto(&fd, payload, SendFlags::empty(), &a),
    })
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
/// merely something listening. Within [`PROXY_BUDGET`].
pub(crate) fn proxy_reachable() -> Verdict {
    let deadline = Deadline::after(PROXY_BUDGET);
    // Only "nothing listens yet" is waited out, and only for a bounded time:
    // no route, a connect left pending, or anything else, is an answer at
    // once.
    let ready = Deadline::after(RELAY_READY);
    let fd = loop {
        let Some(limit) = deadline.left(ATTEMPT) else {
            return Verdict::Unobservable;
        };
        match tcp(Address::v4(PROXY_ADDRESS, PROXY_PORT), limit) {
            Ok(fd) => break fd,
            Err(Errno::CONNREFUSED) if ready.left(RELAY_RETRY).is_some() => {
                std::thread::sleep(RELAY_RETRY);
            }
            Err(_) => return Verdict::Fail,
        }
    };
    let request =
        format!("CONNECT {PROXY_PROBE_HOST}:443 HTTP/1.1\r\nHost: {PROXY_PROBE_HOST}:443\r\n\r\n");
    if send(&fd, request.as_bytes(), SendFlags::empty()) != Ok(request.len()) {
        return Verdict::Fail;
    }
    let mut answer = [0u8; 512];
    let mut read = 0usize;
    while read < answer.len() {
        // However the answer trickles in, the deadline holds.
        let Some(limit) = deadline.left(PROXY_ANSWER) else {
            break;
        };
        if !timed(&fd, limit) {
            return Verdict::Unobservable;
        }
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

/// What `CONTAINER_DIRECT_EGRESS_REFUSED` tries, cheapest proof first: a
/// datagram to every direct destination (accepted means a route, at once),
/// then a connection to each, then the proxy's own address on every other
/// port, where only the namespace's loopback may answer, with a reset.
fn egress_attempts() -> Vec<Attempt> {
    let direct: Vec<Address> = DIRECT_TCP_V4
        .iter()
        .map(|(octets, port, _)| Address::v4(*octets, *port))
        .chain(
            DIRECT_TCP_V6
                .iter()
                .map(|(segments, port, _)| Address::v6(*segments, *port)),
        )
        .collect();
    let mut attempts: Vec<Attempt> = direct.iter().map(|a| Attempt::Udp(*a)).collect();
    attempts.extend(direct.iter().map(|a| Attempt::Tcp {
        address: *a,
        local: false,
    }));
    attempts.extend(PROXY_OTHER_PORTS.iter().map(|port| Attempt::Tcp {
        address: Address::v4(PROXY_ADDRESS, *port),
        local: true,
    }));
    attempts
}

/// Every direct path out refused by the topology, within [`EGRESS_BUDGET`].
pub(crate) fn direct_egress_refused() -> Verdict {
    until_failure(
        &egress_attempts(),
        Deadline::after(EGRESS_BUDGET),
        ATTEMPT,
        |attempt, limit| attempt.verdict(limit),
    )
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

/// A DNS question over UDP to `server`, on a connected socket: no route is
/// refused at the connect; a route to a resolver outside the namespace is a
/// failure at once — the question could leave, whoever answers it; on the
/// namespace's own loopback the question is asked, and any answer is a
/// resolver this process reached, while a reset (nothing listens) or a
/// silence of [`ANSWER`] is not.
fn dns_udp(server: Address, limit: Duration) -> Verdict {
    let fd = match socket(server.family(), SocketType::DGRAM, None) {
        Ok(fd) => fd,
        // No datagram socket of this family, or none permitted: nothing can
        // be asked. Any other failure proves nothing either way.
        Err(errno) if no_path(errno) => return Verdict::Pass,
        Err(_) => return Verdict::Unobservable,
    };
    let connected = match server {
        Address::V4(a) => connect(&fd, &a),
        Address::V6(a) => connect(&fd, &a),
    };
    match connected {
        Err(errno) if no_path(errno) => return Verdict::Pass,
        Err(_) => return Verdict::Unobservable,
        Ok(()) if !server.loopback() => return Verdict::Fail,
        Ok(()) => {}
    }
    if !timed(&fd, limit.min(ANSWER)) {
        return Verdict::Unobservable;
    }
    match send(&fd, QUESTION, SendFlags::empty()) {
        Ok(_) => {}
        Err(errno) if no_path(errno) => return Verdict::Pass,
        Err(Errno::CONNREFUSED) => return Verdict::Pass,
        Err(_) => return Verdict::Unobservable,
    }
    let mut answer = [0u8; 512];
    match recv(&fd, &mut answer, RecvFlags::empty()) {
        // Any answer at all is a resolver this process reached.
        Ok(_) => Verdict::Fail,
        // Nothing listens there, or nothing that answers.
        Err(Errno::CONNREFUSED | Errno::AGAIN) => Verdict::Pass,
        Err(_) => Verdict::Unobservable,
    }
}

/// What `CONTAINER_DIRECT_DNS_REFUSED` tries: the configured and the
/// well-known resolvers, over UDP first (a route outside is proved at the
/// connect), then over TCP, where only the loopback's reset is a refusal.
fn dns_attempts() -> Vec<Attempt> {
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
    let mut attempts: Vec<Attempt> = servers.iter().map(|s| Attempt::Dns(*s)).collect();
    attempts.extend(servers.iter().map(|s| Attempt::Tcp {
        address: *s,
        local: s.loopback(),
    }));
    attempts
}

/// No DNS question leaves, within [`DNS_BUDGET`].
pub(crate) fn direct_dns_refused() -> Verdict {
    until_failure(
        &dns_attempts(),
        Deadline::after(DNS_BUDGET),
        ATTEMPT,
        |attempt, limit| attempt.verdict(limit),
    )
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
            udp_verdict(sendto(&fd, &echo, SendFlags::empty(), &target))
        }
    };
    all(&[raw_v4, raw_v6, packet, ping])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
mod tests {
    use std::os::fd::OwnedFd;
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::sandbox::Verdict;
    use rustix::io::Errno;
    use rustix::net::{
        AddressFamily, Ipv4Addr, RecvFlags, SendFlags, SocketAddrV4, SocketType, bind, getsockname,
        listen, recvfrom, sendto, socket,
    };

    use super::{
        Address, Attempt, DNS_BUDGET, Deadline, EGRESS_BUDGET, PROBE_STEP_SECONDS, PROXY_BUDGET,
        QUESTION, dns_udp, egress_attempts, no_path, tcp, tcp_verdict, udp_verdict, until_failure,
    };

    /// A socket of `kind` bound to a free loopback port, and its address.
    fn bound(kind: SocketType) -> (OwnedFd, SocketAddrV4) {
        let fd = socket(AddressFamily::INET, kind, None).unwrap();
        bind(&fd, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = SocketAddrV4::try_from(getsockname(&fd).unwrap()).unwrap();
        (fd, address)
    }

    /// A route that exists to a destination that stays silent, made
    /// deterministically on loopback: a listener that never accepts, its
    /// queue filled, drops every further SYN, so a connect to it waits until
    /// its time runs out — what a routed namespace's blackholed destination
    /// does. The returned descriptors keep it so.
    fn silent_destination() -> (Vec<OwnedFd>, Address) {
        let (listener, address) = bound(SocketType::STREAM);
        listen(&listener, 1).unwrap();
        let mut held = vec![listener];
        for _ in 0..16 {
            match tcp(Address::V4(address), Duration::from_millis(300)) {
                Ok(queued) => held.push(queued),
                Err(errno) => {
                    assert!(
                        matches!(errno, Errno::INPROGRESS | Errno::AGAIN),
                        "{errno:?}"
                    );
                    return (held, Address::V4(address));
                }
            }
        }
        panic!("a listener that never accepts kept accepting connections")
    }

    #[test]
    fn only_a_missing_path_counts_as_refused() {
        for errno in [
            Errno::NETUNREACH,
            Errno::ACCESS,
            Errno::PERM,
            Errno::ADDRNOTAVAIL,
            Errno::AFNOSUPPORT,
        ] {
            assert!(no_path(errno), "{errno:?}");
        }
        // A timeout, a reset, a pending connect or a neighbour that never
        // answered: a route something answered, dropped or never reached.
        for errno in [
            Errno::TIMEDOUT,
            Errno::CONNREFUSED,
            Errno::INPROGRESS,
            Errno::AGAIN,
            Errno::HOSTUNREACH,
        ] {
            assert!(!no_path(errno), "{errno:?}");
        }
    }

    #[test]
    fn a_route_is_a_failure_whether_or_not_anything_answers() {
        // TCP: connected, still pending, reset from afar, unreachable host.
        for attempt in [
            Ok(()),
            Err(Errno::INPROGRESS),
            Err(Errno::AGAIN),
            Err(Errno::TIMEDOUT),
            Err(Errno::CONNREFUSED),
            Err(Errno::HOSTUNREACH),
            Err(Errno::IO),
        ] {
            assert_eq!(tcp_verdict(attempt, false), Verdict::Fail, "{attempt:?}");
        }
        // Only no path, or the namespace's own loopback with nothing there.
        assert_eq!(tcp_verdict(Err(Errno::NETUNREACH), false), Verdict::Pass);
        assert_eq!(tcp_verdict(Err(Errno::CONNREFUSED), true), Verdict::Pass);
        assert_eq!(tcp_verdict(Err(Errno::INPROGRESS), true), Verdict::Fail);
        // UDP: a datagram the kernel took is a route; never a pass.
        assert_eq!(udp_verdict(Ok(8)), Verdict::Fail);
        assert_eq!(udp_verdict(Err(Errno::NETUNREACH)), Verdict::Pass);
        assert_eq!(udp_verdict(Err(Errno::HOSTUNREACH)), Verdict::Unobservable);
    }

    #[test]
    fn a_routed_but_silent_destination_fails_at_once_and_bounded() {
        // The hosted failure's shape: a namespace with a route, destinations
        // that never answer. Twenty of them at the probe's two seconds each
        // were forty seconds — past the broker's whole step, which lost the
        // report. Now the first silence is the failure, within its cap.
        let (_held, silent) = silent_destination();
        let attempts = vec![
            Attempt::Tcp {
                address: silent,
                local: false,
            };
            20
        ];
        let cap = Duration::from_millis(300);
        let started = Instant::now();
        let verdict = until_failure(
            &attempts,
            Deadline::after(Duration::from_secs(5)),
            cap,
            |a, limit| a.verdict(limit),
        );
        let took = started.elapsed();
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            took >= cap.saturating_sub(Duration::from_millis(50)),
            "{took:?}"
        );
        assert!(took < Duration::from_secs(2), "{took:?}");
        // Even its own loopback's silence is a path, not a refusal.
        assert_eq!(
            Attempt::Tcp {
                address: silent,
                local: true
            }
            .verdict(cap),
            Verdict::Fail
        );
    }

    #[test]
    fn a_deadline_that_passes_undecided_is_never_a_pass() {
        // Attempts that each wait out their time and prove nothing: the
        // deadline stops them, and the verdict is UNOBSERVABLE.
        let items = [(); 50];
        let started = Instant::now();
        let verdict = until_failure(
            &items,
            Deadline::after(Duration::from_millis(400)),
            Duration::from_millis(100),
            |_, limit| {
                std::thread::sleep(limit);
                Verdict::Unobservable
            },
        );
        assert_eq!(verdict, Verdict::Unobservable);
        assert!(started.elapsed() < Duration::from_millis(900));
        // A deadline already gone tries nothing and passes nothing.
        let gone = Deadline::after(Duration::ZERO);
        let verdict = until_failure(&[()], gone, Duration::from_secs(1), |_, _| {
            panic!("nothing is tried after the deadline")
        });
        assert_eq!(verdict, Verdict::Unobservable);
        // Every attempt refused within the deadline: a pass.
        let verdict = until_failure(
            &[(); 3],
            Deadline::after(DNS_BUDGET),
            Duration::from_secs(1),
            |_, _| Verdict::Pass,
        );
        assert_eq!(verdict, Verdict::Pass);
    }

    #[test]
    fn the_cheapest_proof_goes_first_and_the_budgets_fit_the_step() {
        // Datagrams first: each proves a route at once, without waiting.
        let attempts = egress_attempts();
        let first_tcp = attempts
            .iter()
            .position(|a| matches!(a, Attempt::Tcp { .. }))
            .unwrap();
        assert!(first_tcp > 0);
        assert!(
            attempts
                .iter()
                .take(first_tcp)
                .all(|a| matches!(a, Attempt::Udp(_)))
        );
        let total = PROXY_BUDGET + EGRESS_BUDGET + DNS_BUDGET;
        assert!(
            total * 3 <= Duration::from_secs(PROBE_STEP_SECONDS) * 2,
            "{total:?}"
        );
    }

    #[test]
    fn a_loopback_resolver_is_asked_and_judged_by_its_answer() {
        // Nothing listening: the connected socket hears the reset at once,
        // not after a silence.
        let (unused, address) = bound(SocketType::DGRAM);
        drop(unused);
        let started = Instant::now();
        assert_eq!(
            dns_udp(Address::V4(address), Duration::from_secs(1)),
            Verdict::Pass
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        // A resolver that answers inside the namespace: a failure.
        let (resolver, address) = bound(SocketType::DGRAM);
        let answering = std::thread::spawn(move || {
            let mut question = [0u8; 512];
            let (n, _, from) = recvfrom(&resolver, &mut question, RecvFlags::empty()).unwrap();
            assert_eq!(question.get(..n), Some(QUESTION));
            let from = SocketAddrV4::try_from(from.unwrap()).unwrap();
            sendto(&resolver, QUESTION, SendFlags::empty(), &from).unwrap();
        });
        assert_eq!(
            dns_udp(Address::V4(address), Duration::from_secs(1)),
            Verdict::Fail
        );
        answering.join().unwrap();
    }

    #[test]
    fn the_question_is_one_well_formed_a_query() {
        // Header (12) + "example.com" (13) + type and class (4).
        assert_eq!(QUESTION.len(), 29);
        assert_eq!(QUESTION.get(4..6), Some(&[0u8, 1][..]));
        assert_eq!(QUESTION.last(), Some(&1u8));
    }
}
