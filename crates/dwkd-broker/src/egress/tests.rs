//! The proxy end to end in-process (M5b, ADR-0048): a real [`Proxies`]
//! socket, real threads, a real TCP origin on loopback, and the evidence
//! resolver choosing what names resolve to. The test stands where the relay
//! does, connecting through the environment's directory; the OCI topology
//! around it is the sandbox egress evidence's (`tests/sandbox_egress.rs`).
//!
//! Every tunnel names `origin.test`, which the fixture resolves to the
//! loopback origin; `127.0.0.1` is the fixture's one exception, so the guard
//! is still the real guard for every other address.
//!
//! Since F-17 (ADR-0061, Proposed) a CONNECT is carried only while a
//! workload's egress authorisation is in force: [`env`] installs one that
//! allows every granted destination, so each test here exercises its own
//! check; the tests at the end exercise the authorisation itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::{
    EgressBits, EgressByteBudget, EgressCell, EgressDisposition as D, EgressGrant, EgressHost,
    EgressPort, EgressPrefix, EgressPrefixes, EgressTarget, EgressTargets, EgressTunnelLimit,
    WorkloadEgress, WorkloadEgressTarget, WorkloadEgressTargets,
};
use dwk_proto::wire::id::InvocationId;
use dwk_sandbox_profile::{EGRESS_SOCKET_NAME, RELAY_UID};

use super::hello::build;
use super::proxy::{Authorised, Proxies, relay_only_acl};
use super::resolve::{FixtureResolver, Resolver as _, Shared};
use super::{HELLO_MAX_BUFFERED, Limits};

const HOST: &str = "origin.test";

fn limits() -> Limits {
    Limits {
        request: Duration::from_millis(800),
        resolve: Duration::from_millis(300),
        hello: Duration::from_millis(800),
        connect: Duration::from_secs(2),
        idle: Duration::from_secs(5),
        lifetime: Duration::from_secs(20),
    }
}

/// A scratch directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "dw-eg-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A loopback TCP origin: counts connections, keeps what it receives, and
/// sends `reply` bytes to each connection first.
struct Origin {
    port: u16,
    accepted: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<u8>>>,
}

fn origin(reply: usize) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let (count, keep) = (Arc::clone(&accepted), Arc::clone(&received));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let keep = Arc::clone(&keep);
            std::thread::spawn(move || {
                let _ = stream.write_all(&vec![b'r'; reply]);
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    keep.lock().unwrap().extend_from_slice(&buffer[..n]);
                }
            });
        }
    });
    Origin {
        port,
        accepted,
        received,
    }
}

fn grant(port: u16, tunnels: u16, upload: u64, download: u64) -> EgressGrant {
    EgressGrant {
        targets: EgressTargets::new(vec![EgressTarget {
            host: EgressHost::new(HOST.to_owned()).unwrap(),
            port: EgressPort::new(port).unwrap(),
        }])
        .unwrap(),
        max_tunnels: EgressTunnelLimit::new(tunnels).unwrap(),
        max_upload_bytes: EgressByteBudget::new(upload).unwrap(),
        max_download_bytes: EgressByteBudget::new(download).unwrap(),
    }
}

fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A proxy for one environment, `e1`, with this fixture, and a workload's
/// authorisation in force that allows every granted destination.
struct Env {
    proxies: Proxies,
    dir: PathBuf,
    resolver: Arc<FixtureResolver>,
    authorised: Option<Authorised>,
    _scratch: Scratch,
}

const ENV: &str = "e1";

/// The workspace root every environment here is on, unless a test says.
const ROOT: (u64, u64) = (7, 7);

fn invocation(n: u8) -> InvocationId {
    InvocationId::parse(&format!("inv_01M24BB8G3E0A851TRWE3M8F{n:02}")).unwrap()
}

/// The destinations `grant` names.
fn destinations(grant: &EgressGrant) -> Vec<(String, u16)> {
    grant
        .targets
        .iter()
        .map(|t| (t.host.as_str().to_owned(), t.port.get()))
        .collect()
}

/// An authorisation for `destinations` allowing every address in every cell.
fn open_to(destinations: &[(String, u16)]) -> WorkloadEgress {
    let refs: Vec<(&str, u16)> = destinations.iter().map(|(h, p)| (h.as_str(), *p)).collect();
    WorkloadEgress::uniform(&refs, true, false).unwrap()
}

fn env_with(fixture: &str, grant: EgressGrant, limits: Limits) -> Env {
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(fixture).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits).unwrap();
    let granted = destinations(&grant);
    let dir = proxies.start(ENV, grant, ROOT).unwrap();
    let authorised = Some(
        proxies
            .authorise(ENV, &invocation(1), open_to(&granted))
            .unwrap(),
    );
    Env {
        proxies,
        dir,
        resolver,
        authorised,
        _scratch: scratch,
    }
}

fn env(fixture: &str, grant: EgressGrant) -> Env {
    env_with(fixture, grant, limits())
}

fn loopback() -> String {
    format!("resolve {HOST} 127.0.0.1\nallow 127.0.0.1\n")
}

fn dial(dir: &Path) -> UnixStream {
    let stream = UnixStream::connect(dir.join(EGRESS_SOCKET_NAME)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// Send a request and read the reply's head.
fn ask(stream: &mut UnixStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn connect(stream: &mut UnixStream, port: u16) -> String {
    ask(
        stream,
        &format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n"),
    )
}

/// Read until the proxy closes; return what arrived.
fn drain(stream: &mut UnixStream) -> Vec<u8> {
    let mut all = Vec::new();
    let _ = stream.read_to_end(&mut all);
    all
}

/// Wait until `disposition` has been counted `n` times.
fn counted(env: &Env, disposition: D, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let now = env
            .proxies
            .counters(ENV)
            .map_or(0, |c| c.count(disposition));
        if now >= n {
            assert_eq!(now, n, "{disposition:?}");
            return;
        }
        assert!(Instant::now() < deadline, "{disposition:?} never counted");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn refused_with(head: &str, status: &str, disposition: D) {
    assert!(
        head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
        "{head}"
    );
    assert!(
        head.contains(&format!(
            "\r\nX-DireWolf-Egress: {}\r\n",
            disposition.as_str()
        )),
        "{head}"
    );
}

#[test]
fn a_granted_tunnel_with_an_agreeing_name_carries_bytes_both_ways() {
    let origin = origin(5);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    let head = connect(&mut client, origin.port);
    assert_eq!(head, "HTTP/1.1 200 Connection Established\r\n\r\n");
    let hello = build::hello(HOST);
    client.write_all(&hello).unwrap();
    client.write_all(b"opaque application bytes").unwrap();
    let mut reply = [0u8; 5];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"rrrrr");
    client.shutdown(std::net::Shutdown::Write).unwrap();
    counted(&env, D::Closed, 1);
    let mut expected = hello.clone();
    expected.extend_from_slice(b"opaque application bytes");
    assert_eq!(*origin.received.lock().unwrap(), expected);
    let counters = env.proxies.counters(ENV).unwrap();
    assert_eq!(
        counters.bytes_upstream.get(),
        u64::try_from(expected.len()).unwrap()
    );
    assert_eq!(counters.bytes_downstream.get(), 5);
    // Resolved once, for the one tunnel.
    assert_eq!(env.resolver.queries(HOST), 1);
}

#[test]
fn a_target_that_is_not_granted_is_refused_before_anything_is_resolved() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    for request in [
        format!("CONNECT {HOST}:{} HTTP/1.1\r\n\r\n", origin.port + 1),
        format!("CONNECT other.test:{} HTTP/1.1\r\n\r\n", origin.port),
        "CONNECT direwolf-probe.invalid:443 HTTP/1.1\r\n\r\n".to_owned(),
    ] {
        let mut client = dial(&env.dir);
        refused_with(
            &ask(&mut client, &request),
            "403 Forbidden",
            D::TargetNotGranted,
        );
    }
    counted(&env, D::TargetNotGranted, 3);
    assert_eq!(env.resolver.queries(HOST), 0);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_and_smuggling_requests_are_refused_with_400() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let port = origin.port;
    for (request, disposition) in [
        (
            format!("GET http://{HOST}:{port}/ HTTP/1.1\r\n\r\n"),
            D::NotConnect,
        ),
        (
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
            D::TargetNotCanonical,
        ),
        (
            format!("CONNECT ORIGIN.test:{port} HTTP/1.1\r\n\r\n"),
            D::TargetNotCanonical,
        ),
        (
            format!("CONNECT {HOST}.:{port} HTTP/1.1\r\n\r\n"),
            D::TargetNotCanonical,
        ),
        (
            format!("CONNECT user@{HOST}:{port} HTTP/1.1\r\n\r\n"),
            D::TargetNotCanonical,
        ),
        (
            format!("CONNECT {HOST}:{port} HTTP/1.1\r\nContent-Length: 4\r\n\r\nGET "),
            D::Malformed,
        ),
        (
            format!("CONNECT {HOST}:{port} HTTP/1.1\nHost: x\r\n\r\n"),
            D::Malformed,
        ),
        (
            format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: evil.test:{port}\r\n\r\n"),
            D::Malformed,
        ),
    ] {
        let mut client = dial(&env.dir);
        refused_with(&ask(&mut client, &request), "400 Bad Request", disposition);
    }
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(env.resolver.queries(HOST), 0);
}

#[test]
fn a_slow_request_times_out() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    client.write_all(b"CONNECT origin.te").unwrap();
    let reply = String::from_utf8_lossy(&drain(&mut client)).into_owned();
    refused_with(&reply, "408 Request Timeout", D::RequestTimeout);
    counted(&env, D::RequestTimeout, 1);
}

#[test]
fn the_whole_answer_is_judged_and_nothing_blocked_is_dialled() {
    let origin = origin(0);
    for (answer, disposition) in [
        ("10.0.0.1", D::AddressBlocked),
        ("169.254.169.254", D::AddressBlocked),
        ("::ffff:127.0.0.1", D::AddressBlocked),
        ("127.0.0.1,10.0.0.1", D::AddressMixed),
        ("127.0.0.1,169.254.169.254", D::AddressMixed),
        ("fail", D::ResolutionFailed),
        ("timeout", D::ResolutionTimeout),
    ] {
        let fixture = format!("resolve {HOST} {answer}\nallow 127.0.0.1\n");
        let env = env(&fixture, grant(origin.port, 4, 1 << 20, 1 << 20));
        let mut client = dial(&env.dir);
        refused_with(
            &connect(&mut client, origin.port),
            "403 Forbidden",
            disposition,
        );
        counted(&env, disposition, 1);
        assert_eq!(env.resolver.queries(HOST), 1, "{answer}");
    }
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn a_rebinding_name_is_resolved_once_per_tunnel_and_never_again() {
    let origin = origin(0);
    let fixture = format!("resolve {HOST} 127.0.0.1;10.0.0.1\nallow 127.0.0.1\n");
    let env = env(&fixture, grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut first = dial(&env.dir);
    assert!(connect(&mut first, origin.port).starts_with("HTTP/1.1 200 "));
    first.write_all(&build::hello(HOST)).unwrap();
    // The tunnel reached the pinned origin, however the name answers later.
    let deadline = Instant::now() + Duration::from_secs(5);
    while origin.accepted.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    first.write_all(b"more").unwrap();
    assert_eq!(env.resolver.queries(HOST), 1);
    let mut second = dial(&env.dir);
    refused_with(
        &connect(&mut second, origin.port),
        "403 Forbidden",
        D::AddressBlocked,
    );
    assert_eq!(env.resolver.queries(HOST), 2);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn metadata_names_are_refused_by_name_even_when_granted() {
    let scratch = Scratch::new();
    let fixture = FixtureResolver::parse("resolve metadata.google.internal 151.101.0.1\n").unwrap();
    let resolver = Arc::new(fixture);
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let grant = EgressGrant {
        targets: EgressTargets::new(vec![EgressTarget {
            host: EgressHost::new("metadata.google.internal".to_owned()).unwrap(),
            port: EgressPort::new(443).unwrap(),
        }])
        .unwrap(),
        ..grant(443, 1, 1, 1)
    };
    let dir = proxies.start(ENV, grant, ROOT).unwrap();
    let mut client = dial(&dir);
    let head = ask(
        &mut client,
        "CONNECT metadata.google.internal:443 HTTP/1.1\r\n\r\n",
    );
    refused_with(&head, "403 Forbidden", D::AddressBlocked);
    assert_eq!(resolver.queries("metadata.google.internal"), 0);
}

/// After `200`, send `hello` and see the tunnel end with `disposition`
/// without the origin ever being dialled.
fn hello_refused(hello: &[u8], disposition: D) {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(hello).unwrap();
    let rest = drain(&mut client);
    assert!(rest.is_empty(), "{rest:?}");
    counted(&env, disposition, 1);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0, "{disposition:?}");
}

#[test]
fn the_server_name_must_be_the_connect_host_before_anything_is_dialled() {
    use build::{extension, message, records, server_name};
    hello_refused(&build::hello("evil.test"), D::SniMismatch);
    hello_refused(&build::hello("ORIGIN.test"), D::SniMismatch);
    hello_refused(&build::hello("origin.test."), D::SniMismatch);
    hello_refused(
        &records(&message(&[extension(0x000a, &[0, 2, 0, 0x1d])]), 1 << 14),
        D::SniMissing,
    );
    hello_refused(
        &records(
            &message(&[server_name(&[(0, HOST.as_bytes()), (0, b"evil.test")])]),
            1 << 14,
        ),
        D::SniAmbiguous,
    );
    hello_refused(
        &records(
            &message(&[
                server_name(&[(0, HOST.as_bytes())]),
                server_name(&[(0, HOST.as_bytes())]),
            ]),
            1 << 14,
        ),
        D::ClientHelloMalformed,
    );
    hello_refused(
        &records(
            &message(&[
                server_name(&[(0, HOST.as_bytes())]),
                extension(0xfe0d, &[0, 1]),
            ]),
            1 << 14,
        ),
        D::EchRefused,
    );
    hello_refused(
        b"GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n",
        D::ClientHelloMalformed,
    );
    hello_refused(&[22, 3, 1, 0x40, 0x01], D::ClientHelloMalformed);
    hello_refused(
        &records(&[1, 0, 0x40, 0x01], 1 << 14),
        D::ClientHelloMalformed,
    );
    // Truncated: the client gives up half way.
    let whole = build::hello(HOST);
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&whole[..whole.len() >> 1]).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(drain(&mut client).is_empty());
    counted(&env, D::ClientHelloMalformed, 1);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn a_fragmented_hello_is_accepted_and_a_slow_one_times_out() {
    // One byte per record, written a few bytes at a time.
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    let message = build::message(&[build::server_name(&[(0, HOST.as_bytes())])]);
    let fragmented = build::records(&message, 1);
    for chunk in fragmented.chunks(7) {
        client.write_all(chunk).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while origin.received.lock().unwrap().len() < fragmented.len() {
        assert!(
            Instant::now() < deadline,
            "the fragmented hello never arrived"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*origin.received.lock().unwrap(), fragmented);
    // Nothing after 200.
    let mut silent = dial(&env.dir);
    assert!(connect(&mut silent, origin.port).starts_with("HTTP/1.1 200 "));
    assert!(drain(&mut silent).is_empty());
    counted(&env, D::ClientHelloTimeout, 1);
    // An overlong hello in tiny records: refused once the buffer bound is hit.
    let mut flood = dial(&env.dir);
    assert!(connect(&mut flood, origin.port).starts_with("HTTP/1.1 200 "));
    let big = build::message(&[
        build::server_name(&[(0, HOST.as_bytes())]),
        build::extension(0x0015, &vec![0; 16_000]),
    ]);
    let _ = flood.write_all(&build::records(&big, 1)[..=HELLO_MAX_BUFFERED]);
    assert!(drain(&mut flood).is_empty());
    counted(&env, D::ClientHelloMalformed, 1);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn the_upload_budget_holds_at_the_socket() {
    let origin = origin(0);
    let hello = build::hello(HOST);
    let budget = u64::try_from(hello.len()).unwrap() + 1000;
    let env = env(&loopback(), grant(origin.port, 4, budget, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&hello).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while origin.received.lock().unwrap().len() < hello.len() {
        assert!(Instant::now() < deadline, "the hello never arrived");
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = client.write_all(&[b'u'; 4000]);
    let _ = drain(&mut client);
    counted(&env, D::UploadBudget, 1);
    // Exactly the budget was carried, and not a byte more.
    let counters = env.proxies.counters(ENV).unwrap();
    assert_eq!(counters.bytes_upstream.get(), budget);
    std::thread::sleep(Duration::from_millis(200));
    let received = u64::try_from(origin.received.lock().unwrap().len()).unwrap();
    assert!(received <= budget, "{received} > {budget}");
    // Spent is spent: the next tunnel's hello alone exceeds what is left.
    let mut next = dial(&env.dir);
    assert!(connect(&mut next, origin.port).starts_with("HTTP/1.1 200 "));
    next.write_all(&hello).unwrap();
    assert!(drain(&mut next).is_empty());
    counted(&env, D::UploadBudget, 2);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn the_download_budget_holds_at_the_socket() {
    let origin = origin(10_000);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 4096));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&build::hello(HOST)).unwrap();
    let got = drain(&mut client);
    assert!(got.len() <= 4096, "{}", got.len());
    counted(&env, D::DownloadBudget, 1);
    assert_eq!(
        env.proxies.counters(ENV).unwrap().bytes_downstream.get(),
        4096
    );
}

#[test]
fn fronting_inside_an_agreeing_tunnel_is_carried_unseen_and_bounded_by_the_budget() {
    // The residual, shown honestly: after the name agrees, the proxy cannot
    // see the request inside — here a plaintext stand-in for what TLS would
    // hide, naming another host. It is carried, and only the budget bounds it.
    let origin = origin(0);
    let hello = build::hello(HOST);
    let budget = u64::try_from(hello.len()).unwrap() + 64;
    let env = env(&loopback(), grant(origin.port, 4, budget, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&hello).unwrap();
    let inner = b"GET / HTTP/1.1\r\nHost: fronted.example\r\n\r\n";
    client.write_all(inner).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !origin.received.lock().unwrap().ends_with(inner) {
        assert!(
            Instant::now() < deadline,
            "the inner request was not carried"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = client.write_all(&[b'x'; 4096]);
    let _ = drain(&mut client);
    counted(&env, D::UploadBudget, 1);
    assert!(u64::try_from(origin.received.lock().unwrap().len()).unwrap() <= budget);
}

#[test]
fn the_tunnel_limit_holds_while_tunnels_are_open() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 1, 1 << 20, 1 << 20));
    let mut first = dial(&env.dir);
    assert!(connect(&mut first, origin.port).starts_with("HTTP/1.1 200 "));
    let mut second = dial(&env.dir);
    refused_with(
        &connect(&mut second, origin.port),
        "403 Forbidden",
        D::TunnelLimit,
    );
    first.write_all(&build::hello(HOST)).unwrap();
    first.shutdown(std::net::Shutdown::Both).unwrap();
    counted(&env, D::Closed, 1);
    let mut third = dial(&env.dir);
    assert!(connect(&mut third, origin.port).starts_with("HTTP/1.1 200 "));
}

#[test]
fn idle_and_lifetime_end_a_tunnel() {
    let origin = origin(0);
    let short = Limits {
        idle: Duration::from_millis(600),
        ..limits()
    };
    let env = env_with(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20), short);
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&build::hello(HOST)).unwrap();
    assert!(drain(&mut client).is_empty());
    counted(&env, D::IdleTimeout, 1);

    let brief = Limits {
        lifetime: Duration::from_millis(900),
        ..limits()
    };
    let env = env_with(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20), brief);
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&build::hello(HOST)).unwrap();
    // Keep it busy: it is not idle, it is old.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        if client.write_all(b"tick").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    counted(&env, D::LifetimeExceeded, 1);
}

#[test]
fn closing_the_environment_ends_its_tunnels_and_removes_its_socket() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = dial(&env.dir);
    assert!(connect(&mut client, origin.port).starts_with("HTTP/1.1 200 "));
    client.write_all(&build::hello(HOST)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while origin.accepted.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(env.proxies.is_open(ENV));
    let counters = env.proxies.close(ENV).unwrap();
    assert_eq!(counters.count(D::EnvironmentClosed), 1);
    assert!(drain(&mut client).is_empty());
    assert!(!env.proxies.is_open(ENV));
    assert!(!env.dir.exists());
    assert!(UnixStream::connect(env.dir.join(EGRESS_SOCKET_NAME)).is_err());
    assert_eq!(env.proxies.close(ENV), None);
}

#[test]
fn the_socket_is_reachable_only_through_its_directory() {
    let origin = origin(0);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    // The root: the broker's alone. The environment's directory: the broker
    // everything, the relay's uid search through the ACL (its mask shows as
    // the group bits), everyone else nothing. The socket: connectable by
    // whoever reaches it — only the broker and the relay's uid can.
    assert_eq!(mode(env.dir.parent().unwrap()), 0o700);
    assert_eq!(mode(&env.dir), 0o710);
    assert_eq!(mode(&env.dir.join(EGRESS_SOCKET_NAME)), 0o666);
    let mut held = [0u8; 64];
    let length = rustix::fs::lgetxattr(&env.dir, "system.posix_acl_access", &mut held[..]).unwrap();
    assert_eq!(&held[..length], relay_only_acl(RELAY_UID).as_slice());
    // The broker, the directory's owner, still connects.
    assert!(UnixStream::connect(env.dir.join(EGRESS_SOCKET_NAME)).is_ok());
    let names: Vec<_> = std::fs::read_dir(&env.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from(EGRESS_SOCKET_NAME)]);
    // Loosened after the fact, the directory is no longer the relay's
    // alone, and the proxy no longer counts as open (`HOST_PROXY_RELAY`).
    assert!(env.proxies.is_open(ENV));
    std::fs::set_permissions(&env.dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    assert!(!env.proxies.is_open(ENV));
}

#[test]
fn the_relay_only_acl_is_the_kernels_encoding() {
    let acl = relay_only_acl(10_002);
    let undefined = [0xff, 0xff, 0xff, 0xff];
    let entry = |tag: u8, permissions: u8, id: [u8; 4]| {
        let mut e = vec![tag, 0, permissions, 0];
        e.extend_from_slice(&id);
        e
    };
    let mut expected = vec![2, 0, 0, 0];
    expected.extend(entry(0x01, 0o7, undefined));
    expected.extend(entry(0x02, 0o1, [0x12, 0x27, 0, 0]));
    expected.extend(entry(0x04, 0, undefined));
    expected.extend(entry(0x10, 0o1, undefined));
    expected.extend(entry(0x20, 0, undefined));
    assert_eq!(acl, expected);
}

#[test]
fn a_restarted_broker_removes_only_its_own_stale_directories() {
    let scratch = Scratch::new();
    let root = scratch.0.join("egress");
    let shared: Shared = Arc::new(FixtureResolver::parse("").unwrap());
    {
        let proxies = Proxies::new(root.clone(), own_uid(), Arc::clone(&shared), limits()).unwrap();
        proxies.start("e1", grant(443, 1, 1, 1), ROOT).unwrap();
        // The broker dies: its listener is gone, its directory is not.
        std::mem::drop(proxies);
    }
    std::fs::write(root.join("foreign-file"), b"not ours").unwrap();
    std::fs::create_dir(root.join("not.an.environment")).unwrap();
    std::fs::create_dir(root.join("env_FOREIGN")).unwrap();
    std::fs::write(root.join("env_FOREIGN").join("data"), b"not a socket").unwrap();
    let proxies = Proxies::new(root.clone(), own_uid(), shared, limits()).unwrap();
    assert!(!root.join("e1").exists());
    assert!(root.join("foreign-file").exists());
    assert!(root.join("not.an.environment").exists());
    assert!(root.join("env_FOREIGN").join("data").exists());
    assert!(proxies.environments().is_empty());
    // A root anyone else can read is refused.
    let loose = scratch.0.join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(
        &loose,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    let shared: Shared = Arc::new(FixtureResolver::parse("").unwrap());
    assert!(Proxies::new(loose, own_uid(), shared, limits()).is_err());
}

#[test]
fn the_production_resolver_has_no_exceptions() {
    assert!(super::resolve::SystemResolver.exceptions().is_empty());
}

/// The two names of M5e.3's registry origins, as the fixture generator spells
/// them (`tests/sandbox/registry_fixtures.py`), so this test and the fixtures
/// cannot name different hosts.
fn registry_hosts() -> (String, String) {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/sandbox/registry_fixtures.py"),
    )
    .unwrap();
    let constant = |name: &str| -> String {
        let prefix = format!("{name} = \"");
        source
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str())?.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{name} is not in the generator"))
            .to_owned()
    };
    (constant("GRANTED_HOST"), constant("UNGRANTED_HOST"))
}

fn registry_grant(host: &str, port: u16) -> EgressGrant {
    EgressGrant {
        targets: EgressTargets::new(vec![EgressTarget {
            host: EgressHost::new(host.to_owned()).unwrap(),
            port: EgressPort::new(port).unwrap(),
        }])
        .unwrap(),
        ..grant(port, 4, 1 << 20, 1 << 20)
    }
}

fn connect_to(stream: &mut UnixStream, host: &str, port: u16) -> String {
    ask(
        stream,
        &format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"),
    )
}

/// M5e.3's two registry origins as the proxy meets them
/// (`M5E_ASSURANCE_PLAN.md` §7a): the generator's own names, which only the evidence's fixture
/// resolver maps to loopback, and a run granted the granted origin alone. A
/// tunnel to it carries a client hello naming it. A CONNECT to the ungranted
/// origin -- or to the granted name at the ungranted origin's port -- is the
/// proxy's `TARGET_NOT_GRANTED`, decided before its name is resolved and
/// before a byte reaches that origin. Nothing of TLS has begun, so it is never
/// a TLS failure; that the ungranted origin's TLS is as valid as the granted
/// one's is `tests/sandbox/test_registry_origins.py`'s.
#[test]
fn a_registry_tunnel_reaches_the_granted_origin_and_never_the_ungranted_one() {
    let (granted_host, ungranted_host) = registry_hosts();
    // RFC 6761's reserved top-level name: nothing public answers for either.
    for host in [&granted_host, &ungranted_host] {
        assert_eq!(
            host.rsplit_once('.').map(|(_, top)| top),
            Some("test"),
            "{host}"
        );
    }
    assert_ne!(granted_host, ungranted_host);
    let granted = origin(0);
    let ungranted = origin(0);
    let fixture = format!(
        "resolve {granted_host} 127.0.0.1\nresolve {ungranted_host} 127.0.0.1\nallow 127.0.0.1\n"
    );
    let env = env(&fixture, registry_grant(&granted_host, granted.port));
    let mut client = dial(&env.dir);
    assert_eq!(
        connect_to(&mut client, &granted_host, granted.port),
        "HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    let hello = build::hello(&granted_host);
    client.write_all(&hello).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    counted(&env, D::Closed, 1);
    assert_eq!(*granted.received.lock().unwrap(), hello);
    for (host, port) in [
        (ungranted_host.as_str(), ungranted.port),
        (granted_host.as_str(), ungranted.port),
    ] {
        let mut refused = dial(&env.dir);
        refused_with(
            &connect_to(&mut refused, host, port),
            "403 Forbidden",
            D::TargetNotGranted,
        );
    }
    counted(&env, D::TargetNotGranted, 2);
    assert_eq!(env.resolver.queries(&ungranted_host), 0);
    assert_eq!(env.resolver.queries(&granted_host), 1);
    assert_eq!(ungranted.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(granted.accepted.load(Ordering::SeqCst), 1);
}

/// Without the evidence fixture's loopback exception the production guard
/// stands as it always does: the granted registry, resolved to loopback, is
/// refused as a blocked address and never dialled. The registry origins are
/// reachable only through the evidence-only resolver.
#[test]
fn a_registry_origin_on_loopback_is_refused_without_the_evidence_exception() {
    let (granted_host, _) = registry_hosts();
    let granted = origin(0);
    let env = env(
        &format!("resolve {granted_host} 127.0.0.1\n"),
        registry_grant(&granted_host, granted.port),
    );
    let mut client = dial(&env.dir);
    refused_with(
        &connect_to(&mut client, &granted_host, granted.port),
        "403 Forbidden",
        D::AddressBlocked,
    );
    counted(&env, D::AddressBlocked, 1);
    assert_eq!(granted.accepted.load(Ordering::SeqCst), 0);
}

// ===========================================================================
// F-17 (ADR-0061, Proposed): a workload's egress authorisation, in force.
// ===========================================================================

/// A destination and its cells: host, port, the four cells' bits, and a
/// per-tunnel bound for every cell.
type Destination<'a> = (&'a str, u16, [&'a [bool]; 4], Option<u64>);

/// An authorisation whose cells are given: per destination, the four cells'
/// bits -- novel/pristine, novel/exposed, seen/pristine, seen/exposed -- over
/// the pieces `prefixes` make, and a per-tunnel bound for every cell.
fn authorisation(prefixes: &[&str], targets: &[Destination<'_>]) -> WorkloadEgress {
    let cell = |bits: &[bool], bound: Option<u64>| EgressCell {
        allowed: EgressBits::from_pieces(bits).unwrap(),
        max_tunnel_download_bytes: bound.map(|b| EgressByteBudget::new(b).unwrap()),
    };
    let egress = WorkloadEgress {
        exposed: false,
        prefixes: EgressPrefixes::new(
            prefixes
                .iter()
                .map(|p| EgressPrefix::new(*p).unwrap())
                .collect(),
        )
        .unwrap(),
        targets: WorkloadEgressTargets::new(
            targets
                .iter()
                .map(|(host, port, cells, bound)| WorkloadEgressTarget {
                    host: EgressHost::new(*host).unwrap(),
                    port: EgressPort::new(*port).unwrap(),
                    seen: false,
                    novel_pristine: cell(cells[0], *bound),
                    novel_exposed: cell(cells[1], *bound),
                    seen_pristine: cell(cells[2], *bound),
                    seen_exposed: cell(cells[3], *bound),
                })
                .collect(),
        )
        .unwrap(),
    };
    assert_eq!(egress.check(), Ok(()));
    egress
}

/// A grant of these destinations, roomy budgets.
fn grant_of(destinations: &[(&str, u16)]) -> EgressGrant {
    EgressGrant {
        targets: EgressTargets::new(
            destinations
                .iter()
                .map(|(host, port)| EgressTarget {
                    host: EgressHost::new(*host).unwrap(),
                    port: EgressPort::new(*port).unwrap(),
                })
                .collect(),
        )
        .unwrap(),
        ..grant(443, 8, 1 << 20, 1 << 20)
    }
}

/// A loopback origin that answers only when told: it takes the client
/// hello, waits for the word, then sends `reply` bytes.
fn gated_origin(reply: usize) -> (Origin, std::sync::mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let (word, wait) = std::sync::mpsc::channel::<()>();
    let (count, keep) = (Arc::clone(&accepted), Arc::clone(&received));
    std::thread::spawn(move || {
        let Some(Ok(mut stream)) = listener.incoming().next() else {
            return;
        };
        count.fetch_add(1, Ordering::SeqCst);
        let mut buffer = [0u8; 4096];
        if let Ok(n) = stream.read(&mut buffer) {
            keep.lock().unwrap().extend_from_slice(&buffer[..n]);
        }
        if wait.recv_timeout(Duration::from_secs(20)).is_ok() {
            let _ = stream.write_all(&vec![b'r'; reply]);
        }
        while let Ok(n) = stream.read(&mut buffer) {
            if n == 0 {
                break;
            }
            keep.lock().unwrap().extend_from_slice(&buffer[..n]);
        }
    });
    (
        Origin {
            port,
            accepted,
            received,
        },
        word,
    )
}

/// Wait until `origin` has received something.
fn received_something(origin: &Origin) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while origin.received.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "the origin heard nothing");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait until `environment`'s proxy has counted `disposition` `n` times.
fn counted_in(proxies: &Proxies, environment: &str, disposition: D, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let now = proxies
            .counters(environment)
            .map_or(0, |c| c.count(disposition));
        if now >= n {
            assert_eq!(now, n, "{disposition:?}");
            return;
        }
        assert!(Instant::now() < deadline, "{disposition:?} never counted");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Open a tunnel to `host:port` through `dir` and send its client hello.
fn tunnel_to(dir: &Path, host: &str, port: u16) -> UnixStream {
    let mut client = dial(dir);
    let head = connect_to(&mut client, host, port);
    assert_eq!(
        head, "HTTP/1.1 200 Connection Established\r\n\r\n",
        "{host}"
    );
    client.write_all(&build::hello(host)).unwrap();
    client
}

const OTHER: &str = "other.test";

fn two_names() -> String {
    format!("resolve {HOST} 127.0.0.1\nresolve {OTHER} 127.0.0.1\nallow 127.0.0.1\n")
}

#[test]
fn nothing_is_carried_without_a_workloads_authorisation() {
    let origin = origin(5);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let Env {
        proxies,
        dir,
        resolver,
        authorised,
        _scratch,
    } = env;
    // The workload ends: its authorisation goes, and a granted destination
    // is refused before anything is resolved or dialled.
    let report = authorised.unwrap().finish().unwrap();
    assert!(!report.exposed);
    let mut client = dial(&dir);
    refused_with(
        &connect(&mut client, origin.port),
        "403 Forbidden",
        D::NotAuthorised,
    );
    counted_in(&proxies, ENV, D::NotAuthorised, 1);
    assert_eq!(resolver.queries(HOST), 0);
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
    // The probe's reserved name is still the ceiling's: TARGET_NOT_GRANTED,
    // whatever is in force.
    let mut probe = dial(&dir);
    refused_with(
        &ask(
            &mut probe,
            "CONNECT direwolf-probe.invalid:443 HTTP/1.1\r\n\r\n",
        ),
        "403 Forbidden",
        D::TargetNotGranted,
    );
}

#[test]
fn a_cell_that_allows_nothing_refuses_before_resolution() {
    let origin = origin(5);
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(&loopback()).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let dir = proxies
        .start(ENV, grant_of(&[(HOST, origin.port)]), ROOT)
        .unwrap();
    let denied = WorkloadEgress::uniform(&[(HOST, origin.port)], false, false).unwrap();
    let authorised = proxies.authorise(ENV, &invocation(2), denied).unwrap();
    let mut client = dial(&dir);
    refused_with(
        &connect(&mut client, origin.port),
        "403 Forbidden",
        D::PolicyDenied,
    );
    counted_in(&proxies, ENV, D::PolicyDenied, 1);
    assert_eq!(
        resolver.queries(HOST),
        0,
        "resolved for a denied destination"
    );
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
    let report = authorised.finish().unwrap();
    assert_eq!(
        report.targets.as_slice()[0].dispositions.as_slice()[0].disposition,
        D::PolicyDenied
    );
    assert!(!report.targets.as_slice()[0].reached);
}

#[test]
fn an_address_outside_the_cell_is_refused_whole_and_one_inside_is_reached() {
    // Pieces: IPv4 in no range, IPv6 in no range, 127.0.0.0/8. The guard's
    // evidence exception lets the loopback origin through; policy's range
    // decides.
    for (cells, expected) in [
        ([true, true, false], None),
        ([false, false, true], Some(5usize)),
    ] {
        let origin = origin(5);
        let scratch = Scratch::new();
        let resolver = Arc::new(FixtureResolver::parse(&loopback()).unwrap());
        let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
        let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
        let dir = proxies
            .start(ENV, grant_of(&[(HOST, origin.port)]), ROOT)
            .unwrap();
        let egress = authorisation(
            &["127.0.0.0/8"],
            &[(HOST, origin.port, [&cells, &cells, &cells, &cells], None)],
        );
        let authorised = proxies
            .authorise(ENV, &invocation(3), egress.clone())
            .unwrap();
        let mut client = dial(&dir);
        let head = connect(&mut client, origin.port);
        match expected {
            None => {
                refused_with(&head, "403 Forbidden", D::PolicyAddressDenied);
                assert_eq!(origin.accepted.load(Ordering::SeqCst), 0);
            }
            Some(n) => {
                assert_eq!(head, "HTTP/1.1 200 Connection Established\r\n\r\n");
                client.write_all(&build::hello(HOST)).unwrap();
                let mut reply = vec![0u8; n];
                client.read_exact(&mut reply).unwrap();
                client.shutdown(std::net::Shutdown::Write).unwrap();
                counted_in(&proxies, ENV, D::Closed, 1);
            }
        }
        assert_eq!(resolver.queries(HOST), 1);
        let report = authorised.finish().unwrap();
        assert!(report.consistent_with(&egress));
        let target = &report.targets.as_slice()[0];
        assert_eq!(target.reached, expected.is_some());
        let address = &target.addresses.as_slice()[0];
        assert_eq!(address.address.as_str(), "127.0.0.1");
        assert_eq!(
            (address.allowed.get(), address.refused.get()),
            if expected.is_some() { (1, 0) } else { (0, 1) }
        );
    }
}

#[test]
fn a_destination_reached_is_decided_by_its_seen_cell() {
    // Novel: allowed. Seen: refused. The first tunnel reaches it: its first
    // byte makes the destination reached and exposes the root, and the
    // tunnel, held to the seen cell from then on, is shut before that byte
    // is forwarded. The next is decided as reached, and refused before
    // resolution.
    let origin = origin(3);
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(&loopback()).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let dir = proxies
        .start(ENV, grant_of(&[(HOST, origin.port)]), ROOT)
        .unwrap();
    let yes: &[bool] = &[true, true];
    let no: &[bool] = &[false, false];
    let egress = authorisation(&[], &[(HOST, origin.port, [yes, yes, no, no], None)]);
    let authorised = proxies.authorise(ENV, &invocation(4), egress).unwrap();
    let mut first = tunnel_to(&dir, HOST, origin.port);
    assert_eq!(drain(&mut first), b"");
    counted_in(&proxies, ENV, D::ExposureRevoked, 1);
    let mut second = dial(&dir);
    refused_with(
        &connect(&mut second, origin.port),
        "403 Forbidden",
        D::PolicyDenied,
    );
    assert_eq!(resolver.queries(HOST), 1);
    let report = authorised.finish().unwrap();
    assert!(report.exposed && report.targets.as_slice()[0].reached);
    assert_eq!(report.targets.as_slice()[0].bytes_downstream.get(), 0);
}

#[test]
fn a_tunnel_carries_back_no_more_than_its_cell_allows() {
    let origin = origin(10);
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(&loopback()).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let dir = proxies
        .start(ENV, grant_of(&[(HOST, origin.port)]), ROOT)
        .unwrap();
    let yes: &[bool] = &[true, true];
    let egress = authorisation(&[], &[(HOST, origin.port, [yes, yes, yes, yes], Some(3))]);
    let authorised = proxies.authorise(ENV, &invocation(5), egress).unwrap();
    let mut client = tunnel_to(&dir, HOST, origin.port);
    let got = drain(&mut client);
    assert_eq!(got, b"rrr");
    counted_in(&proxies, ENV, D::TunnelOutputLimit, 1);
    assert_eq!(proxies.counters(ENV).unwrap().bytes_downstream.get(), 3);
    let report = authorised.finish().unwrap();
    assert_eq!(report.targets.as_slice()[0].bytes_downstream.get(), 3);
}

#[test]
fn a_workloads_end_stops_its_tunnels_and_nothing_follows() {
    let (origin, word) = gated_origin(5);
    let env = env(&loopback(), grant(origin.port, 4, 1 << 20, 1 << 20));
    let mut client = tunnel_to(&env.dir, HOST, origin.port);
    received_something(&origin);
    let Env {
        proxies,
        dir,
        authorised,
        _scratch,
        ..
    } = env;
    let report = authorised.unwrap().finish().unwrap();
    // Its tunnel is shut at once, both ways: what the client sends after the
    // end never reaches the origin, and the origin's late reply never
    // reaches the client.
    counted_in(&proxies, ENV, D::WorkloadEnded, 1);
    let _ = client.write_all(b"after the end");
    std::thread::sleep(Duration::from_millis(200));
    let _ = word.send(());
    assert_eq!(drain(&mut client), b"");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        *origin.received.lock().unwrap(),
        build::hello(HOST),
        "nothing after the workload's end reached the origin"
    );
    let target = &report.targets.as_slice()[0];
    assert!(!target.reached && !report.exposed);
    assert_eq!(
        target.dispositions.as_slice()[0].disposition,
        D::WorkloadEnded
    );
    let mut after = dial(&dir);
    refused_with(
        &connect(&mut after, origin.port),
        "403 Forbidden",
        D::NotAuthorised,
    );
}

#[test]
fn exposure_revokes_what_it_no_longer_allows_on_the_whole_root_before_the_byte_arrives() {
    // Three environments: e1 and e2 on one workspace root, e3 on another.
    // Each holds a tunnel open to `other.test`, whose cells allow it while
    // the workspace is pristine and refuse it once exposed. When e1's
    // tunnel to `origin.test` receives its first byte, e2's tunnel -- same
    // root -- is shut before that byte is forwarded, and never receives
    // its origin's reply; e3's, on another root, is untouched by it -- and
    // shut, in turn, by the first byte its own origin sends, which exposes
    // its own root.
    let (exposer, open_exposer) = gated_origin(5);
    let (e2_origin, open_e2) = gated_origin(4);
    let (e3_origin, open_e3) = gated_origin(4);
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(&two_names()).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let yes: &[bool] = &[true, true];
    let no: &[bool] = &[false, false];
    let mut held = Vec::new();
    let mut dirs = Vec::new();
    for (index, (environment, root, other)) in [
        ("e1", ROOT, e2_origin.port),
        ("e2", ROOT, e2_origin.port),
        ("e3", (8, 8), e3_origin.port),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = proxies
            .start(
                environment,
                grant_of(&[(HOST, exposer.port), (OTHER, other)]),
                root,
            )
            .unwrap();
        let egress = authorisation(
            &[],
            &[
                (HOST, exposer.port, [yes, yes, yes, yes], None),
                (OTHER, other, [yes, no, yes, no], None),
            ],
        );
        let n = u8::try_from(10 + index).unwrap();
        held.push((
            egress.clone(),
            proxies
                .authorise(environment, &invocation(n), egress)
                .unwrap(),
        ));
        dirs.push(dir);
    }
    let mut e2_tunnel = tunnel_to(&dirs[1], OTHER, e2_origin.port);
    let mut e3_tunnel = tunnel_to(&dirs[2], OTHER, e3_origin.port);
    received_something(&e2_origin);
    received_something(&e3_origin);
    // e1 reaches an origin: the root is exposed.
    let mut e1_tunnel = tunnel_to(&dirs[0], HOST, exposer.port);
    received_something(&exposer);
    let _ = open_exposer.send(());
    let mut reply = [0u8; 5];
    e1_tunnel.read_exact(&mut reply).unwrap();
    counted_in(&proxies, "e2", D::ExposureRevoked, 1);
    // e2's origin answers now; nothing of it reaches e2's client.
    let _ = open_e2.send(());
    assert_eq!(drain(&mut e2_tunnel), b"");
    // e3, on another root, is not exposed by e1: a new tunnel there to
    // `other.test` is still decided pristine -- admitted, not refused.
    let mut fresh = dial(&dirs[2]);
    assert_eq!(
        connect_to(&mut fresh, OTHER, e3_origin.port),
        "HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    drop(fresh);
    counted_in(&proxies, "e3", D::ClientHelloMalformed, 1);
    assert_eq!(proxies.counters("e3").unwrap().count(D::ExposureRevoked), 0);
    // When e3's own origin answers, that byte exposes e3's root, whose
    // exposed cell refuses `other.test`: the tunnel is shut before the byte
    // reaches it.
    let _ = open_e3.send(());
    assert_eq!(drain(&mut e3_tunnel), b"");
    counted_in(&proxies, "e3", D::ExposureRevoked, 1);
    // On the exposed root a new tunnel to `other.test` is decided exposed:
    // refused before anything is resolved, in e1 and e2 alike.
    let before = resolver.queries(OTHER);
    for dir in &dirs[..2] {
        let mut client = dial(dir);
        refused_with(
            &connect_to(&mut client, OTHER, e2_origin.port),
            "403 Forbidden",
            D::PolicyDenied,
        );
    }
    assert_eq!(resolver.queries(OTHER), before);
    // A workload installed on the exposed root starts exposed, whatever the
    // authority said: e2's next workload is refused `other.test` too.
    let (egress_e2, authorised_e2) = held.remove(1);
    let report = authorised_e2.finish().unwrap();
    assert!(report.consistent_with(&egress_e2));
    assert!(!report.exposed);
    assert_eq!(
        report.targets.as_slice()[1].dispositions.as_slice()[0].disposition,
        D::ExposureRevoked
    );
    let next = proxies
        .authorise("e2", &invocation(20), egress_e2.clone())
        .unwrap();
    let mut client = dial(&dirs[1]);
    refused_with(
        &connect_to(&mut client, OTHER, e2_origin.port),
        "403 Forbidden",
        D::PolicyDenied,
    );
    drop(next);
    let (egress_e1, authorised_e1) = held.remove(0);
    let report = authorised_e1.finish().unwrap();
    assert!(report.exposed && report.consistent_with(&egress_e1));
    assert_eq!(report.targets.as_slice()[0].bytes_downstream.get(), 5);
}

#[test]
fn the_tunnel_whose_byte_exposes_the_root_is_held_to_its_seen_cell() {
    // ADR-0061 (EG-7, EG-8): the first byte a tunnel carries back is its
    // destination reached. That tunnel is then held to the destination's
    // seen-and-exposed cell -- under the shipped packs, the cell a tainted
    // run keeps for a destination it has reached -- and carries its reply.
    // Another tunnel already open, admitted while its destination was novel,
    // keeps that novelty, and is shut by the novel-and-exposed cell.
    let (reached, open_reached) = gated_origin(5);
    let (waiting, open_waiting) = gated_origin(4);
    let scratch = Scratch::new();
    let shared: Shared = Arc::new(FixtureResolver::parse(&two_names()).unwrap());
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let yes: &[bool] = &[true, true];
    let no: &[bool] = &[false, false];
    let dir = proxies
        .start(
            "e1",
            grant_of(&[(HOST, reached.port), (OTHER, waiting.port)]),
            ROOT,
        )
        .unwrap();
    // Novel: allowed pristine, refused exposed. Seen: allowed either way.
    let egress = authorisation(
        &[],
        &[
            (HOST, reached.port, [yes, no, yes, yes], None),
            (OTHER, waiting.port, [yes, no, yes, yes], None),
        ],
    );
    let authorised = proxies
        .authorise("e1", &invocation(30), egress.clone())
        .unwrap();
    let mut waiting_tunnel = tunnel_to(&dir, OTHER, waiting.port);
    received_something(&waiting);
    let mut tunnel = tunnel_to(&dir, HOST, reached.port);
    received_something(&reached);
    let _ = open_reached.send(());
    let mut reply = [0u8; 5];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"rrrrr");
    counted_in(&proxies, "e1", D::ExposureRevoked, 1);
    let _ = open_waiting.send(());
    assert_eq!(drain(&mut waiting_tunnel), b"");
    drop(tunnel);
    let report = authorised.finish().unwrap();
    assert!(report.exposed && report.consistent_with(&egress));
    let targets = report.targets.as_slice();
    assert!(targets[0].reached && !targets[1].reached);
    assert_eq!(targets[0].bytes_downstream.get(), 5);
    assert_eq!(targets[1].bytes_downstream.get(), 0);
}

#[test]
fn an_authorisation_is_refused_without_a_proxy_beyond_the_grant_or_twice() {
    use dwk_proto::brokerp::BrokerRefusal;
    let scratch = Scratch::new();
    let shared: Shared = Arc::new(FixtureResolver::parse(&loopback()).unwrap());
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits()).unwrap();
    let open = |pairs: &[(&str, u16)]| WorkloadEgress::uniform(pairs, true, false).unwrap();
    assert_eq!(
        proxies
            .authorise(ENV, &invocation(30), open(&[(HOST, 443)]))
            .err(),
        Some(BrokerRefusal::ProxyUnavailable)
    );
    proxies.start(ENV, grant_of(&[(HOST, 443)]), ROOT).unwrap();
    assert_eq!(
        proxies
            .authorise(ENV, &invocation(31), open(&[(HOST, 443), (OTHER, 443)]))
            .err(),
        Some(BrokerRefusal::EgressNotGranted)
    );
    assert_eq!(
        proxies
            .authorise(ENV, &invocation(32), open(&[(HOST, 8443)]))
            .err(),
        Some(BrokerRefusal::EgressNotGranted)
    );
    let first = proxies
        .authorise(ENV, &invocation(33), open(&[(HOST, 443)]))
        .unwrap();
    assert_eq!(
        proxies
            .authorise(ENV, &invocation(34), open(&[(HOST, 443)]))
            .err(),
        Some(BrokerRefusal::WorkloadInUse)
    );
    // Dropped unfinished -- its thread gone -- it is removed all the same.
    drop(first);
    assert!(
        proxies
            .authorise(ENV, &invocation(35), open(&[(HOST, 443)]))
            .is_ok()
    );
}
