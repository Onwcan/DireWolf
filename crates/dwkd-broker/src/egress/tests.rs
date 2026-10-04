//! The proxy end to end in-process (M5b, ADR-0048): a real [`Proxies`]
//! socket, real threads, a real TCP origin on loopback, and the evidence
//! resolver choosing what names resolve to. The test stands where the relay
//! does, connecting through the environment's directory; the OCI topology
//! around it is the sandbox egress evidence's (`tests/sandbox_egress.rs`).
//!
//! Every tunnel names `origin.test`, which the fixture resolves to the
//! loopback origin; `127.0.0.1` is the fixture's one exception, so the guard
//! is still the real guard for every other address.

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
    EgressByteBudget, EgressDisposition as D, EgressGrant, EgressHost, EgressPort, EgressTarget,
    EgressTargets, EgressTunnelLimit,
};
use dwk_sandbox_profile::{EGRESS_SOCKET_NAME, RELAY_UID};

use super::hello::build;
use super::proxy::{Proxies, relay_only_acl};
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

/// A proxy for one environment, `e1`, with this fixture.
struct Env {
    proxies: Proxies,
    dir: PathBuf,
    resolver: Arc<FixtureResolver>,
    _scratch: Scratch,
}

const ENV: &str = "e1";

fn env_with(fixture: &str, grant: EgressGrant, limits: Limits) -> Env {
    let scratch = Scratch::new();
    let resolver = Arc::new(FixtureResolver::parse(fixture).unwrap());
    let shared: Shared = Arc::<FixtureResolver>::clone(&resolver);
    let proxies = Proxies::new(scratch.0.join("egress"), own_uid(), shared, limits).unwrap();
    let dir = proxies.start(ENV, grant).unwrap();
    Env {
        proxies,
        dir,
        resolver,
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
    let dir = proxies.start(ENV, grant).unwrap();
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
        proxies.start("e1", grant(443, 1, 1, 1)).unwrap();
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
