//! The HTTPS client against real TLS origins in this process (M5c, ADR-0050
//! §§9, 16): `rustls` servers on loopback presenting certificates from a PKI
//! generated for this run (`tests/net_http/make-pki.sh`), each answering one
//! connection with scripted bytes. The client is the production one; only its
//! trust anchor (the evidence authority, as `--allow-evidence-trust` would
//! load it), its resolver's loopback exception and — for the deadline cases —
//! its deadlines are the test's.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::{EgressHost, EgressPort};
use dwk_proto::brokerp::http::{
    ExchangeDisposition, HopNumber, HopSpec, HttpCredential, HttpExchangeAuthorisation,
    HttpExchangeDone, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpLocation, HttpMethod,
    HttpResolveAuthorisation, HttpStatus, HttpTarget, NetAddress, NetAddresses, RequestHeaders,
    ResolveDisposition, ResponseLimit,
};
use dwk_proto::brokerp::{
    BrokerRefusal, ChannelNonce, Common, OutcomeResult, SecretHandle, SecretHeaderName,
    SecretHeaderPrefix,
};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::HexContent;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::{Client, Deadlines, tls};
use crate::egress::resolve::{FixtureResolver, Shared};

/// This run's PKI, made once.
fn pki() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("dw-net-pki-{}", std::process::id()));
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/net_http/make-pki.sh");
        let status = std::process::Command::new("bash")
            .arg(&script)
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("bash runs");
        assert!(status.success(), "the test PKI is made: needs openssl");
        dir
    })
}

fn evidence(case: &str, outcome: &str, layer: &str) {
    println!(
        "NET-EVIDENCE {{\"suite\":\"broker-http\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"layer\":\"{layer}\"}}"
    );
}

/// A server configuration presenting `name`'s certificate, offering `alpn`.
fn server(name: &str, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let dir = pki();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(dir.join(format!("{name}.pem")))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join(format!("{name}.key"))).unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// What an origin does once it has read a request.
enum Act {
    /// Write these bytes.
    Write(Vec<u8>),
    /// Wait.
    Sleep(Duration),
}

/// An origin on loopback: one connection, one TLS handshake with `config`,
/// one request read (its head, then `Content-Length` bytes of body), then the
/// script. The request's bytes come back on the channel.
fn origin(config: Arc<ServerConfig>, script: Vec<Act>) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let Ok(connection) = ServerConnection::new(config) else {
            return;
        };
        let mut stream = StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if let Ok(1) = stream.read(&mut byte) {
                request.push(byte[0]);
            } else {
                let _ = send.send(request);
                return;
            }
        }
        let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let length: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        if stream.read_exact(&mut body).is_ok() {
            request.extend_from_slice(&body);
        }
        let _ = send.send(request);
        for act in script {
            match act {
                Act::Write(bytes) => {
                    if stream.write_all(&bytes).is_err() || stream.flush().is_err() {
                        return;
                    }
                }
                Act::Sleep(d) => thread::sleep(d),
            }
        }
        stream.conn.send_close_notify();
        let _ = stream.flush();
    });
    (port, receive)
}

fn loopback() -> Address {
    Address::V4([127, 0, 0, 1])
}

/// A client trusting the evidence authority, resolving from a fixture that
/// excepts loopback, with `deadlines`.
fn client(fixture: &str, deadlines: Deadlines) -> Client {
    let resolver: Shared = Arc::new(FixtureResolver::parse(fixture).unwrap());
    let trust = tls::evidence(&pki().join("ca.pem")).unwrap();
    Client::new(resolver, trust, deadlines)
}

fn evidence_client() -> Client {
    client(
        "resolve origin.test 127.0.0.1\nallow 127.0.0.1\n",
        Deadlines::PRODUCTION,
    )
}

fn quick() -> Deadlines {
    Deadlines {
        resolve: Duration::from_millis(500),
        connect: Duration::from_millis(500),
        handshake: Duration::from_millis(800),
        head: Duration::from_millis(600),
        idle: Duration::from_millis(600),
        hop: Duration::from_secs(3),
    }
}

fn common() -> Common {
    Common::new(
        ChannelNonce::new("0123456789abcdef0123456789abcdef").unwrap(),
        InvocationId::parse("inv_01M24BB8G4E87TVJX9GX248ADD").unwrap(),
    )
}

struct Hop {
    method: HttpMethod,
    host: &'static str,
    port: u16,
    target: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: Option<Vec<u8>>,
    addresses: Vec<Address>,
    limit: u32,
    credential: Option<HttpCredential>,
}

impl Hop {
    fn get(port: u16) -> Self {
        Self {
            method: HttpMethod::Get,
            host: "origin.test",
            port,
            target: "/v1/items?page=2",
            headers: vec![("accept", "application/json")],
            body: None,
            addresses: vec![loopback()],
            limit: 1024,
            credential: None,
        }
    }

    fn authorisation(&self) -> HttpExchangeAuthorisation {
        let headers = self
            .headers
            .iter()
            .map(|(n, v)| HttpHeader {
                name: HttpHeaderName::new(*n).unwrap(),
                value: HttpHeaderValue::new(*v).unwrap(),
            })
            .collect();
        HttpExchangeAuthorisation::new(
            common(),
            HopSpec {
                hop: HopNumber::new(1).unwrap(),
                method: self.method,
                host: EgressHost::new(self.host).unwrap(),
                port: EgressPort::new(self.port).unwrap(),
                target: HttpTarget::new(self.target).unwrap(),
                headers: RequestHeaders::new(headers).unwrap(),
                body: self
                    .body
                    .as_deref()
                    .map(|b| HexContent::from_bytes(b).unwrap()),
                addresses: NetAddresses::new(
                    self.addresses
                        .iter()
                        .map(|a| NetAddress::from_address(*a))
                        .collect(),
                )
                .unwrap(),
                response_limit: ResponseLimit::new(self.limit).unwrap(),
                credential: self.credential.clone(),
            },
        )
    }
}

fn run(client: &Client, hop: &Hop, secret: Option<std::os::fd::OwnedFd>) -> OutcomeResult {
    let authorisation = hop.authorisation();
    dwk_proto::brokerp::Authorisation::HttpExchange(authorisation.clone())
        .encode_frame()
        .expect("the hop is a valid authorisation");
    client.exchange(
        &authorisation,
        secret,
        Instant::now() + Duration::from_secs(45),
    )
}

fn done(outcome: OutcomeResult) -> HttpExchangeDone {
    match outcome {
        OutcomeResult::Done(done) => done.http_exchange.expect("an exchange's answer"),
        other => panic!("expected done, got {other:?}"),
    }
}

fn refused(outcome: OutcomeResult) -> BrokerRefusal {
    match outcome {
        OutcomeResult::Refused(why) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn response(head: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = head.replace('\n', "\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn a_pinned_request_is_rendered_from_typed_fields_and_its_response_kept_whole() {
    let reply = response(
        "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 11\nSet-Cookie: s=1\nServer: x\nETag: \"v1\"\n\n",
        b"{\"ok\":true}",
    );
    let (port, request) = origin(server("origin", &[b"http/1.1"]), vec![Act::Write(reply)]);
    let outcome = done(run(&evidence_client(), &Hop::get(port), None));
    assert_eq!(outcome.disposition, ExchangeDisposition::Completed);
    assert_eq!(outcome.status.map(HttpStatus::get), Some(200));
    assert_eq!(outcome.body.to_bytes(), b"{\"ok\":true}");
    assert!(!outcome.truncated);
    let kept: Vec<(&str, &str)> = outcome
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert!(kept.contains(&("content-type", "application/json")));
    assert!(kept.contains(&("etag", "\"v1\"")));
    assert!(
        !kept
            .iter()
            .any(|(n, _)| *n == "set-cookie" || *n == "server")
    );
    assert_eq!(outcome.cookies_dropped.get(), 1);
    assert_eq!(outcome.headers_dropped.get(), 1);
    let sent = String::from_utf8(request.recv().unwrap()).unwrap();
    let mut lines = sent.split("\r\n");
    assert_eq!(lines.next(), Some("GET /v1/items?page=2 HTTP/1.1"));
    let headers: Vec<String> = lines.filter(|l| !l.is_empty()).map(str::to_owned).collect();
    assert_eq!(
        headers,
        vec![
            format!("host: origin.test:{port}"),
            format!("user-agent: DireWolf/{}", env!("CARGO_PKG_VERSION")),
            "accept-encoding: identity".to_owned(),
            "connection: close".to_owned(),
            "accept: application/json".to_owned(),
        ]
    );
    evidence("pinned-request-rendered", "completed", "broker");
}

#[test]
fn a_body_is_read_to_the_bound_plus_one_then_cut() {
    for (case, head, body) in [
        (
            "length",
            "HTTP/1.1 200 OK\nContent-Length: 4096\n\n",
            vec![b'a'; 4096],
        ),
        (
            "chunked",
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n",
            b"800\r\n"
                .iter()
                .copied()
                .chain(vec![b'a'; 2048])
                .chain(b"\r\n800\r\n".iter().copied())
                .chain(vec![b'a'; 2048])
                .chain(b"\r\n0\r\n\r\n".iter().copied())
                .collect(),
        ),
    ] {
        let (port, _) = origin(
            server("origin", &[b"http/1.1"]),
            vec![Act::Write(response(head, &body))],
        );
        let mut hop = Hop::get(port);
        hop.limit = 100;
        let outcome = done(run(&evidence_client(), &hop, None));
        assert_eq!(
            outcome.disposition,
            ExchangeDisposition::Completed,
            "{case}"
        );
        assert_eq!(outcome.body.byte_len(), 100, "{case}");
        assert!(outcome.truncated, "{case}");
    }
    evidence("body-past-bound-cut", "truncated", "broker");
}

#[test]
fn framing_the_client_cannot_trust_is_refused_not_guessed() {
    for (case, reply, expected) in [
        (
            "length-and-chunked",
            response(
                "HTTP/1.1 200 OK\nContent-Length: 3\nTransfer-Encoding: chunked\n\n",
                b"3\r\nabc\r\n0\r\n\r\n",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "two-lengths",
            response(
                "HTTP/1.1 200 OK\nContent-Length: 3\nContent-Length: 4\n\n",
                b"abcd",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "close-delimited",
            response("HTTP/1.1 200 OK\n\n", b"abc"),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "other-transfer-coding",
            response(
                "HTTP/1.1 200 OK\nTransfer-Encoding: gzip, chunked\n\n",
                b"0\r\n\r\n",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "switching-protocols",
            response(
                "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\n\n",
                b"",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "http-1-0",
            response("HTTP/1.0 200 OK\nContent-Length: 1\n\n", b"a"),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "bad-chunk-size",
            response(
                "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n",
                b"zz\r\nabc\r\n0\r\n\r\n",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "truncated-body",
            response("HTTP/1.1 200 OK\nContent-Length: 10\n\n", b"abc"),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "gzip",
            response(
                "HTTP/1.1 200 OK\nContent-Encoding: gzip\nContent-Length: 1\n\n",
                b"a",
            ),
            ExchangeDisposition::EncodingUnsupported,
        ),
        (
            "two-locations",
            response(
                "HTTP/1.1 302 Found\nLocation: /a\nLocation: /b\nContent-Length: 0\n\n",
                b"",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "header-bomb",
            response(
                &format!(
                    "HTTP/1.1 200 OK\n{}Content-Length: 0\n\n",
                    (0..101).fold(String::new(), |mut all, i| {
                        use std::fmt::Write as _;
                        let _ = writeln!(all, "X-H{i}: v");
                        all
                    })
                ),
                b"",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "head-past-64-kib",
            response(
                &format!(
                    "HTTP/1.1 200 OK\nX-Big: {}\nContent-Length: 0\n\n",
                    "a".repeat(70_000)
                ),
                b"",
            ),
            ExchangeDisposition::ResponseMalformed,
        ),
        (
            "status-past-599",
            response("HTTP/1.1 600 Nope\nContent-Length: 0\n\n", b""),
            ExchangeDisposition::ResponseMalformed,
        ),
    ] {
        let (port, _) = origin(server("origin", &[b"http/1.1"]), vec![Act::Write(reply)]);
        let outcome = done(run(&evidence_client(), &Hop::get(port), None));
        assert_eq!(outcome.disposition, expected, "{case}");
        assert!(
            outcome.body.byte_len() == 0,
            "{case}: nothing kept of a refused response"
        );
        evidence(case, expected.as_str(), "broker");
    }
}

#[test]
fn a_redirect_is_returned_raw_and_never_followed() {
    let (port, _) = origin(
        server("origin", &[b"http/1.1"]),
        vec![Act::Write(response(
            "HTTP/1.1 302 Found\nLocation: https://metadata.google.internal/\nContent-Length: 0\n\n",
            b"",
        ))],
    );
    let outcome = done(run(&evidence_client(), &Hop::get(port), None));
    assert_eq!(outcome.status.map(HttpStatus::get), Some(302));
    assert_eq!(
        outcome.location.as_ref().map(HttpLocation::as_str),
        Some("https://metadata.google.internal/")
    );
    assert!(
        outcome
            .headers
            .iter()
            .all(|h| h.name.as_str() != "location")
    );
    evidence("redirect-not-followed-by-broker", "returned", "broker");
}

#[test]
fn certificates_that_do_not_name_the_host_or_do_not_chain_are_refused() {
    for (case, name) in [
        ("wrong-name", "other"),
        ("expired", "expired"),
        ("untrusted-authority", "rogue-origin"),
        ("self-signed", "selfsigned"),
    ] {
        let (port, request) = origin(server(name, &[b"http/1.1"]), vec![]);
        let why = refused(run(&evidence_client(), &Hop::get(port), None));
        assert_eq!(why, BrokerRefusal::HttpTlsFailed, "{case}");
        // Nothing of the request reached the origin.
        assert!(
            request
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_default()
                .is_empty(),
            "{case}"
        );
        evidence(case, "HTTP_TLS_FAILED", "broker-tls");
    }
}

#[test]
fn a_server_that_speaks_only_http_2_is_refused() {
    let (port, _) = origin(server("origin", &[b"h2"]), vec![]);
    assert_eq!(
        refused(run(&evidence_client(), &Hop::get(port), None)),
        BrokerRefusal::HttpTlsFailed
    );
    evidence("http2-only-server", "HTTP_TLS_FAILED", "broker-tls");
}

#[test]
fn a_production_trust_store_does_not_know_the_evidence_authority() {
    let resolver: Shared = Arc::new(FixtureResolver::parse("allow 127.0.0.1\n").unwrap());
    let production = Client::new(resolver, tls::production().unwrap(), Deadlines::PRODUCTION);
    let (port, _) = origin(server("origin", &[b"http/1.1"]), vec![]);
    assert_eq!(
        refused(run(&production, &Hop::get(port), None)),
        BrokerRefusal::HttpTlsFailed
    );
    evidence(
        "evidence-ca-under-production-trust",
        "HTTP_TLS_FAILED",
        "broker-tls",
    );
}

#[test]
fn the_broker_rejudges_every_pinned_address_and_never_dials_a_blocked_one() {
    // No exception: loopback is blocked, whatever the authority sent.
    let strict = client("", Deadlines::PRODUCTION);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut hop = Hop::get(listener.local_addr().unwrap().port());
    assert_eq!(
        refused(run(&strict, &hop, None)),
        BrokerRefusal::HttpAddressBlocked
    );
    assert!(listener.accept().is_err(), "nothing was dialled");
    // A metadata name is refused by name, before anything.
    hop.host = "metadata.google.internal";
    assert_eq!(
        refused(run(&evidence_client(), &hop, None)),
        BrokerRefusal::HttpAddressBlocked
    );
    // Mixed: one allowed and one blocked address is refused whole.
    hop.host = "origin.test";
    hop.addresses = vec![Address::V4([151, 101, 0, 223]), Address::V4([10, 0, 0, 1])];
    assert_eq!(
        refused(run(&evidence_client(), &hop, None)),
        BrokerRefusal::HttpAddressBlocked
    );
    evidence(
        "broker-rejudges-pinned-addresses",
        "HTTP_ADDRESS_BLOCKED",
        "broker-guard",
    );
}

#[test]
fn deadlines_hold_for_a_silent_origin_a_slow_head_and_a_stalled_body() {
    // An address that never answers the handshake: the listener accepts and
    // says nothing.
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = silent.local_addr().unwrap().port();
    let started = Instant::now();
    let why = refused(run(
        &client("allow 127.0.0.1\n", quick()),
        &Hop::get(port),
        None,
    ));
    assert_eq!(why, BrokerRefusal::HttpTimeout);
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(silent);
    evidence("tls-handshake-timeout", "HTTP_TIMEOUT", "broker-deadline");

    for (case, script) in [
        (
            "slow-head",
            vec![
                Act::Write(b"HTTP/1.1 200 OK\r\n".to_vec()),
                Act::Sleep(Duration::from_secs(2)),
            ],
        ),
        (
            "stalled-body",
            vec![
                Act::Write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc".to_vec()),
                Act::Sleep(Duration::from_secs(2)),
            ],
        ),
    ] {
        let (port, _) = origin(server("origin", &[b"http/1.1"]), script);
        let started = Instant::now();
        let outcome = done(run(
            &client("allow 127.0.0.1\n", quick()),
            &Hop::get(port),
            None,
        ));
        assert_eq!(outcome.disposition, ExchangeDisposition::Timeout, "{case}");
        assert!(started.elapsed() < Duration::from_secs(3), "{case}");
        evidence(case, "TIMEOUT", "broker-deadline");
    }
}

#[test]
fn a_body_is_sent_only_with_a_method_that_carries_one_and_with_its_length() {
    let (port, request) = origin(
        server("origin", &[b"http/1.1"]),
        vec![Act::Write(response(
            "HTTP/1.1 201 Created\nContent-Length: 0\n\n",
            b"",
        ))],
    );
    let mut hop = Hop::get(port);
    hop.method = HttpMethod::Post;
    hop.headers = vec![("content-type", "application/json")];
    hop.body = Some(b"{\"a\":1}".to_vec());
    let outcome = done(run(&evidence_client(), &hop, None));
    assert_eq!(outcome.status.map(HttpStatus::get), Some(201));
    let sent = String::from_utf8(request.recv().unwrap()).unwrap();
    assert!(sent.starts_with("POST /v1/items?page=2 HTTP/1.1\r\n"));
    assert!(sent.contains("\r\ncontent-length: 7\r\n"));
    assert!(sent.ends_with("\r\n\r\n{\"a\":1}"));
    assert!(!sent.contains("transfer-encoding"));
}

/// A pipe holding `value`, its writer closed: what the authority hands over.
fn pipe_with(value: &[u8]) -> std::os::fd::OwnedFd {
    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(value).unwrap();
    drop(writer);
    std::os::fd::OwnedFd::from(reader)
}

fn credential() -> HttpCredential {
    HttpCredential {
        handle: SecretHandle::new("api-token").unwrap(),
        header_name: SecretHeaderName::new("Authorization").unwrap(),
        header_prefix: Some(SecretHeaderPrefix::new("Bearer ").unwrap()),
    }
}

/// Whether `haystack` holds any 8-byte window of `value`.
fn holds_a_window_of(haystack: &[u8], value: &[u8]) -> bool {
    value
        .windows(8)
        .any(|w| haystack.windows(w.len()).any(|h| h == w))
}

/// D11 (ADR-0050 §§8, 20): the broker that put the credential on the wire
/// takes it out of what comes back, before anything of the response is
/// copied into the answer -- and counts it, for the authority's audit.
#[test]
fn an_echoed_credential_is_redacted_or_dropped_before_the_answer_holds_it() {
    const VALUE: &[u8] = b"t0k3n-v4lue-0123456789";
    let echo = |script: Vec<Act>, limit: u32, with_credential: bool| {
        let (port, _) = origin(server("origin", &[b"http/1.1"]), script);
        let mut hop = Hop::get(port);
        hop.limit = limit;
        let secret = with_credential.then(|| {
            hop.credential = Some(credential());
            pipe_with(VALUE)
        });
        done(run(&evidence_client(), &hop, secret))
    };
    let names = |done: &HttpExchangeDone| -> Vec<String> {
        done.headers
            .iter()
            .map(|h| h.name.as_str().to_owned())
            .collect()
    };
    // The body, the value split across two writes: replaced, counted.
    let mut body = b"x Bearer ".to_vec();
    body.extend_from_slice(VALUE);
    body.extend_from_slice(b" y");
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let mut first = head.into_bytes();
    first.extend_from_slice(&body[..14]);
    let script = || {
        vec![
            Act::Write(first.clone()),
            Act::Sleep(Duration::from_millis(50)),
            Act::Write(body[14..].to_vec()),
        ]
    };
    let got = echo(script(), 1024, true);
    assert_eq!(got.disposition, ExchangeDisposition::Completed);
    assert_eq!(got.body.to_bytes(), b"x Bearer [redacted:api-token] y");
    assert_eq!(got.credential_echoes.get(), 1);
    assert!(!got.truncated);
    evidence(
        "echo-body-redacted-before-encoding",
        "placeholder-counted",
        "broker-redaction",
    );
    // A hop without the credential: the broker knows no value to take out;
    // the authority's redaction is the return path's.
    let got = echo(script(), 1024, false);
    assert_eq!(got.body.to_bytes(), body);
    assert_eq!(got.credential_echoes.get(), 0);
    // A header holding it -- kept, off the keep-list, or a `Location` --
    // dropped whole, never copied; each counted.
    let value = std::str::from_utf8(VALUE).unwrap();
    for (case, extra, status) in [
        ("kept", format!("ETag: \"{value}\"\r\n"), "200 OK"),
        ("dropped", format!("X-Echo: Bearer {value}\r\n"), "200 OK"),
        (
            "location",
            format!("Location: /next?t={value}\r\n"),
            "302 Found",
        ),
    ] {
        let reply = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 2\r\n\r\nok");
        let got = echo(vec![Act::Write(reply.into_bytes())], 1024, true);
        assert_eq!(got.disposition, ExchangeDisposition::Completed, "{case}");
        assert_eq!(got.credential_echoes.get(), 1, "{case}");
        assert!(got.location.is_none(), "{case}");
        assert!(!names(&got).contains(&"etag".to_owned()), "{case}");
        for header in &got.headers {
            assert!(
                !holds_a_window_of(header.value.as_str().as_bytes(), VALUE),
                "{case}"
            );
        }
    }
    evidence(
        "echo-header-dropped-whole",
        "dropped-counted",
        "broker-redaction",
    );
    // Straddling the bound: read whole past it, replaced, and only then cut.
    let mut long = vec![b'a'; 54];
    long.extend_from_slice(VALUE);
    long.extend_from_slice(&[b'b'; 50]);
    let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", long.len());
    let mut bytes = reply.into_bytes();
    bytes.extend_from_slice(&long);
    let got = echo(vec![Act::Write(bytes)], 64, true);
    let returned = got.body.to_bytes();
    assert_eq!(returned.len(), 64);
    assert!(got.truncated);
    assert!(!holds_a_window_of(&returned, VALUE));
    assert_eq!(&returned[54..], b"[redacted:");
    assert_eq!(got.credential_echoes.get(), 1);
    evidence(
        "echo-straddling-the-bound",
        "redacted-then-cut",
        "broker-redaction",
    );
    // A response that broke off: its status for the record, no header, no
    // `Location`; the echo in its head still counted.
    let reply = format!(
        "HTTP/1.1 302 Found\r\nLocation: /x\r\nETag: \"{value}\"\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
    );
    let got = echo(vec![Act::Write(reply.into_bytes())], 1024, true);
    assert_eq!(got.disposition, ExchangeDisposition::ResponseMalformed);
    assert!(got.headers.is_empty() && got.location.is_none());
    assert_eq!(got.credential_echoes.get(), 1);
    evidence(
        "echo-in-a-broken-response",
        "no-header-crosses-counted",
        "broker-redaction",
    );
}

#[test]
fn a_credential_is_composed_once_into_the_request_it_was_authorised_for() {
    let (port, request) = origin(
        server("origin", &[b"http/1.1"]),
        vec![Act::Write(response("HTTP/1.1 204 No Content\n\n", b""))],
    );
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    let outcome = done(run(
        &evidence_client(),
        &hop,
        Some(pipe_with(b"t0k3n-value")),
    ));
    assert_eq!(outcome.status.map(HttpStatus::get), Some(204));
    let sent = String::from_utf8(request.recv().unwrap()).unwrap();
    assert_eq!(
        sent.matches("authorization: Bearer t0k3n-value\r\n")
            .count(),
        1,
        "{sent}"
    );
    evidence("credential-composed-in-broker", "injected", "broker-render");
}

#[test]
fn a_credential_that_cannot_be_a_header_is_refused_before_anything_is_dialled() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut hop = Hop::get(listener.local_addr().unwrap().port());
    hop.credential = Some(credential());
    for (case, value, expected) in [
        (
            "crlf",
            &b"a\r\nhost: evil"[..],
            BrokerRefusal::SecretUnsafeBytes,
        ),
        ("nul", &b"a\0b"[..], BrokerRefusal::SecretUnsafeBytes),
        ("control", &b"a\x07b"[..], BrokerRefusal::SecretUnsafeBytes),
        ("empty", &b""[..], BrokerRefusal::SecretEmpty),
    ] {
        let why = refused(run(&evidence_client(), &hop, Some(pipe_with(value))));
        assert_eq!(why, expected, "{case}");
    }
    // A credential exchange without its descriptor, or a plain exchange with
    // one, is not this exchange.
    assert_eq!(
        refused(run(&evidence_client(), &hop, None)),
        BrokerRefusal::DescriptorCount
    );
    assert!(listener.accept().is_err(), "nothing was dialled");
    evidence(
        "credential-header-injection-refused",
        "SECRET_UNSAFE_BYTES",
        "broker-render",
    );
}

#[test]
fn a_resolution_is_judged_whole_and_pinned() {
    let fixture = "resolve public.test 151.101.0.223,2a04:4e42::223\n\
                   resolve mixed.test 151.101.0.223,10.0.0.1\n\
                   resolve private.test 10.0.0.1\n\
                   resolve rebind.test 151.101.0.223;127.0.0.1\n\
                   resolve gone.test fail\n\
                   resolve slow.test timeout\n";
    let client = client(fixture, quick());
    let ask = |host: &str| {
        let authorisation = HttpResolveAuthorisation::new(common(), EgressHost::new(host).unwrap());
        match client.resolve(&authorisation) {
            OutcomeResult::Done(done) => done.http_resolve.unwrap(),
            other => panic!("{other:?}"),
        }
    };
    let public = ask("public.test");
    assert_eq!(public.disposition, ResolveDisposition::Resolved);
    let pinned: Vec<Address> = public
        .addresses
        .iter()
        .map(NetAddress::to_address)
        .collect();
    assert_eq!(pinned.len(), 2);
    assert_eq!(pinned[0], Address::V4([151, 101, 0, 223]));
    for (host, disposition) in [
        ("mixed.test", ResolveDisposition::AddressMixed),
        ("private.test", ResolveDisposition::AddressBlocked),
        ("gone.test", ResolveDisposition::ResolutionFailed),
        ("slow.test", ResolveDisposition::ResolutionTimeout),
        ("metadata.google.internal", ResolveDisposition::NameBlocked),
    ] {
        let found = ask(host);
        assert_eq!(found.disposition, disposition, "{host}");
        assert!(found.addresses.is_empty(), "{host}");
    }
    // A rebinding name: allowed once, refused the next time it is asked.
    assert_eq!(ask("rebind.test").disposition, ResolveDisposition::Resolved);
    assert_eq!(
        ask("rebind.test").disposition,
        ResolveDisposition::AddressBlocked
    );
    evidence("resolution-judged-whole", "pinned", "broker-guard");
}

/// A small deterministic generator: the mutation campaign below replays
/// exactly from its seed.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
    }
}

/// The response's head parser, DireWolf's framing judgement and the body
/// decoder under mutation, without a socket (D2): 20 000 responses built from
/// well-formed templates -- chunk extensions, trailers and informational
/// responses among them -- by flipping, inserting, dropping, repeating and
/// cutting bytes, each fed whole to `ureq-proto` as the client feeds it. None
/// panics; every status that parses is in 100 to 599; a decoded body never
/// outgrows its input. Fixed seed: a failure replays exactly.
#[test]
fn the_head_parser_framing_and_body_decoder_never_panic_on_mutated_responses() {
    use ureq_proto::client::{Call, RecvResponseResult, SendRequestResult};
    use ureq_proto::http::{Method, Request, Version};
    const SEED: u64 = 0x0D2_5EED;
    const TEMPLATES: [&[u8]; 6] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        b"HTTP/1.1 304 Not Modified\r\nETag: \"a\"\r\n\r\n",
    ];
    const TOKENS: [&[u8]; 12] = [
        b"\r\n",
        b"\n",
        b":",
        b"Content-Length: ",
        b"Transfer-Encoding: chunked\r\n",
        b"0\r\n\r\n",
        b";",
        b" ",
        b"\x00",
        b"ffffffffffffffff",
        b"HTTP/1.1 101 Switching Protocols\r\n",
        b"Content-Encoding: gzip\r\n",
    ];
    let fresh = || {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .version(Version::HTTP_11)
            .header("host", "origin.test")
            .header("connection", "close")
            .body(())
            .unwrap();
        let mut call = Call::new(request).unwrap().proceed();
        let mut out = vec![0u8; 4096];
        while !call.can_proceed() {
            call.write(&mut out).unwrap();
        }
        match call.proceed().unwrap() {
            Some(SendRequestResult::RecvResponse(call)) => call,
            _ => panic!("a request without a body awaits its response"),
        }
    };
    let mut rng = Xorshift(SEED | 1);
    let (mut heads, mut bodies) = (0u32, 0u32);
    for _ in 0..20_000 {
        let mut bytes = TEMPLATES[rng.below(TEMPLATES.len())].to_vec();
        for _ in 0..=rng.below(4) {
            match rng.below(5) {
                0 if !bytes.is_empty() => {
                    let i = rng.below(bytes.len());
                    bytes[i] ^= 1 << rng.below(8);
                }
                1 => {
                    let token = TOKENS[rng.below(TOKENS.len())];
                    let at = rng.below(bytes.len() + 1);
                    bytes.splice(at..at, token.iter().copied());
                }
                2 if !bytes.is_empty() => {
                    let start = rng.below(bytes.len());
                    let end = start + rng.below(bytes.len() - start + 1);
                    bytes.drain(start..end);
                }
                3 if !bytes.is_empty() => {
                    let start = rng.below(bytes.len());
                    let end = start + rng.below((bytes.len() - start).min(32) + 1);
                    let copy = bytes[start..end].to_vec();
                    let at = rng.below(bytes.len() + 1);
                    bytes.splice(at..at, copy);
                }
                _ => bytes.truncate(rng.below(bytes.len() + 1)),
            }
        }
        let mut call = fresh();
        let mut offset = 0usize;
        // Informational responses are consumed, as the client does.
        let response = loop {
            match call.try_response(&bytes[offset..], false) {
                Ok((used, Some(response))) => {
                    offset += used;
                    break Some(response);
                }
                Ok((used, None)) if used > 0 => offset += used,
                _ => break None,
            }
        };
        let Some(response) = response else {
            continue;
        };
        heads += 1;
        let status = response.status().as_u16();
        assert!((100..=999).contains(&status), "seed {SEED:#x}");
        let judged = super::framing(response.headers(), HttpMethod::Get, status);
        if judged.is_err() || !(200..=599).contains(&status) {
            continue;
        }
        if let Some(RecvResponseResult::RecvBody(mut body)) = call.proceed() {
            bodies += 1;
            let mut out = vec![0u8; 512];
            let (mut read, mut produced) = (offset, 0usize);
            while read < bytes.len() && produced < out.len() {
                let Ok((used, made)) = body.read(&bytes[read..], &mut out[produced..]) else {
                    break;
                };
                if used == 0 && made == 0 {
                    break;
                }
                read += used;
                produced += made;
                assert!(produced <= bytes.len(), "seed {SEED:#x}");
                if body.can_proceed() {
                    break;
                }
            }
        }
    }
    assert!(
        heads > 1_000 && bodies > 100,
        "the campaign reached the parser: {heads} {bodies}"
    );
    evidence(
        "head-parser-mutation",
        "20000-mutants-no-panic",
        "broker-fuzz",
    );
}

/// The response parser under mutation (ADR-0050 §16): responses from a real
/// TLS origin, built from well-formed templates by flipping, inserting,
/// dropping, repeating and cutting bytes. Whatever arrives, the client never
/// panics, returns no more body than its bound, keeps only the keep-list's
/// headers, and never a status outside 100 to 599 -- or refuses. The seed is
/// fixed, so a failure replays exactly; the client module reads no
/// environment, its tests included (TX046).
#[test]
fn a_mutated_response_never_panics_and_never_exceeds_its_bounds() {
    const SEED: u64 = 0x5EED_4E77;
    const TEMPLATES: [&[u8]; 4] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nETag: \"a\"\r\n\r\n",
    ];
    const TOKENS: [&[u8]; 10] = [
        b"\r\n",
        b":",
        b"Content-Length: ",
        b"Transfer-Encoding: chunked\r\n",
        b"0\r\n\r\n",
        b" ",
        b"\x00",
        b"ffffffff",
        b"Set-Cookie: a=1\r\n",
        b"Content-Encoding: gzip\r\n",
    ];
    let seed = SEED;
    let mut rng = Xorshift(seed | 1);
    let client = client("allow 127.0.0.1\n", quick());
    let config = server("origin", &[b"http/1.1"]);
    let (mut done, mut refused) = (0u32, 0u32);
    for _ in 0..120 {
        let mut bytes = TEMPLATES[rng.below(TEMPLATES.len())].to_vec();
        for _ in 0..=rng.below(3) {
            match rng.below(5) {
                0 if !bytes.is_empty() => {
                    let i = rng.below(bytes.len());
                    bytes[i] ^= 1 << rng.below(8);
                }
                1 => {
                    let token = TOKENS[rng.below(TOKENS.len())];
                    let at = rng.below(bytes.len() + 1);
                    bytes.splice(at..at, token.iter().copied());
                }
                2 if !bytes.is_empty() => {
                    let start = rng.below(bytes.len());
                    let end = start + rng.below(bytes.len() - start + 1);
                    bytes.drain(start..end);
                }
                3 if !bytes.is_empty() => {
                    let start = rng.below(bytes.len());
                    let end = start + rng.below((bytes.len() - start).min(32) + 1);
                    let copy = bytes[start..end].to_vec();
                    let at = rng.below(bytes.len() + 1);
                    bytes.splice(at..at, copy);
                }
                _ => bytes.truncate(rng.below(bytes.len() + 1)),
            }
        }
        let (port, _) = origin(Arc::clone(&config), vec![Act::Write(bytes)]);
        match run(&client, &Hop::get(port), None) {
            OutcomeResult::Done(answer) => {
                let exchange = answer.http_exchange.expect("an exchange's answer");
                assert!(exchange.body.byte_len() <= 1024, "seed {seed}");
                assert!(
                    exchange.headers.iter().all(|h| {
                        let name = h.name.as_str();
                        name != "location" && dwk_proto::wire::http::response_header_kept(name)
                    }),
                    "seed {seed}"
                );
                assert!(
                    exchange
                        .status
                        .is_none_or(|s| (100..=599).contains(&s.get())),
                    "seed {seed}"
                );
                done += 1;
            }
            OutcomeResult::Refused(_) => refused += 1,
            OutcomeResult::Indeterminate(why) => panic!("seed {seed}: {why:?}"),
        }
    }
    assert!(done > 0 && refused + done == 120, "seed {seed}");
    evidence(
        "response-parser-mutation",
        "120-mutants-bounded",
        "broker-fuzz",
    );
}
