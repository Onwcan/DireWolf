//! `net.http`'s HTTPS client (M5c, [ADR-0050] §§6, 9): the broker performs
//! each hop the authority authorised — **exactly that request, to exactly the
//! addresses the guard pinned** — and decides nothing.
//!
//! | step | what is checked | refusal, nothing sent |
//! |---|---|---|
//! | resolve (`http_resolve`) | the one resolver, once, its deadline; the whole answer judged by the shared guard | — (a disposition, for the authority to judge again) |
//! | re-judge (`http_exchange`) | the host is not a metadata name; every pinned address passes the shared guard | `HTTP_ADDRESS_BLOCKED` |
//! | credential | one closed pipe, 1 to 32 KiB, no byte a header cannot carry ([`render`]) | `SECRET_*` |
//! | render | the request from typed fields: `Host`, a fixed `User-Agent`, `Accept-Encoding: identity`, `Connection: close`, `Content-Length` for a method that may carry a body, the caller's judged headers, the credential last | `HTTP_REQUEST_INVALID` |
//! | dial | the pinned addresses only, in order, sharing one deadline ([`connect`]) | `HTTP_CONNECT_FAILED`, `HTTP_TIMEOUT` |
//! | handshake | `rustls`, verification always on, the host as server name and certificate name, `http/1.1` or no ALPN ([`tls`]) | `HTTP_TLS_FAILED`, `HTTP_TIMEOUT` |
//!
//! From the first byte of the request on, the exchange is `done` with a
//! disposition — `COMPLETED`, `RESPONSE_MALFORMED`, `ENCODING_UNSUPPORTED` or
//! `TIMEOUT` — because the origin may have acted on what it received:
//!
//! * the response head: within 64 KiB and 100 headers, HTTP/1.1, a status
//!   from 100 to 599 and never `101`; framed by exactly one `Content-Length`
//!   or exactly `Transfer-Encoding: chunked`, never both and never neither
//!   when a body may follow (a body delimited by the connection's close is
//!   refused: it cannot be told from a cut one); no `Content-Encoding` but
//!   `identity` (D7);
//! * the body: read to the bound **plus one byte** — so a longer body is
//!   known to be longer — then cut and marked `truncated`; every read under
//!   the idle deadline, the whole hop under its own;
//! * the headers: only the keep-list's come back (`dwk_proto::wire::http`),
//!   each once, each in its one spelling; `location` is returned apart, raw,
//!   for the authority to judge; `set-cookie` and everything else are counted
//!   and dropped.
//!
//! **The broker never follows a redirect, never retries, never re-resolves,
//! never pools, never reads a proxy setting and never decodes a body.** A 3xx
//! is a response like any other; the authority decides what happens next.
//!
//! Every buffer that can hold request plaintext — the rendered head and body,
//! and with them the credential — and every buffer response plaintext is read
//! into is `Zeroizing`, sized once so it never reallocates. `rustls` encrypts
//! a record in place once the handshake is complete, which it is before the
//! first byte of the request is written.
//!
//! **An echoed credential stops here (D11).** A hop that carries mode A's
//! credential keeps its value as a [`Needle`] until the exchange ends, and the
//! response is redacted of it **before any byte of the response is copied
//! into the answer**: every header holding it is counted, a kept header or
//! `Location` holding it is dropped whole, and the body — read past the bound
//! by the value's length, so an echo straddling the bound is seen whole — is
//! redacted into a `Zeroizing` buffer and only then cut to the bound. The
//! count crosses as `credential_echoes`, for the authority's audit; a response
//! that did not complete carries no header and no `Location` at all. What
//! `rustls` and the `http` crate hold of the response in their own
//! allocations, freed without being zeroed, is the measured residual of
//! ADR-0050 §20.
//!
//! [ADR-0050]: ../../../../docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md

mod connect;
mod render;
pub(crate) mod tls;

#[cfg(test)]
mod tests;

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::EgressDisposition;
use dwk_proto::brokerp::http::{
    self as wire, ExchangeDisposition, HeaderCount, HttpExchangeAuthorisation, HttpExchangeDone,
    HttpHeader, HttpHeaderName, HttpLocation, HttpMethod, HttpResolveAuthorisation,
    HttpResolveDone, HttpStatus, NetAddress, NetAddresses, ResolveDisposition, ResponseHeaders,
};
use dwk_proto::brokerp::{BrokerDone, BrokerRefusal, OutcomeResult};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::http as rules;
use dwk_proto::wire::scalar::{ByteCount, HexContent};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use ureq_proto::client::state::{RecvBody, RecvResponse};
use ureq_proto::client::{Call, RecvResponseResult, SendRequestResult};
use ureq_proto::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Version};
use zeroize::Zeroizing;

use crate::egress::{guard, resolve};
use crate::secret::{Needle, Redactor};

/// The fixed `User-Agent`: the product and its version, nothing about the
/// host, the run or the caller.
const USER_AGENT: &str = concat!("DireWolf/", env!("CARGO_PKG_VERSION"));

/// How many plaintext bytes one read asks for.
const READ_CHUNK: usize = 16 * 1024;

/// The rendering buffer: the longest header line it must hold is a
/// credential's — a 64-byte name, a 64-byte prefix and a 32 KiB value — and
/// the caller's are at most 4 KiB.
const RENDER_BUFFER: usize = 40 * 1024;

/// How many wire bytes a body may take per body byte returned, at most: a
/// chunked body of one-byte chunks costs six. Past this the response is
/// malformed (trailers that never end, chunk extensions that never end).
const BODY_FRAMING_FACTOR: usize = 8;

/// How long each step of a hop may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deadlines {
    /// One resolution.
    pub(crate) resolve: Duration,
    /// Connecting to the pinned addresses, together.
    pub(crate) connect: Duration,
    /// The TLS handshake.
    pub(crate) handshake: Duration,
    /// The response head, after the request was sent.
    pub(crate) head: Duration,
    /// The body going without a byte.
    pub(crate) idle: Duration,
    /// The whole hop.
    pub(crate) hop: Duration,
}

impl Deadlines {
    /// The broker's own: shared with the authority through
    /// `dwk_proto::brokerp::http`, never set by an authorisation.
    pub(crate) const PRODUCTION: Self = Self {
        resolve: Duration::from_secs(wire::RESOLVE_DEADLINE_SECONDS),
        connect: Duration::from_secs(wire::CONNECT_DEADLINE_SECONDS),
        handshake: Duration::from_secs(wire::HANDSHAKE_DEADLINE_SECONDS),
        head: Duration::from_secs(wire::RESPONSE_HEAD_DEADLINE_SECONDS),
        idle: Duration::from_secs(wire::BODY_IDLE_DEADLINE_SECONDS),
        hop: Duration::from_secs(wire::HOP_DEADLINE_SECONDS),
    };
}

/// The client: the broker's one resolver, its one trust configuration and
/// its deadlines.
#[derive(Debug)]
pub(crate) struct Client {
    resolver: resolve::Shared,
    tls: Arc<ClientConfig>,
    deadlines: Deadlines,
}

/// The octets as a standard-library address, for the one place that dials.
fn ip(address: Address) -> IpAddr {
    match address {
        Address::V4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
        Address::V6(octets) => IpAddr::V6(Ipv6Addr::from(octets)),
    }
}

/// Why a hop ended where it did, before it is an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Before any byte of the request was sent.
    Refused(BrokerRefusal),
    /// After: how.
    Sent(ExchangeDisposition),
}

/// Whether an I/O error is a deadline.
fn timed_out(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Set both socket timeouts to what is left before `until`.
fn arm(socket: &TcpStream, until: Instant) -> Result<(), ()> {
    let now = Instant::now();
    if now >= until {
        return Err(());
    }
    let left = (until - now).max(Duration::from_millis(1));
    socket.set_read_timeout(Some(left)).map_err(|_| ())?;
    socket.set_write_timeout(Some(left)).map_err(|_| ())
}

impl Client {
    /// A client over `resolver`, trusting `tls`'s roots.
    pub(crate) fn new(
        resolver: resolve::Shared,
        tls: Arc<ClientConfig>,
        deadlines: Deadlines,
    ) -> Self {
        Self {
            resolver,
            tls,
            deadlines,
        }
    }

    /// `broker.http_resolve`: resolve the host once and judge the whole
    /// answer. Always `done`: a blocked or failed answer is a disposition the
    /// authority records, not a refusal of the authorisation.
    pub(crate) fn resolve(&self, authorisation: &HttpResolveAuthorisation) -> OutcomeResult {
        let host = authorisation.host.as_str();
        let (disposition, allowed) = if guard::name_blocked(host) {
            (ResolveDisposition::NameBlocked, Vec::new())
        } else {
            match self.resolver.resolve(host, self.deadlines.resolve) {
                Err(EgressDisposition::ResolutionTimeout) => {
                    (ResolveDisposition::ResolutionTimeout, Vec::new())
                }
                Err(_) => (ResolveDisposition::ResolutionFailed, Vec::new()),
                Ok(answer) => match guard::judge(&answer, self.resolver.exceptions()) {
                    Ok(allowed) => (ResolveDisposition::Resolved, allowed),
                    Err(EgressDisposition::AddressBlocked) => {
                        (ResolveDisposition::AddressBlocked, Vec::new())
                    }
                    Err(EgressDisposition::AddressMixed) => {
                        (ResolveDisposition::AddressMixed, Vec::new())
                    }
                    Err(_) => (ResolveDisposition::ResolutionFailed, Vec::new()),
                },
            }
        };
        let addresses: Vec<NetAddress> = allowed
            .into_iter()
            .take(wire::MAX_PINNED_ADDRESSES)
            .map(|address| NetAddress::from_address(guard::address(address)))
            .collect();
        let Some(addresses) = NetAddresses::new(addresses) else {
            return OutcomeResult::Refused(BrokerRefusal::HttpRequestInvalid);
        };
        OutcomeResult::done(BrokerDone::http_resolve(HttpResolveDone {
            disposition,
            addresses,
        }))
    }

    /// `broker.http_exchange` and `broker.http_credential_exchange`: perform
    /// one hop, before `until` (the private channel's own bound).
    pub(crate) fn exchange(
        &self,
        authorisation: &HttpExchangeAuthorisation,
        secret: Option<OwnedFd>,
        until: Instant,
    ) -> OutcomeResult {
        let started = Instant::now();
        // The hop's bound, and never past the channel's: the outcome must
        // still be sent.
        let hop_until = (started + self.deadlines.hop).min(until);
        match self.perform(authorisation, secret, started, hop_until) {
            Ok(done) => OutcomeResult::done(BrokerDone::http_exchange(done)),
            Err(refusal) => OutcomeResult::Refused(refusal),
        }
    }

    fn perform(
        &self,
        authorisation: &HttpExchangeAuthorisation,
        secret: Option<OwnedFd>,
        started: Instant,
        hop_until: Instant,
    ) -> Result<HttpExchangeDone, BrokerRefusal> {
        let host = authorisation.host.as_str();
        // 1. The broker's own judgement of where this may go: the same guard,
        // the same table, whatever the authority said.
        if guard::name_blocked(host) {
            return Err(BrokerRefusal::HttpAddressBlocked);
        }
        let pinned: Vec<IpAddr> = authorisation
            .addresses
            .iter()
            .map(|address| ip(address.to_address()))
            .collect();
        if guard::judge(&pinned, self.resolver.exceptions()).is_err() {
            return Err(BrokerRefusal::HttpAddressBlocked);
        }
        // 2. The credential, read once, composed once; the needle its
        // response is redacted of.
        let (credential, needle) = match (&authorisation.credential, secret) {
            (Some(credential), Some(fd)) => {
                let rendered = render::credential_header(credential, &fd)?;
                (Some((rendered.name, rendered.value)), Some(rendered.needle))
            }
            (None, None) => (None, None),
            _ => return Err(BrokerRefusal::DescriptorCount),
        };
        // 3. The request, rendered from typed fields. Nothing is dialled yet.
        let request = request(authorisation, credential)?;
        let body = Zeroizing::new(
            authorisation
                .body
                .as_ref()
                .map_or_else(Vec::new, HexContent::to_bytes),
        );
        let limit = usize::try_from(authorisation.response_limit.get()).unwrap_or(0);
        // 4. The pinned addresses, and the handshake.
        let connect_until = (started + self.deadlines.connect).min(hop_until);
        let Some(socket) = connect::dial(&pinned, authorisation.port.get(), connect_until) else {
            return Err(if Instant::now() >= hop_until {
                BrokerRefusal::HttpTimeout
            } else {
                BrokerRefusal::HttpConnectFailed
            });
        };
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|_| BrokerRefusal::HttpRequestInvalid)?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| BrokerRefusal::HttpTlsFailed)?;
        let mut stream = StreamOwned::new(connection, socket);
        let handshake_until = (Instant::now() + self.deadlines.handshake).min(hop_until);
        handshake(&mut stream, handshake_until)?;
        crate::crash::point("http_after_handshake");
        // 5. The request, the response.
        let mut conversation = Conversation {
            stream,
            deadlines: self.deadlines,
            hop_until,
            sent: false,
            bytes_sent: 0,
            bytes_received: 0,
            status: None,
            headers: Vec::new(),
            location: None,
            location_seen: false,
            headers_dropped: 0,
            cookies_dropped: 0,
            needle,
            echoes: 0,
        };
        let outcome = conversation.run(request, &body, limit, authorisation.method);
        conversation.close();
        let (disposition, kept, truncated) = match outcome {
            Ok((kept, truncated)) => (ExchangeDisposition::Completed, kept, truncated),
            Err(Ended::Refused(refusal)) if !conversation.sent => return Err(refusal),
            Err(Ended::Refused(_)) => (
                ExchangeDisposition::ResponseMalformed,
                Zeroizing::new(Vec::new()),
                false,
            ),
            Err(Ended::Sent(disposition)) => (disposition, Zeroizing::new(Vec::new()), false),
        };
        conversation.done(disposition, &kept, truncated)
    }
}

/// Complete the TLS handshake before `until`, and require `http/1.1` or no
/// ALPN at all.
fn handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    until: Instant,
) -> Result<(), BrokerRefusal> {
    while stream.conn.is_handshaking() {
        arm(&stream.sock, until).map_err(|()| BrokerRefusal::HttpTimeout)?;
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if timed_out(&error) => return Err(BrokerRefusal::HttpTimeout),
            Err(_) => return Err(BrokerRefusal::HttpTlsFailed),
        }
    }
    match stream.conn.alpn_protocol() {
        None => Ok(()),
        Some(protocol) if protocol == tls::ALPN_HTTP_1_1 => Ok(()),
        Some(_) => Err(BrokerRefusal::HttpTlsFailed),
    }
}

/// The request, rendered from the authorisation's typed fields alone.
fn request(
    authorisation: &HttpExchangeAuthorisation,
    credential: Option<(HeaderName, HeaderValue)>,
) -> Result<Request<()>, BrokerRefusal> {
    let invalid = |_| BrokerRefusal::HttpRequestInvalid;
    let method = match authorisation.method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
        HttpMethod::Options => Method::OPTIONS,
    };
    let port = authorisation.port.get();
    let host = if port == 443 {
        authorisation.host.as_str().to_owned()
    } else {
        format!("{}:{port}", authorisation.host.as_str())
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(authorisation.target.as_str())
        .version(Version::HTTP_11)
        .header("host", host)
        .header("user-agent", USER_AGENT)
        .header("accept-encoding", "identity")
        .header("connection", "close");
    let length = authorisation.body.as_ref().map_or(0, HexContent::byte_len);
    if authorisation.method.permits_body() {
        builder = builder.header("content-length", length.to_string());
    } else if length > 0 {
        return Err(BrokerRefusal::HttpRequestInvalid);
    }
    for header in &authorisation.headers {
        // Judged by the authority and by this decoder already; a third time
        // costs nothing, and the header map is what is written.
        if !rules::request_header_allowed(header.name.as_str()) {
            return Err(BrokerRefusal::HttpRequestInvalid);
        }
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }
    let mut request = builder.body(()).map_err(invalid)?;
    if let Some((name, value)) = credential {
        if request.headers().contains_key(&name) {
            return Err(BrokerRefusal::HttpRequestInvalid);
        }
        request.headers_mut().insert(name, value);
    }
    Ok(request)
}

/// One hop's conversation over an established TLS stream.
struct Conversation {
    stream: StreamOwned<ClientConnection, TcpStream>,
    deadlines: Deadlines,
    hop_until: Instant,
    /// Whether any byte of the request was written: from then on the origin
    /// may have acted.
    sent: bool,
    bytes_sent: u64,
    bytes_received: u64,
    status: Option<HttpStatus>,
    headers: Vec<HttpHeader>,
    location: Option<HttpLocation>,
    /// Whether a `Location` arrived, kept or not: a second is ambiguous.
    location_seen: bool,
    headers_dropped: u32,
    cookies_dropped: u32,
    /// The hop's credential, when it carries one: the response is redacted
    /// of it before anything of the response is copied into the answer.
    needle: Option<Arc<Needle>>,
    /// Response headers that held the credential, and occurrences of it
    /// replaced in the body.
    echoes: u32,
}

/// The response body's bytes kept, and whether more arrived.
type Body = (Zeroizing<Vec<u8>>, bool);

impl Conversation {
    fn malformed(&self) -> Ended {
        if self.sent {
            Ended::Sent(ExchangeDisposition::ResponseMalformed)
        } else {
            Ended::Refused(BrokerRefusal::HttpRequestInvalid)
        }
    }

    fn deadline(&self) -> Ended {
        if self.sent {
            Ended::Sent(ExchangeDisposition::Timeout)
        } else {
            Ended::Refused(BrokerRefusal::HttpTimeout)
        }
    }

    /// Write `bytes` before the hop's deadline.
    fn send(&mut self, bytes: &[u8]) -> Result<(), Ended> {
        if bytes.is_empty() {
            return Ok(());
        }
        arm(&self.stream.sock, self.hop_until).map_err(|()| self.deadline())?;
        // From the first byte on, the origin may act on what it has.
        self.sent = true;
        match self.stream.write_all(bytes) {
            Ok(()) => {
                self.bytes_sent = self
                    .bytes_sent
                    .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                Ok(())
            }
            Err(error) if timed_out(&error) => Err(self.deadline()),
            Err(_) => Err(self.malformed()),
        }
    }

    /// Read at most `into.len()` plaintext bytes before `until`. `Ok(0)` is
    /// the end of the stream.
    fn read(&mut self, into: &mut [u8], until: Instant) -> Result<usize, Ended> {
        arm(&self.stream.sock, until.min(self.hop_until)).map_err(|()| self.deadline())?;
        loop {
            match self.stream.read(into) {
                Ok(n) => {
                    self.bytes_received = self
                        .bytes_received
                        .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                    return Ok(n);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if timed_out(&error) => return Err(self.deadline()),
                // A connection that ended without TLS's close, or broke TLS:
                // nothing more can be read, and what was not is missing.
                Err(_) => return Ok(0),
            }
        }
    }

    /// Send the request and read the response. The kept body bytes, and
    /// whether more arrived.
    fn run(
        &mut self,
        request: Request<()>,
        body: &[u8],
        limit: usize,
        method: HttpMethod,
    ) -> Result<Body, Ended> {
        let invalid = |_| Ended::Refused(BrokerRefusal::HttpRequestInvalid);
        let mut output = Zeroizing::new(vec![0u8; RENDER_BUFFER]);
        let mut call = Call::new(request).map_err(invalid)?.proceed();
        // The head, in as many writes as the buffer needs.
        loop {
            let written = call.write(&mut output).map_err(|_| self.malformed())?;
            let chunk = output.get(..written).ok_or_else(|| self.malformed())?;
            self.send(chunk)?;
            if call.can_proceed() {
                break;
            }
        }
        crate::crash::point("http_after_request_head");
        let mut call = match call.proceed().map_err(|_| self.malformed())? {
            Some(SendRequestResult::RecvResponse(call)) => call,
            Some(SendRequestResult::SendBody(mut call)) => {
                let mut offset = 0usize;
                while offset < body.len() {
                    let rest = body.get(offset..).unwrap_or_default();
                    let (used, written) = call
                        .write(rest, &mut output)
                        .map_err(|_| self.malformed())?;
                    let chunk = output.get(..written).ok_or_else(|| self.malformed())?;
                    self.send(chunk)?;
                    if used == 0 {
                        return Err(self.malformed());
                    }
                    offset = offset.saturating_add(used);
                }
                let (_, written) = call.write(&[], &mut output).map_err(|_| self.malformed())?;
                let chunk = output.get(..written).ok_or_else(|| self.malformed())?;
                self.send(chunk)?;
                call.proceed().ok_or_else(|| self.malformed())?
            }
            // No `Expect` header is ever sent, so no 100-continue is awaited.
            Some(SendRequestResult::Await100(_)) | None => return Err(self.malformed()),
        };
        self.stream.flush().map_err(|error| {
            if timed_out(&error) {
                self.deadline()
            } else {
                self.malformed()
            }
        })?;
        drop(output);
        crate::crash::point("http_after_request_sent");
        let (response, leftover) = self.head(&mut call)?;
        self.judge_head(&response, method)?;
        match call.proceed() {
            Some(RecvResponseResult::RecvBody(call)) => self.body(call, &leftover, limit),
            Some(RecvResponseResult::Redirect(_) | RecvResponseResult::Cleanup(_)) => {
                Ok((Zeroizing::new(Vec::new()), false))
            }
            None => Err(self.malformed()),
        }
    }

    /// Read the response head: the status line and headers, within their
    /// bounds and the head deadline. Informational responses before it are
    /// consumed. Returns the response and the bytes read past it.
    fn head(
        &mut self,
        call: &mut Call<RecvResponse>,
    ) -> Result<(Response<()>, Zeroizing<Vec<u8>>), Ended> {
        let until = Instant::now() + self.deadlines.head;
        let mut buffer = Zeroizing::new(vec![0u8; rules::MAX_RESPONSE_HEAD_BYTES]);
        let mut filled = 0usize;
        loop {
            if filled > 0 {
                let available = buffer.get(..filled).ok_or_else(|| self.malformed())?;
                match call.try_response(available, false) {
                    Ok((used, Some(response))) => {
                        let rest = buffer.get(used..filled).ok_or_else(|| self.malformed())?;
                        let mut leftover = Zeroizing::new(Vec::with_capacity(rest.len()));
                        leftover.extend_from_slice(rest);
                        return Ok((response, leftover));
                    }
                    // An informational response, consumed: keep what follows.
                    Ok((used, None)) if used > 0 => {
                        buffer.copy_within(used..filled, 0);
                        filled -= used;
                        continue;
                    }
                    Ok((_, None)) => {}
                    Err(_) => return Err(self.malformed()),
                }
            }
            if filled >= buffer.len() {
                // The head is longer than DireWolf reads.
                return Err(self.malformed());
            }
            let window = buffer
                .get_mut(filled..)
                .ok_or(Ended::Sent(ExchangeDisposition::ResponseMalformed))?;
            let take = window.len().min(READ_CHUNK);
            let window = window
                .get_mut(..take)
                .ok_or(Ended::Sent(ExchangeDisposition::ResponseMalformed))?;
            let read = self.read(window, until)?;
            if read == 0 {
                return Err(self.malformed());
            }
            filled = filled.saturating_add(read);
        }
    }

    /// Judge the response head and keep what may come back.
    fn judge_head(&mut self, response: &Response<()>, method: HttpMethod) -> Result<(), Ended> {
        let malformed = Ended::Sent(ExchangeDisposition::ResponseMalformed);
        let status = response.status().as_u16();
        if response.version() != Version::HTTP_11 || status == 101 {
            return Err(malformed);
        }
        self.status = Some(HttpStatus::new(status).ok_or(malformed)?);
        let headers = response.headers();
        if headers.len() > rules::MAX_RESPONSE_HEADERS {
            return Err(malformed);
        }
        // Every header that holds the credential is counted, whatever else
        // is wrong with the response: the audit learns of an echo even when
        // nothing is answered.
        if let Some(needle) = &self.needle {
            let echoed = headers
                .values()
                .filter(|value| needle.found_in(value.as_bytes()))
                .count();
            self.echoes = self
                .echoes
                .saturating_add(u32::try_from(echoed).unwrap_or(u32::MAX));
        }
        framing(headers, method, status)?;
        for (name, value) in headers {
            self.keep(name, value)?;
        }
        Ok(())
    }

    /// Keep one response header if it is on the keep-list, spelled, the
    /// first of its name, and free of the hop's credential; count it
    /// otherwise.
    fn keep(&mut self, name: &HeaderName, value: &HeaderValue) -> Result<(), Ended> {
        let name = name.as_str();
        if name == "set-cookie" {
            self.cookies_dropped = self.cookies_dropped.saturating_add(1);
            return Ok(());
        }
        if !rules::response_header_kept(name) {
            self.headers_dropped = self.headers_dropped.saturating_add(1);
            return Ok(());
        }
        if name == "location" {
            // Two locations are two redirects: the response is ambiguous.
            if self.location_seen {
                return Err(Ended::Sent(ExchangeDisposition::ResponseMalformed));
            }
            self.location_seen = true;
        }
        // A header holding the credential is dropped whole -- never copied
        // into the answer -- and was counted with the head.
        if self
            .needle
            .as_ref()
            .is_some_and(|needle| needle.found_in(value.as_bytes()))
        {
            return Ok(());
        }
        let text = value.to_str().ok();
        if name == "location" {
            match text.and_then(HttpLocation::new) {
                Some(location) => self.location = Some(location),
                None => self.headers_dropped = self.headers_dropped.saturating_add(1),
            }
            return Ok(());
        }
        let repeated = self.headers.iter().any(|h| h.name.as_str() == name);
        let kept = self.headers.len() < rules::MAX_KEPT_RESPONSE_HEADERS;
        match (text.and_then(wire::kept_value), HttpHeaderName::new(name)) {
            (Some(value), Some(name)) if !repeated && kept => {
                self.headers.push(HttpHeader { name, value });
            }
            _ => self.headers_dropped = self.headers_dropped.saturating_add(1),
        }
        Ok(())
    }

    /// The body the answer carries: read to its end or past the bound, then
    /// — for a hop that carried the credential — redacted of it, and only
    /// then cut to the bound.
    ///
    /// The read goes past the bound by the value's length, so an occurrence
    /// that begins inside the bound is read whole and replaced; what the
    /// redactor still holds when the read stopped short lies past the bound,
    /// and is dropped with it. The redacted body is written into a
    /// `Zeroizing` buffer sized once; the raw one is zeroed when dropped.
    fn body(&mut self, call: Call<RecvBody>, leftover: &[u8], limit: usize) -> Result<Body, Ended> {
        let past = self.needle.as_ref().map_or(0, |needle| needle.len());
        let (mut raw, more) = self.read_body(call, leftover, limit.saturating_add(past))?;
        let Some(needle) = self.needle.clone() else {
            let truncated = more || raw.len() > limit;
            raw.truncate(limit);
            return Ok((raw, truncated));
        };
        let room = limit.saturating_add(1);
        let mut out = Zeroizing::new(Vec::with_capacity(room));
        let mut redactor = Redactor::new(needle);
        {
            let mut emit = |bytes: &[u8]| {
                let take = bytes.len().min(room.saturating_sub(out.len()));
                out.extend_from_slice(bytes.get(..take).unwrap_or_default());
            };
            redactor.feed(&raw, &mut emit);
            // A prefix of the value at the very end is the value's only when
            // the body ended there; otherwise it lies past the bound.
            if !more {
                redactor.finish(&mut emit);
            }
        }
        drop(raw);
        self.echoes = self
            .echoes
            .saturating_add(u32::try_from(redactor.occurrences()).unwrap_or(u32::MAX));
        let truncated = more || out.len() > limit;
        out.truncate(limit);
        Ok((out, truncated))
    }

    /// Read the body: to its end (`false`), or to `cap` plus one byte
    /// (`true`: more arrived).
    fn read_body(
        &mut self,
        mut call: Call<RecvBody>,
        leftover: &[u8],
        cap: usize,
    ) -> Result<Body, Ended> {
        let malformed = Ended::Sent(ExchangeDisposition::ResponseMalformed);
        let mut kept = Zeroizing::new(vec![0u8; cap.saturating_add(1)]);
        let mut filled = 0usize;
        let wire_cap = cap
            .saturating_add(1)
            .saturating_mul(BODY_FRAMING_FACTOR)
            .saturating_add(rules::MAX_RESPONSE_HEAD_BYTES);
        let mut wire_bytes = 0usize;
        let mut input = Zeroizing::new(vec![0u8; READ_CHUNK.max(leftover.len())]);
        let mut pending = leftover.len();
        input
            .get_mut(..pending)
            .ok_or(malformed)?
            .copy_from_slice(leftover);
        loop {
            // Decode what is pending, into what is left of the cap + 1.
            let mut offset = 0usize;
            while offset < pending && filled <= cap {
                let source = input.get(offset..pending).ok_or(malformed)?;
                let target = kept.get_mut(filled..).ok_or(malformed)?;
                let (used, produced) = call.read(source, target).map_err(|_| malformed)?;
                offset = offset.saturating_add(used);
                filled = filled.saturating_add(produced);
                if used == 0 && produced == 0 {
                    break;
                }
                if call.can_proceed() {
                    break;
                }
            }
            if filled > cap {
                // More than the cap arrived: stop reading.
                kept.truncate(filled);
                return Ok((kept, true));
            }
            if call.can_proceed() {
                kept.truncate(filled);
                return Ok((kept, false));
            }
            // Bytes the decoder left unread are an incomplete framing unit:
            // keep them in front of the next read.
            let unread = pending.saturating_sub(offset);
            input.copy_within(offset..pending, 0);
            if unread >= input.len() {
                return Err(malformed);
            }
            let until = Instant::now() + self.deadlines.idle;
            let window = input.get_mut(unread..).ok_or(malformed)?;
            let read = self.read(window, until)?;
            if read == 0 {
                // The connection ended before the framing did: a cut body.
                return Err(malformed);
            }
            wire_bytes = wire_bytes.saturating_add(read);
            if wire_bytes > wire_cap {
                return Err(malformed);
            }
            pending = unread.saturating_add(read);
        }
    }

    /// End TLS politely and close. Best effort: nothing waits on it.
    fn close(&mut self) {
        self.stream.conn.send_close_notify();
        if arm(
            &self.stream.sock,
            Instant::now() + Duration::from_millis(200),
        )
        .is_ok()
        {
            let _ = self.stream.conn.complete_io(&mut self.stream.sock);
        }
        let _ = self.stream.sock.shutdown(std::net::Shutdown::Both);
    }

    /// The answer.
    fn done(
        &mut self,
        disposition: ExchangeDisposition,
        kept: &[u8],
        truncated: bool,
    ) -> Result<HttpExchangeDone, BrokerRefusal> {
        let invalid = BrokerRefusal::HttpRequestInvalid;
        // Only a complete response is an answer: one that broke off carries
        // its status for the record, and no header and no `Location`.
        let completed = disposition == ExchangeDisposition::Completed;
        let kept_headers = std::mem::take(&mut self.headers);
        let location = self.location.take();
        let (kept_headers, location) = if completed {
            (kept_headers, location)
        } else {
            (Vec::new(), None)
        };
        let headers = ResponseHeaders::new(kept_headers).ok_or(invalid)?;
        let body = HexContent::from_bytes(kept).ok_or(invalid)?;
        Ok(HttpExchangeDone {
            disposition,
            status: self.status,
            headers,
            location,
            body,
            truncated,
            credential_echoes: HeaderCount::new(u16::try_from(self.echoes).unwrap_or(u16::MAX))
                .ok_or(invalid)?,
            headers_dropped: HeaderCount::new(
                u16::try_from(self.headers_dropped).unwrap_or(u16::MAX),
            )
            .ok_or(invalid)?,
            cookies_dropped: HeaderCount::new(
                u16::try_from(self.cookies_dropped).unwrap_or(u16::MAX),
            )
            .ok_or(invalid)?,
            bytes_sent: ByteCount::new(self.bytes_sent).ok_or(invalid)?,
            bytes_received: ByteCount::new(self.bytes_received).ok_or(invalid)?,
        })
    }
}

/// Whether the head frames its body as DireWolf requires: exactly one
/// `Content-Length` or exactly `Transfer-Encoding: chunked`, never both, and
/// one of them whenever a body may follow; no encoding but identity.
fn framing(headers: &HeaderMap, method: HttpMethod, status: u16) -> Result<(), Ended> {
    let malformed = Ended::Sent(ExchangeDisposition::ResponseMalformed);
    let lengths: Vec<&HeaderValue> = headers.get_all("content-length").iter().collect();
    let codings: Vec<&HeaderValue> = headers.get_all("transfer-encoding").iter().collect();
    for encoding in headers.get_all("content-encoding") {
        let identity = encoding
            .to_str()
            .is_ok_and(|e| e.trim().eq_ignore_ascii_case("identity"));
        if !identity {
            return Err(Ended::Sent(ExchangeDisposition::EncodingUnsupported));
        }
    }
    let chunked = match codings.as_slice() {
        [] => false,
        [only]
            if only
                .to_str()
                .is_ok_and(|c| c.trim().eq_ignore_ascii_case("chunked")) =>
        {
            true
        }
        _ => return Err(malformed),
    };
    let length = match lengths.as_slice() {
        [] => false,
        [only] if only.as_bytes().iter().all(u8::is_ascii_digit) && !only.is_empty() => true,
        _ => return Err(malformed),
    };
    if chunked && length {
        return Err(malformed);
    }
    let no_body = method == HttpMethod::Head || status == 204 || status == 304 || status < 200;
    if !no_body && !chunked && !length {
        // Delimited by the connection's close: indistinguishable from a cut.
        return Err(malformed);
    }
    Ok(())
}
