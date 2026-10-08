//! `net.http` (M5c, [ADR-0050]): the authority decides every hop of one HTTPS
//! request; the broker resolves and performs each, unfollowed.
//!
//! # One hop (ADR-0050 §5), in the authority
//!
//! | step | where | |
//! |---|---|---|
//! | 1. decode, canonicalise the URL and headers; metadata names | the first transaction | [`canon`] |
//! | 3. the capability: `network.https:<host>:<port>?methods=<m>&max_requests=<n>`, and `secret.use:<handle>` | the first transaction | [`plan`] |
//! | 4–5. resolve **only a covered host**, once per request; the whole answer guarded, here as in the broker | **no transaction**: the broker | [`Resolution`] |
//! | 6. policy for **each** pinned address, novelty, environment, body size; obligations enforceable | the intent transaction | [`plan`] |
//! | 7. budgets, never refilled | the intent transaction | `ledger` |
//! | 8. a configured secret's value anywhere in the request refuses | the first transaction | [`canon`] |
//! | 9. durable intent: the hop's, and its credential's | the intent transaction | `ledger`, `secret_use` |
//! | 10. the credential's one-shot pipe; the exchange to the pinned addresses | **no transaction**: the broker | |
//! | 11. the outcome, durably; taint raised | the outcome transaction | `ledger` |
//! | 12. the response: kept headers, redacted, bounded | memory, then the outcome transaction | |
//! | 13. a redirect is a new hop, decided from step 1 | | [`hop`] |
//!
//! Nothing is resolved for a host no grant covers, and nothing is resolved
//! when a decision that needs no address already denies. Nothing is sent to an
//! origin before that hop's gates, guard and budgets passed and its intent is
//! durable. A credential goes only to a hop at the request's first origin,
//! each time its own decided and recorded use; a cross-origin hop never
//! carries it, nor the caller's headers. A hop whose outcome is not proved is
//! `UNKNOWN` and never performed again; a request a dead incarnation left open
//! is ended `UNKNOWN` at start ([`reconcile_open`]).
//!
//! [ADR-0050]: ../../../../../docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md

pub(crate) mod canon;
mod hop;
mod ledger;
pub(crate) mod plan;

use std::collections::BTreeMap;
use std::sync::Arc;

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::egress::{EgressHost, EgressPort};
use dwk_proto::brokerp::http::{
    ExchangeDisposition, HopNumber, HopSpec, HttpExchangeDone, HttpHeader, HttpHeaderName,
    HttpHeaderValue, HttpStatus, HttpTarget, NetAddress, NetAddresses, RequestHeaders,
    ResolveDisposition, ResponseHeaders, ResponseLimit,
};
use dwk_proto::dwkp::DwkpBody;
use dwk_proto::dwkp::DwkpMessage;
use dwk_proto::dwkp::netops::{
    HttpMethod, NetHop, NetHops, NetHttpCall, NetHttpResult, RedirectEnd, ToolCallV4,
    ToolFailureReasonV4, ToolRefusalReasonV4 as Refusal,
};
use dwk_proto::dwkp::procops::ToolCallV3;
use dwk_proto::wire::guard::{self, Address, Verdict};
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::{Epoch, HexContent, IdempotencyKey, ToolOperation};
use dwk_proto::wire::url::HttpsUrl;
use dwk_proto::wire::{Cx, WireType};
use zeroize::Zeroizing;

use crate::broker::{BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, Operation};
use crate::secret::SecretError;

use super::crash::CrashPoint;
use super::digest::{self, Sha256Hash};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::policy_state::ActiveAuthority;
use super::secret_use::{self, Ending as SecretEnding};
use super::secrets::{Hits, SecretsState};
use super::{Authority, Shared, WireGap, wire};

use canon::Canonical;
use plan::NetPlan;

pub(crate) use ledger::reconcile_open;

/// The response bound before any narrowing: the frame's (ADR-0050 §10).
const RESPONSE_LIMIT: u32 = 262_144;
const _: () = assert!(dwk_proto::limits::MAX_NET_RESPONSE_BODY_BYTES == 262_144);

/// How long one request may take, all its hops together (ADR-0050 §10): the
/// authority's bound across hops; each hop has the broker's own.
pub(crate) const REQUEST_DEADLINE_MS: u64 = 300_000;

/// A run's network budgets (ADR-0050 §10, D10): requests, bytes each way and
/// distinct origins. Charged at each hop's intent — before anything is sent —
/// from the hop's own bounds, and **never refilled**: a hop record is never
/// deleted, and the charge is never refunded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetBudget {
    /// Hops, every redirect included.
    pub requests: u64,
    /// Request bytes: each hop's body, headers, request line and, when it
    /// carries one, the largest credential a header may hold.
    pub bytes_out: u64,
    /// Response bytes: each hop's response bound and the largest head.
    pub bytes_in: u64,
    /// Distinct origins (`host:port`).
    pub origins: u64,
}

impl Default for NetBudget {
    /// D10's defaults.
    fn default() -> Self {
        Self {
            requests: 100,
            bytes_out: 8 * 1024 * 1024,
            bytes_in: 64 * 1024 * 1024,
            origins: 16,
        }
    }
}

/// A `net.http` call as the authority receives it: the call, and for an
/// invocation its idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetRequest {
    pub(crate) call: NetHttpCall,
    pub(crate) key: Option<IdempotencyKey>,
}

/// What a `net.http` came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetReply {
    /// Refused before any effect was authorised, and recorded.
    Refused(ToolOperation, Refusal),
    /// The first hop's plan, with a refusing decision. Nothing was sent.
    Denied(NetPlan),
    /// A preview's plan. Nothing was resolved or sent.
    Previewed(NetPlan),
    /// The last response, and every hop.
    Done {
        invocation: InvocationId,
        plan: NetPlan,
        output: Box<NetHttpResult>,
    },
    /// The first hop was authorised and recorded and produced no response.
    Failed {
        invocation: InvocationId,
        reason: ToolFailureReasonV4,
    },
}

/// Who asks, about what.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Asked<'a> {
    pub(crate) caller: &'a CallerContext,
    pub(crate) operation: ToolOperation,
    pub(crate) session: &'a SessionId,
    pub(crate) run: &'a RunId,
    pub(crate) epoch: Epoch,
    pub(crate) request: &'a NetRequest,
}

/// What every transaction of one request decides with.
struct Ctx<'a> {
    asked: &'a Asked<'a>,
    active: &'a ActiveAuthority,
    secrets: &'a SecretsState,
    budget: NetBudget,
    after_metadata: &'a dyn Fn() -> Result<(), AuthorityError>,
}

impl Ctx<'_> {
    /// The response bound the call asked for: the frame's, or narrower.
    fn limit(&self) -> u32 {
        self.asked
            .request
            .call
            .max_response_bytes
            .map_or(RESPONSE_LIMIT, |l| l.get().min(RESPONSE_LIMIT))
    }
}

/// One hop's request, as the authority decides and sends it.
#[derive(Debug, Clone)]
struct HopRequest {
    number: u8,
    method: HttpMethod,
    url: HttpsUrl,
    url_sha256: Sha256Hash,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether this hop asks for the request's credential: it names one,
    /// and the hop is at the request's first origin.
    credential: bool,
}

impl HopRequest {
    fn first(canonical: &Canonical) -> Self {
        Self {
            number: 1,
            method: canonical.method,
            url_sha256: digest::plain(canonical.url.canonical().as_bytes()),
            url: canonical.url.clone(),
            headers: canonical.headers.clone(),
            body: canonical.body.clone(),
            credential: canonical.credential.is_some(),
        }
    }

    /// A redirect's hop: no body, ever; the caller's headers and the
    /// credential only at the request's first origin.
    fn next(&self, canonical: &Canonical, url: HttpsUrl, method: HttpMethod) -> Self {
        let home = url.origin() == canonical.url.origin();
        Self {
            number: self.number.saturating_add(1),
            method,
            url_sha256: digest::plain(url.canonical().as_bytes()),
            url,
            headers: if home {
                canonical.headers.clone()
            } else {
                Vec::new()
            },
            body: Vec::new(),
            credential: home && canonical.credential.is_some(),
        }
    }

    fn host(&self) -> &str {
        self.url.origin().host()
    }

    fn port(&self) -> u16 {
        self.url.origin().port()
    }
}

/// A response that arrived whole: what the request may answer with.
struct Response {
    status: u16,
    headers: Vec<HttpHeader>,
    location: Option<String>,
    body: Zeroizing<Vec<u8>>,
    truncated: bool,
    /// The URL it answered: the base its `Location` resolves against.
    url: HttpsUrl,
    /// The bound its body was read to.
    limit: u32,
}

/// What a resolution came to, as the authority judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unresolved {
    Blocked,
    Mixed,
    Failed,
    Timeout,
    Unavailable,
}

impl Unresolved {
    const fn refusal(self) -> Refusal {
        match self {
            Self::Blocked => Refusal::AddressBlocked,
            Self::Mixed => Refusal::AddressMixed,
            Self::Failed => Refusal::ResolutionFailed,
            Self::Timeout => Refusal::ResolutionTimeout,
            Self::Unavailable => Refusal::NetworkUnavailable,
        }
    }

    const fn end(self) -> RedirectEnd {
        match self {
            Self::Blocked => RedirectEnd::AddressBlocked,
            Self::Mixed => RedirectEnd::AddressMixed,
            Self::Failed => RedirectEnd::ResolutionFailed,
            Self::Timeout => RedirectEnd::ResolutionTimeout,
            Self::Unavailable => RedirectEnd::HopFailed,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "ADDRESS_BLOCKED",
            Self::Mixed => "ADDRESS_MIXED",
            Self::Failed => "RESOLUTION_FAILED",
            Self::Timeout => "RESOLUTION_TIMEOUT",
            Self::Unavailable => "NETWORK_UNAVAILABLE",
        }
    }
}

/// A resolution: the pinned addresses, or why there are none.
type Resolution = Result<Vec<Address>, Unresolved>;

/// The broker's answer to a resolution, judged again by the authority with
/// the one shared guard and the exceptions it was given — none in
/// production.
fn judge_resolution(
    result: &Result<BrokerDelivery, BrokerError>,
    exceptions: &[Address],
) -> Resolution {
    let Ok(BrokerDelivery::HttpResolved(done)) = result else {
        return Err(Unresolved::Unavailable);
    };
    match done.disposition {
        ResolveDisposition::Resolved => {}
        ResolveDisposition::NameBlocked | ResolveDisposition::AddressBlocked => {
            return Err(Unresolved::Blocked);
        }
        ResolveDisposition::AddressMixed => return Err(Unresolved::Mixed),
        ResolveDisposition::ResolutionFailed => return Err(Unresolved::Failed),
        ResolveDisposition::ResolutionTimeout => return Err(Unresolved::Timeout),
    }
    let addresses: Vec<Address> = done.addresses.iter().map(NetAddress::to_address).collect();
    match guard::judge(&addresses, exceptions) {
        Verdict::Allowed => Ok(addresses),
        Verdict::Empty => Err(Unresolved::Failed),
        Verdict::Blocked => Err(Unresolved::Blocked),
        Verdict::Mixed => Err(Unresolved::Mixed),
    }
}

/// How an exchange ended, before it is recorded.
#[derive(Debug)]
enum Exchanged {
    /// A complete response.
    Completed(Box<HttpExchangeDone>),
    /// The request was sent and the response broke, was encoded or late.
    Broken(Box<HttpExchangeDone>),
    /// The broker refused before sending a byte to the origin.
    Refused(BrokerRefusal),
    /// The broker was never told: unavailable, or a broken channel.
    NotSent(ToolFailureReasonV4),
    /// The credential could not be handed over; nothing reached the broker.
    CredentialFailed,
    /// The request may have been sent, and nothing proves what came of it.
    Unknown,
}

fn classify(result: Result<BrokerDelivery, BrokerError>) -> Exchanged {
    match result {
        Ok(BrokerDelivery::HttpExchanged(done)) => {
            if done.disposition == ExchangeDisposition::Completed {
                Exchanged::Completed(Box::new(done))
            } else {
                Exchanged::Broken(Box::new(done))
            }
        }
        // The broker said it refused: nothing went to the origin.
        Err(BrokerError {
            failure: BrokerFailure::Refused(refusal),
            ..
        }) => Exchanged::Refused(refusal),
        Err(error) if !error.sent => Exchanged::NotSent(match error.failure {
            BrokerFailure::Protocol(_) => ToolFailureReasonV4::BrokerProtocolError,
            _ => ToolFailureReasonV4::BrokerUnavailable,
        }),
        // Another operation's answer, an answer past the hop's bounds, or a
        // failure after the authorisation left: the origin may have acted.
        _ => Exchanged::Unknown,
    }
}

/// Why a hop that sent nothing failed, as the caller learns it.
const fn refusal_failure(refusal: BrokerRefusal) -> ToolFailureReasonV4 {
    match refusal {
        BrokerRefusal::HttpAddressBlocked => ToolFailureReasonV4::AddressBlocked,
        BrokerRefusal::HttpConnectFailed => ToolFailureReasonV4::ConnectFailed,
        BrokerRefusal::HttpTlsFailed => ToolFailureReasonV4::TlsFailed,
        BrokerRefusal::HttpTimeout => ToolFailureReasonV4::Timeout,
        BrokerRefusal::SecretDescriptor
        | BrokerRefusal::SecretEmpty
        | BrokerRefusal::SecretTooLarge
        | BrokerRefusal::SecretUnsafeBytes => ToolFailureReasonV4::CredentialFailed,
        BrokerRefusal::ChannelMismatch | BrokerRefusal::DescriptorCount => {
            ToolFailureReasonV4::BrokerProtocolError
        }
        _ => ToolFailureReasonV4::BrokerExecutionError,
    }
}

impl Exchanged {
    /// How often the broker found the hop's own credential in the response
    /// it redacted before answering (D11): a count, never a position.
    fn echoes(&self) -> u64 {
        match self {
            Self::Completed(done) | Self::Broken(done) => u64::from(done.credential_echoes.get()),
            _ => 0,
        }
    }

    /// The hop's recorded state, disposition, status, whether its handshake
    /// completed, and its byte counts.
    fn hop_ending(&self) -> ledger::HopEnding {
        let sent = |state: &'static str, done: &HttpExchangeDone| ledger::HopEnding {
            state,
            disposition: done.disposition.as_str(),
            status: done.status.map(HttpStatus::get),
            tls: true,
            bytes_sent: Some(done.bytes_sent.get()),
            bytes_received: Some(done.bytes_received.get()),
            injected: true,
            headers_dropped: u64::from(done.headers_dropped.get()),
            cookies_dropped: u64::from(done.cookies_dropped.get()),
            truncated: done.truncated,
        };
        let unsent = |state: &'static str, disposition: &'static str| ledger::HopEnding {
            state,
            disposition,
            status: None,
            tls: false,
            bytes_sent: None,
            bytes_received: None,
            injected: false,
            headers_dropped: 0,
            cookies_dropped: 0,
            truncated: false,
        };
        match self {
            Self::Completed(done) => sent("COMPLETED", done),
            Self::Broken(done) => sent("FAILED", done),
            Self::Refused(refusal) => unsent("FAILED", refusal.as_str()),
            Self::NotSent(reason) => unsent("FAILED", reason.as_str()),
            Self::CredentialFailed => unsent("FAILED", "CREDENTIAL_FAILED"),
            Self::Unknown => unsent("UNKNOWN", "OUTCOME_UNKNOWN"),
        }
    }

    /// The credential's ending, when the hop carried one. `failure` is the
    /// typed reason a handover that never reached the broker failed with.
    fn secret_ending(&self, failure: Option<&'static str>) -> SecretEnding {
        match self {
            Self::Completed(_) | Self::Broken(_) => SecretEnding::Injected,
            Self::Refused(refusal) => SecretEnding::Failed(refusal.as_str()),
            Self::NotSent(reason) => SecretEnding::Failed(reason.as_str()),
            Self::CredentialFailed => SecretEnding::Failed(failure.unwrap_or("CREDENTIAL_FAILED")),
            Self::Unknown => SecretEnding::Unknown,
        }
    }

    /// Why the first hop failed, when it did: `None` for a response, and
    /// for an unknown outcome (which the request records as unknown).
    fn failure(&self) -> Option<ToolFailureReasonV4> {
        match self {
            Self::Completed(_) | Self::Unknown => None,
            Self::Broken(done) => Some(match done.disposition {
                ExchangeDisposition::EncodingUnsupported => {
                    ToolFailureReasonV4::EncodingUnsupported
                }
                ExchangeDisposition::Timeout => ToolFailureReasonV4::Timeout,
                _ => ToolFailureReasonV4::ResponseMalformed,
            }),
            Self::Refused(refusal) => Some(refusal_failure(*refusal)),
            Self::NotSent(reason) => Some(*reason),
            Self::CredentialFailed => Some(ToolFailureReasonV4::CredentialFailed),
        }
    }
}

/// A request in flight: what every later hop is decided against.
struct Chain {
    invocation: InvocationId,
    canonical: Canonical,
    /// The request's pins: host → the guarded answer, for every hop.
    pins: BTreeMap<String, Vec<Address>>,
    /// Every canonical URL the request has asked for.
    visited: Vec<String>,
    /// Every hop that was recorded, for the result.
    hops: Vec<NetHop>,
    /// The first hop's plan.
    plan: Option<NetPlan>,
    /// The last response that arrived whole.
    last: Option<Response>,
    /// The broker's counts of the credential's echoes (D11), as redaction
    /// hits of its handle: every hop's, for the request's audit.
    echoes: Hits,
    started_ms: u64,
}

/// A wire header from a pair the canonicaliser already judged.
fn wire_header(name: &str, value: &str) -> Option<HttpHeader> {
    Some(HttpHeader {
        name: HttpHeaderName::new(name)?,
        value: HttpHeaderValue::new(value)?,
    })
}

/// The hop as the broker is told it.
fn hop_spec(
    hop: &HopRequest,
    addresses: &[Address],
    limit: u32,
    credential: Option<dwk_proto::brokerp::http::HttpCredential>,
) -> Result<HopSpec, AuthorityError> {
    let unfit = |what: &'static str| AuthorityError::Invariant(what);
    let headers = hop
        .headers
        .iter()
        .map(|(n, v)| wire_header(n, v))
        .collect::<Option<Vec<_>>>()
        .and_then(RequestHeaders::new)
        .ok_or_else(|| unfit("a judged header does not fit the private wire"))?;
    let body = if hop.body.is_empty() {
        None
    } else {
        Some(HexContent::from_bytes(&hop.body).ok_or_else(|| unfit("a body does not fit"))?)
    };
    Ok(HopSpec {
        hop: HopNumber::new(hop.number).ok_or_else(|| unfit("a hop number"))?,
        method: hop.method,
        host: EgressHost::new(hop.host()).ok_or_else(|| unfit("a canonical host"))?,
        port: EgressPort::new(hop.port()).ok_or_else(|| unfit("a port"))?,
        target: HttpTarget::new(hop.url.request_target())
            .ok_or_else(|| unfit("a request target"))?,
        headers,
        body,
        addresses: NetAddresses::new(
            addresses
                .iter()
                .take(dwk_proto::brokerp::http::MAX_PINNED_ADDRESSES)
                .map(|a| NetAddress::from_address(*a))
                .collect(),
        )
        .ok_or_else(|| unfit("the pinned addresses"))?,
        response_limit: ResponseLimit::new(limit).ok_or_else(|| unfit("a response bound"))?,
        credential,
    })
}

/// Merge `more` into `hits`.
fn add_hits(hits: &mut Hits, more: Hits) {
    for (kind, count) in more {
        let slot = hits.entry(kind).or_insert(0);
        *slot = slot.saturating_add(count);
    }
}

/// The answer: the last response's status, kept headers — redacted, and
/// `location` as the authority canonicalised it — and body, redacted and
/// bounded; every hop; why a redirect was not followed.
fn result(
    secrets: &SecretsState,
    last: Response,
    hops: &[NetHop],
    redirect_ended: Option<RedirectEnd>,
) -> Result<(NetHttpResult, Hits), AuthorityError> {
    let unfit = |what: &'static str| AuthorityError::Invariant(what);
    let Response {
        status,
        headers,
        location,
        mut body,
        truncated,
        url,
        limit,
    } = last;
    let mut hits = Hits::new();
    let mut kept = Vec::new();
    for header in headers {
        let redaction = secrets.redact(header.value.as_str().as_bytes());
        let clean = redaction.hits.is_empty();
        add_hits(&mut hits, redaction.hits);
        // A kept header that held a secret is dropped whole, never half.
        if clean {
            kept.push(header);
        }
    }
    if let Some(location) = location
        && let Ok(target) = url.resolve(&location)
    {
        let canonical = target.canonical();
        let redaction = secrets.redact(canonical.as_bytes());
        let clean = redaction.hits.is_empty();
        add_hits(&mut hits, redaction.hits);
        if clean
            && let (Some(name), Some(value)) = (
                HttpHeaderName::new("location"),
                dwk_proto::brokerp::http::kept_value(&canonical),
            )
        {
            kept.push(HttpHeader { name, value });
        }
    }
    let limit = usize::try_from(limit).unwrap_or(0);
    let redacted = secrets.redact_bounded(&mut body, limit);
    add_hits(&mut hits, redacted.hits);
    let output = NetHttpResult {
        status: HttpStatus::new(status).ok_or_else(|| unfit("a status"))?,
        headers: ResponseHeaders::new(kept).ok_or_else(|| unfit("the kept headers"))?,
        body: HexContent::from_bytes(&redacted.bytes).ok_or_else(|| unfit("a body"))?,
        truncated: truncated || redacted.cut,
        hops: NetHops::new(hops.to_vec()).ok_or_else(|| unfit("the hops"))?,
        redirect_ended,
    };
    Ok((output, hits))
}

impl Authority {
    /// `ToolInvoke` of `net.http` (M5c, ADR-0050): every hop decided,
    /// resolved, guarded, recorded, performed and recorded again, in that
    /// order — and only then answered.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook at a
    /// [`CrashPoint::NET`] or [`CrashPoint::SECRET`] point poisons the store,
    /// as a crash would.
    pub(crate) fn net_invoke(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &NetRequest,
    ) -> Result<NetReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = Asked {
            caller,
            operation: ToolOperation::ToolInvoke,
            session,
            run,
            epoch,
            request,
        };
        if request.call.credential_handle.is_some() {
            shared.crash(CrashPoint::SecretBeforeMetadata)?;
        }
        let after_metadata = || shared.crash(CrashPoint::SecretAfterMetadata);
        let ctx = Ctx {
            asked: &asked,
            active,
            secrets: &shared.secrets,
            budget: shared.net_budget,
            after_metadata: &after_metadata,
        };
        let located = self.transact(|work| ledger::locate(work, &ctx, false))?;
        let (canonical, invocation) = match located {
            ledger::Located::Refused(reason) => {
                return Ok(NetReply::Refused(asked.operation, reason));
            }
            ledger::Located::Denied(plan) => return Ok(NetReply::Denied(plan)),
            ledger::Located::Previewed(_) => {
                return Err(AuthorityError::Invariant(
                    "an invocation was answered as a preview",
                ));
            }
            ledger::Located::Resolve {
                canonical,
                invocation,
            } => (canonical, invocation),
        };
        let mut chain = Chain {
            invocation,
            hops: Vec::new(),
            pins: BTreeMap::new(),
            visited: Vec::new(),
            plan: None,
            last: None,
            echoes: Hits::new(),
            started_ms: shared.clock.now_ms(),
            canonical: *canonical,
        };
        let mut hop = HopRequest::first(&chain.canonical);
        loop {
            match self.net_hop(&shared, &ctx, &mut chain, &hop)? {
                Step::Answer(reply) => return Ok(*reply),
                Step::Next(next) => hop = *next,
            }
        }
    }

    /// `CanonicalPreview` of `net.http`: the same canonicalisation and gates
    /// as an invocation's first decision, without an address — so a rule
    /// that needs one is unevaluable and the preview says so. Nothing is
    /// resolved, recorded or sent.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub(crate) fn net_preview(
        &mut self,
        caller: &CallerContext,
        session: &SessionId,
        run: &RunId,
        epoch: Epoch,
        request: &NetRequest,
    ) -> Result<NetReply, AuthorityError> {
        let shared = Arc::clone(&self.shared);
        let active = shared.active()?;
        let asked = Asked {
            caller,
            operation: ToolOperation::CanonicalPreview,
            session,
            run,
            epoch,
            request,
        };
        let after_metadata = || Ok(());
        let ctx = Ctx {
            asked: &asked,
            active,
            secrets: &shared.secrets,
            budget: shared.net_budget,
            after_metadata: &after_metadata,
        };
        Ok(
            match self.transact(|work| ledger::locate(work, &ctx, true))? {
                ledger::Located::Refused(reason) => NetReply::Refused(asked.operation, reason),
                ledger::Located::Previewed(plan) => NetReply::Previewed(plan),
                ledger::Located::Denied(_) | ledger::Located::Resolve { .. } => {
                    return Err(AuthorityError::Invariant(
                        "a preview was answered as an invocation",
                    ));
                }
            },
        )
    }

    /// One hop, from its resolution to its outcome — and, when the chain ends
    /// here, the request's.
    fn net_hop(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        hop: &HopRequest,
    ) -> Result<Step, AuthorityError> {
        let addresses = match self.net_addresses(shared, ctx, chain, hop)? {
            Ok(addresses) => addresses,
            Err(step) => return Ok(step),
        };
        let recorded = match self.net_intent(shared, ctx, chain, hop, &addresses)? {
            Ok(recorded) => recorded,
            Err(step) => return Ok(step),
        };
        if hop.number == 1 {
            chain.plan = Some(recorded.plan.clone());
        }
        chain.visited.push(hop.url.canonical());
        shared.crash(CrashPoint::NetAfterIntent)?;
        let injection = recorded.injection;
        if injection.is_some() {
            shared.crash(CrashPoint::SecretAfterIntent)?;
        }
        let limit = recorded.plan.net.response_limit;
        // 10. The credential's pipe, then the exchange. No transaction.
        let (exchanged, secret_failure, resolved) =
            exchange(shared, chain, hop, &addresses, limit, injection.as_ref())?;
        if let Some(authorised) = injection.as_ref() {
            shared.crash(CrashPoint::SecretBeforeOutcome)?;
            // What the broker redacted of the credential before answering is
            // a redaction of its handle, audited with the request.
            let echoes = exchanged.echoes();
            if echoes > 0 {
                let handle =
                    crate::secret::redact::HitKind::Handle(authorised.prepared.handle.clone());
                add_hits(&mut chain.echoes, Hits::from([(handle, echoes)]));
            }
        }
        let secret = injection
            .as_ref()
            .map(|a| (a, exchanged.secret_ending(secret_failure), resolved));
        let step = self.net_settle(shared, ctx, chain, hop, exchanged, secret, limit)?;
        shared.crash(CrashPoint::NetAfterOutcome)?;
        if injection.is_some() {
            shared.crash(CrashPoint::SecretAfterOutcome)?;
        }
        Ok(step)
    }

    /// Steps 1–5 of a hop: for a later one, the request's deadline, a
    /// metadata name and — when the host must be resolved — a covering grant;
    /// then the pinned addresses, resolving and judging a host this request
    /// has not pinned. `Err` is the step the request takes instead.
    fn net_addresses(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        hop: &HopRequest,
    ) -> Result<Result<Vec<Address>, Step>, AuthorityError> {
        let first = hop.number == 1;
        if !first {
            if shared.clock.now_ms().saturating_sub(chain.started_ms) > REQUEST_DEADLINE_MS {
                return self
                    .net_end(shared, ctx, chain, RedirectEnd::RequestTimeout)
                    .map(Err);
            }
            if guard::name_blocked(hop.host()) {
                return self
                    .net_end(shared, ctx, chain, RedirectEnd::AddressBlocked)
                    .map(Err);
            }
            if !chain.pins.contains_key(hop.host()) {
                let ended = self.transact(|work| ledger::precheck(work, ctx, hop))?;
                if let Some(end) = ended {
                    return self.net_end(shared, ctx, chain, end).map(Err);
                }
            }
        }
        if let Some(pinned) = chain.pins.get(hop.host()) {
            return Ok(Ok(pinned.clone()));
        }
        let order = BrokerOrder::new(
            chain.invocation.clone(),
            Operation::HttpResolve {
                host: EgressHost::new(hop.host())
                    .ok_or(AuthorityError::Invariant("a canonical host is not a host"))?,
            },
        );
        let answer = perform(shared, order);
        shared.crash(CrashPoint::NetAfterResolve)?;
        let exceptions = shared.net_exceptions.get().map_or(&[][..], Vec::as_slice);
        let resolution = judge_resolution(&answer, exceptions);
        self.transact(|work| {
            ledger::record_resolution(work, ctx, &chain.invocation, hop, &resolution)
        })?;
        match resolution {
            Ok(addresses) => {
                chain.pins.insert(hop.host().to_owned(), addresses.clone());
                Ok(Ok(addresses))
            }
            Err(unresolved) if first => Ok(Err(Step::answer(NetReply::Refused(
                ctx.asked.operation,
                unresolved.refusal(),
            )))),
            Err(unresolved) => self.net_end(shared, ctx, chain, unresolved.end()).map(Err),
        }
    }

    /// Steps 6–9 of a hop: decide with every pinned address, the budgets, the
    /// durable intent. `Err` is the step the request takes instead.
    fn net_intent(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        hop: &HopRequest,
        addresses: &[Address],
    ) -> Result<Result<ledger::Recorded, Step>, AuthorityError> {
        let first = hop.number == 1;
        let intent = self.transact(|work| {
            ledger::record_intent(
                work,
                ctx,
                &chain.invocation,
                &chain.canonical,
                hop,
                addresses,
            )
        })?;
        let refused = |reason| {
            Ok(Err(Step::answer(NetReply::Refused(
                ctx.asked.operation,
                reason,
            ))))
        };
        match intent {
            ledger::Intent::Recorded(recorded) => Ok(Ok(*recorded)),
            ledger::Intent::Refused(reason) if first => refused(reason),
            ledger::Intent::Denied(plan) if first => Ok(Err(Step::answer(NetReply::Denied(*plan)))),
            ledger::Intent::Exhausted if first => refused(Refusal::BudgetExhausted),
            ledger::Intent::Exhausted => self
                .net_end(shared, ctx, chain, RedirectEnd::BudgetExhausted)
                .map(Err),
            ledger::Intent::Refused(_) | ledger::Intent::Denied(_) => self
                .net_end(shared, ctx, chain, RedirectEnd::HopDenied)
                .map(Err),
        }
    }

    /// Steps 11–13 of a hop: what came back, recorded; and what follows it —
    /// the next hop, or the request's answer.
    #[expect(
        clippy::too_many_arguments,
        reason = "one hop's whole state, taken apart only to be put back together"
    )]
    fn net_settle(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        hop: &HopRequest,
        exchanged: Exchanged,
        secret: Option<SecretOutcome<'_>>,
        limit: u32,
    ) -> Result<Step, AuthorityError> {
        let first = hop.number == 1;
        let ending = exchanged.hop_ending();
        chain.hops.push(NetHop {
            hop: HopNumber::new(hop.number).ok_or(AuthorityError::Invariant("a hop number"))?,
            host: dwk_proto::dwkp::netops::NetHost::new(hop.host())
                .ok_or(AuthorityError::Invariant("a canonical host"))?,
            port: dwk_proto::dwkp::netops::NetPort::new(hop.port())
                .ok_or(AuthorityError::Invariant("a port"))?,
            method: hop.method,
            status: ending.status.and_then(HttpStatus::new),
            injected: secret.is_some() && ending.injected,
        });
        let failure = exchanged.failure();
        let follows = if let Exchanged::Completed(done) = exchanged {
            let done = *done;
            let status = done
                .status
                .map(HttpStatus::get)
                .ok_or(AuthorityError::Invariant(
                    "a completed exchange without a status",
                ))?;
            let location = done.location.as_ref().map(|l| l.as_str().to_owned());
            let next = hop::next(
                status,
                location.as_deref(),
                &hop.url,
                hop.method,
                chain.canonical.follow_redirects,
                usize::from(hop.number),
                &chain.visited,
            );
            chain.last = Some(Response {
                status,
                headers: done.headers.iter().cloned().collect(),
                location,
                body: Zeroizing::new(done.body.to_bytes()),
                truncated: done.truncated,
                url: hop.url.clone(),
                limit,
            });
            Some(next)
        } else {
            None
        };
        match follows {
            Some(hop::Next::Hop { url, method }) => {
                self.transact(|work| {
                    ledger::end_hop(work, ctx, &chain.invocation, hop, &ending, secret)
                })?;
                Ok(Step::Next(Box::new(hop.next(
                    &chain.canonical,
                    url,
                    method,
                ))))
            }
            Some(hop::Next::End(why)) => self
                .net_finish(shared, ctx, chain, Some((hop, &ending, secret)), why)
                .map(Step::answer),
            // A later hop with no response ends the chain with the response
            // before it.
            None if !first => self
                .net_finish(
                    shared,
                    ctx,
                    chain,
                    Some((hop, &ending, secret)),
                    Some(RedirectEnd::HopFailed),
                )
                .map(Step::answer),
            // A first hop with no response fails the request.
            None => {
                let echoes = std::mem::take(&mut chain.echoes);
                let reply = self.transact(|work| {
                    ledger::end_hop(work, ctx, &chain.invocation, hop, &ending, secret)?;
                    let request_ending = match failure {
                        Some(reason) => ledger::RequestEnding::Failed(reason),
                        None => ledger::RequestEnding::Unknown,
                    };
                    ledger::end_request(work, ctx, &chain.invocation, &request_ending, 1, &echoes)?;
                    Ok(NetReply::Failed {
                        invocation: chain.invocation.clone(),
                        reason: failure.unwrap_or(ToolFailureReasonV4::OutcomeUnknown),
                    })
                })?;
                Ok(Step::answer(reply))
            }
        }
    }
}

/// Have the broker perform `order`; with none configured, nothing is sent.
fn perform(shared: &Shared, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
    if let Some(broker) = &shared.broker {
        broker.perform(order)
    } else {
        drop(order);
        Err(BrokerError::before_sending(BrokerFailure::NotConfigured))
    }
}

/// Step 10: hand the credential over, if the hop carries one, and have the
/// broker perform the hop. Returns how it ended, the typed reason a handover
/// that never reached the broker failed with, and whether the value was read
/// from its backend.
fn exchange(
    shared: &Shared,
    chain: &Chain,
    hop: &HopRequest,
    addresses: &[Address],
    limit: u32,
    injection: Option<&secret_use::Authorised>,
) -> Result<(Exchanged, Option<&'static str>, bool), AuthorityError> {
    let (secret, credential, resolved) = match injection {
        None => (None, None, false),
        Some(authorised) => {
            let prepared = &authorised.prepared;
            // The value, with no transaction open.
            let material = crate::secret::backend::read(
                &prepared.metadata.storage,
                shared.secrets.config().age.as_ref(),
                shared.authority_uid,
            );
            let material = match material {
                Ok(material) => material,
                Err(error) => return Ok((Exchanged::CredentialFailed, Some(error.code()), false)),
            };
            shared.crash(CrashPoint::SecretAfterBackend)?;
            // The return path learns it before it can go anywhere.
            shared.secrets.register(&prepared.handle, &material);
            shared.crash(CrashPoint::SecretAfterRegister)?;
            if !crate::secret::handoff::header_safe(&material) {
                drop(material);
                return Ok((
                    Exchanged::CredentialFailed,
                    Some(SecretError::MaterialInvalid.code()),
                    true,
                ));
            }
            // The one-shot pipe; the authority's copy is zeroed.
            let pipe = match crate::secret::handoff::one_shot(material) {
                Ok(pipe) => pipe,
                Err(error) => {
                    return Ok((Exchanged::CredentialFailed, Some(error.code()), true));
                }
            };
            shared.crash(CrashPoint::SecretAfterHandoff)?;
            (Some(pipe), Some(prepared.credential.clone()), true)
        }
    };
    let spec = hop_spec(hop, addresses, limit, credential)?;
    let order = BrokerOrder::new(
        chain.invocation.clone(),
        Operation::HttpExchange { hop: spec, secret },
    );
    let answer = perform(shared, order);
    shared.crash(CrashPoint::NetAfterBroker)?;
    if injection.is_some() {
        shared.crash(CrashPoint::SecretAfterBroker)?;
    }
    Ok((classify(answer), None, resolved))
}

impl Authority {
    /// The chain ends before a later hop was recorded: the last response is
    /// the answer, with why.
    fn net_end(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        why: RedirectEnd,
    ) -> Result<Step, AuthorityError> {
        self.net_finish(shared, ctx, chain, None, Some(why))
            .map(Step::answer)
    }

    /// The request's answer: the last response, redacted and bounded; the
    /// hop that ended it, if it has not been recorded; the request's
    /// outcome — in one transaction.
    fn net_finish(
        &mut self,
        shared: &Shared,
        ctx: &Ctx<'_>,
        chain: &mut Chain,
        hop: Option<EndedHop<'_>>,
        why: Option<RedirectEnd>,
    ) -> Result<NetReply, AuthorityError> {
        let last = chain.last.take().ok_or(AuthorityError::Invariant(
            "a chain ended without a response",
        ))?;
        let status = last.status;
        let (output, mut hits) = result(&shared.secrets, last, &chain.hops, why)?;
        add_hits(&mut hits, std::mem::take(&mut chain.echoes));
        let plan = chain
            .plan
            .clone()
            .ok_or(AuthorityError::Invariant("a chain ended without a plan"))?;
        let hops = u8::try_from(chain.hops.len()).unwrap_or(u8::MAX);
        let invocation = chain.invocation.clone();
        let body_bytes = output.body.byte_len();
        let truncated = output.truncated;
        self.transact(|work| {
            if let Some((hop, ending, secret)) = hop {
                ledger::end_hop(work, ctx, &invocation, hop, ending, secret)?;
            }
            if let Some(why) = why {
                ledger::end_redirect(work, ctx, &invocation, hops, why)?;
            }
            ledger::end_request(
                work,
                ctx,
                &invocation,
                &ledger::RequestEnding::Completed {
                    status,
                    redirect_ended: why,
                    body_bytes: u64::try_from(body_bytes).unwrap_or(u64::MAX),
                    truncated,
                },
                hops,
                &hits,
            )
        })?;
        Ok(NetReply::Done {
            invocation,
            plan,
            output: Box::new(output),
        })
    }

    /// Version 4 of `tool.invoke` (`invoke`) or `canonical.preview`: a
    /// `net.http` reaches this module; any other of the eleven tools is
    /// version 3's call in version 4's envelope, and is answered by version
    /// 3's path in version 4's shapes — the members are the same types.
    pub(super) fn dispatch_v4(
        &mut self,
        caller: &CallerContext,
        message: &DwkpMessage,
        call: &ToolCallV4,
        invoke: bool,
    ) -> Result<DwkpBody, AuthorityError> {
        let header = &message.header;
        let missing = || AuthorityError::Invariant("a decoded request lacks an envelope field");
        let unrepresentable = |_: WireGap| {
            AuthorityError::Invariant("a stored value does not fit the wire type that carries it")
        };
        let session = header.session_id.as_ref().ok_or_else(missing)?;
        let run = header.run_id.as_ref().ok_or_else(missing)?;
        let epoch = header.epoch.ok_or_else(missing)?;
        if let Some(net) = &call.net_http {
            let key = if invoke {
                Some(header.idempotency_key.clone().ok_or_else(missing)?)
            } else {
                None
            };
            let request = NetRequest {
                call: net.clone(),
                key,
            };
            let reply = if invoke {
                self.net_invoke(caller, session, run, epoch, &request)?
            } else {
                self.net_preview(caller, session, run, epoch, &request)?
            };
            return wire::net_reply(&reply).map_err(unrepresentable);
        }
        let recoded = call
            .encode()
            .and_then(|value| ToolCallV3::decode(value, &mut Cx::new()))
            .map_err(|_| {
                AuthorityError::Invariant("a version-4 call other than net.http is not version 3's")
            })?;
        let body = self.dispatch_v3(caller, message, &recoded, invoke)?;
        wire::v4_from_v3(body).map_err(unrepresentable)
    }
}

/// What one hop leads to.
enum Step {
    /// The request is answered.
    Answer(Box<NetReply>),
    /// Another hop, decided from the start.
    Next(Box<HopRequest>),
}

impl Step {
    fn answer(reply: NetReply) -> Self {
        Self::Answer(Box::new(reply))
    }
}

/// How a hop's credential ended: the use, its ending, and whether its value
/// was read.
type SecretOutcome<'a> = (&'a secret_use::Authorised, SecretEnding, bool);

/// A hop whose outcome is recorded with the request's.
type EndedHop<'a> = (
    &'a HopRequest,
    &'a ledger::HopEnding,
    Option<SecretOutcome<'a>>,
);

// A real store and a fake broker: Linux only, like the secret side's.
#[cfg(all(test, target_os = "linux"))]
mod tests;
