//! `net.http`'s private vocabulary (M5c, ADR-0050 §12): what the authority
//! asks the broker to resolve, the one exchange it authorises per hop, and
//! what comes back.
//!
//! **Typed facts, never a request.** An exchange names a method from the
//! closed set, an origin (host and port), the request target the authority
//! canonicalised, the caller's headers it already judged, a body, the
//! addresses the guard allowed — **pinned**: the broker dials only these and
//! never resolves the host again — and the response bound. The broker renders
//! the request itself, from these fields; the only header it adds that the
//! fields do not name is the credential's, composed from the operator's
//! metadata and the value in the last descriptor (ADR-0046 §12). Nothing here
//! names a resolver, an exception, a proxy, a TLS option or trust material
//! (TX036), and no field can hold a credential value.
//!
//! The decoder re-checks what the authority already did — the target parses
//! back to a canonical URL of the named origin, the headers pass the shared
//! allowlist with the credential's header reserved, a body only with a method
//! that carries one, a credential exactly when the kind says so — so that a
//! malformed authorisation is refused before anything is dialled, whoever sent
//! it.

use crate::brokerp::egress::{EgressHost, EgressPort};
use crate::brokerp::{
    ChannelNonce, DescriptorCount, PrivateKind, ProtocolVersion, SecretHandle, SecretHeaderName,
    SecretHeaderPrefix,
};
// The public call's scalar types, re-exported: an exchange states a hop in
// the vocabulary the runtime's call was decided in, and the broker names them
// here, never through `dwkp` (TX013: the broker speaks the private protocol).
pub use crate::dwkp::netops::{
    HopNumber, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpMethod, HttpStatus, RequestHeaders,
    ResponseHeaders, ResponseLimit,
};
use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::guard::Address;
use crate::wire::http;
use crate::wire::id::InvocationId;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{ByteCount, HexContent, wire_enum, wire_int, wire_text};
use crate::wire::url::HttpsUrl;
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// How long one resolution may take in the broker (`NETWORK_SECURITY.md` §3):
/// the CONNECT proxy's bound, shared.
pub const RESOLVE_DEADLINE_SECONDS: u64 = 5;
/// How long connecting to the pinned addresses may take, all of them together.
pub const CONNECT_DEADLINE_SECONDS: u64 = 10;
/// How long the TLS handshake may take.
pub const HANDSHAKE_DEADLINE_SECONDS: u64 = 10;
/// How long the response's status line and headers may take to arrive after
/// the request was sent.
pub const RESPONSE_HEAD_DEADLINE_SECONDS: u64 = 15;
/// How long the response body may go without a byte arriving.
pub const BODY_IDLE_DEADLINE_SECONDS: u64 = 15;
/// How long one hop may take, end to end, in the broker.
pub const HOP_DEADLINE_SECONDS: u64 = 30;
/// How long one `broker.http_resolve` exchange may take on the private
/// channel, both sides.
pub const RESOLVE_EXCHANGE_DEADLINE_SECONDS: u64 = 10;
/// How long one `broker.http_exchange` may take on the private channel, both
/// sides: the hop's bound and the channel's own hello and answer.
pub const HTTP_EXCHANGE_DEADLINE_SECONDS: u64 = HOP_DEADLINE_SECONDS + 15;

/// The most addresses one resolution pins: the guard judges the whole answer,
/// and the first sixteen are dialled in order.
pub const MAX_PINNED_ADDRESSES: usize = 16;

/// An address in its one private spelling: 4 or 16 octets, as 8 or 32
/// lowercase hexadecimal characters. Not text a resolver would accept: an
/// address on this wire is an answer the guard judged, never a name.
fn valid_address(s: &str) -> bool {
    (s.len() == 8 || s.len() == 32)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

wire_text! {
    /// A resolved address the guard allowed, pinned: 8 or 32 lowercase
    /// hexadecimal characters.
    NetAddress,
    max_chars = 32,
    pattern = Some("^(?:[0-9a-f]{8}|[0-9a-f]{32})$"),
    format = None,
    validate = valid_address
}

impl NetAddress {
    /// Spell `address`.
    #[must_use]
    pub fn from_address(address: Address) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(32);
        for byte in address.octets() {
            for nibble in [byte >> 4, byte & 0x0f] {
                if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                    text.push(char::from(*digit));
                }
            }
        }
        Self(text)
    }

    /// The address this spells. Validation guarantees 4 or 16 octets.
    #[must_use]
    pub fn to_address(&self) -> Address {
        let octets = HexContent::new(self.as_str()).map_or_else(Vec::new, |hex| hex.to_bytes());
        if let Ok(v4) = <[u8; 4]>::try_from(octets.as_slice()) {
            Address::V4(v4)
        } else if let Ok(v6) = <[u8; 16]>::try_from(octets.as_slice()) {
            Address::V6(v6)
        } else {
            // Unreachable for a validated value; the unspecified address is
            // blocked by the guard, so a fallback can reach nothing.
            Address::V4([0, 0, 0, 0])
        }
    }
}

/// The addresses a resolution pinned, in the resolver's order.
pub type NetAddresses = BoundedList<NetAddress, MAX_PINNED_ADDRESSES>;

/// A request target: `/`, then visible ASCII.
fn valid_target(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= crate::wire::url::MAX_URL_BYTES
        && s.bytes().all(|b| b.is_ascii_graphic())
}

wire_text! {
    /// The request target the authority canonicalised: the path and, if any,
    /// `?` and the query (`crate::wire::url::HttpsUrl::request_target`).
    HttpTarget,
    max_chars = 8192,
    pattern = Some("^/[!-~]{0,8191}$"),
    format = None,
    validate = valid_target
}

wire_text! {
    /// A `Location` header's value exactly as the response carried it, for
    /// the authority to resolve and canonicalise: visible ASCII and interior
    /// spaces, at most 8 KiB. The broker never follows it.
    HttpLocation,
    max_chars = 8192,
    pattern = Some("^[!-~](?:[ -~]{0,8190}[!-~])?$"),
    format = None,
    validate = |s| !s.is_empty() && http::is_header_value_within(s, 8192)
}

wire_int! {
    /// A small count: dropped headers, cookies.
    HeaderCount(u16), min = 0, max = 65535
}

wire_enum! {
    /// What one resolution found, judged by the shared guard
    /// (`crate::wire::guard`) with the broker's resolver's exceptions — none
    /// in production.
    ResolveDisposition {
        /// Every address is allowed: they are pinned.
        Resolved = "RESOLVED",
        /// The host is a cloud metadata name: nothing was resolved.
        NameBlocked = "NAME_BLOCKED",
        /// Every address is blocked.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// Some addresses are blocked and some are not: refused whole.
        AddressMixed = "ADDRESS_MIXED",
        /// The resolver failed, or answered nothing.
        ResolutionFailed = "RESOLUTION_FAILED",
        /// The resolver overran its deadline.
        ResolutionTimeout = "RESOLUTION_TIMEOUT",
    }
}

wire_enum! {
    /// How an exchange that sent its request ended. Anything that ended
    /// before a byte of the request was sent — a blocked address, no
    /// connection, a failed handshake, a refused credential — is a refusal,
    /// not one of these.
    ExchangeDisposition {
        /// A complete response arrived: its head, and its body to its end or
        /// to the bound.
        Completed = "COMPLETED",
        /// The response broke HTTP/1.1 framing or a bound DireWolf refuses
        /// rather than cuts.
        ResponseMalformed = "RESPONSE_MALFORMED",
        /// The response is encoded, and DireWolf never decodes (D7).
        EncodingUnsupported = "ENCODING_UNSUPPORTED",
        /// A deadline passed after the request was sent.
        Timeout = "TIMEOUT",
    }
}

wire_struct! {
    /// Resolve one host, once, for the authority to judge: the trusted-side
    /// resolver, under its deadline (ADR-0050 §6). No descriptor.
    HttpResolveAuthorisation: reject {
        /// Always `broker.http_resolve`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the request the hop belongs to.
        required invocation_id: InvocationId,
        /// The host, canonical, never an address literal.
        required host: EgressHost,
        /// None.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// What a resolution found.
    HttpResolveDone: reject {
        /// The guard's verdict on the whole answer.
        required disposition: ResolveDisposition,
        /// When resolved: the addresses, in the resolver's order, at most
        /// sixteen. Otherwise none.
        required addresses: NetAddresses,
    }
}

wire_struct! {
    /// The credential a hop carries: the operator's handle, header and
    /// prefix. The value is the last descriptor, never a field.
    HttpCredential: reject {
        /// The handle.
        required handle: SecretHandle,
        /// The header, from the operator's metadata.
        required header_name: SecretHeaderName,
        /// What precedes the value, from the operator's metadata.
        optional header_prefix: SecretHeaderPrefix,
    }
}

wire_struct! {
    /// One hop the authority authorised: exactly this request, to exactly
    /// these pinned addresses (ADR-0050 §§5, 9). `broker.http_exchange`
    /// carries no descriptor; `broker.http_credential_exchange` carries the
    /// credential's pipe and names its header.
    HttpExchangeAuthorisation: reject {
        /// `broker.http_exchange` or `broker.http_credential_exchange`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the request.
        required invocation_id: InvocationId,
        /// Which hop of the request this is.
        required hop: HopNumber,
        /// The method.
        required method: HttpMethod,
        /// The origin's host: the TLS server name and the name the
        /// certificate must hold.
        required host: EgressHost,
        /// The origin's port.
        required port: EgressPort,
        /// The request target.
        required target: HttpTarget,
        /// The caller's headers, judged.
        required headers: RequestHeaders,
        /// The body, for a method that carries one.
        optional body: HexContent,
        /// The pinned addresses, at least one.
        required addresses: NetAddresses,
        /// The most response body bytes to return.
        required response_limit: ResponseLimit,
        /// The credential, exactly for `broker.http_credential_exchange`.
        optional credential: HttpCredential,
        /// None, or one: the credential's pipe.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// What an exchange that sent its request found.
    HttpExchangeDone: reject {
        /// How it ended.
        required disposition: ExchangeDisposition,
        /// The status, if a head arrived.
        optional status: HttpStatus,
        /// The response's headers on the keep-list, `location` excepted, and
        /// none that held the hop's credential. Only for a `COMPLETED`
        /// exchange; none otherwise.
        required headers: ResponseHeaders,
        /// The response's `Location`, as it was, for the authority to judge;
        /// never one that held the hop's credential. Only for a `COMPLETED`
        /// exchange.
        optional location: HttpLocation,
        /// The body's first bytes, at most the bound.
        required body: HexContent,
        /// Whether more body arrived than was returned.
        required truncated: bool,
        /// Response headers dropped: off the keep-list, repeated, or not in
        /// one spelling. Counted, never returned.
        required headers_dropped: HeaderCount,
        /// `Set-Cookie` headers dropped.
        required cookies_dropped: HeaderCount,
        /// How often the response held the hop's own credential (D11): each
        /// header that held it, dropped whole, and each occurrence the broker
        /// replaced in the body with its placeholder before the body was
        /// encoded. Zero for a hop that carried no credential. A count, for
        /// the authority's audit; never a position or a byte of it.
        required credential_echoes: HeaderCount,
        /// Bytes written to the connection, TLS framing excluded.
        required bytes_sent: ByteCount,
        /// Bytes read from the connection, TLS framing excluded.
        required bytes_received: ByteCount,
    }
}

impl HttpResolveAuthorisation {
    /// A resolution of `host`.
    #[must_use]
    pub fn new(common: super::Common, host: EgressHost) -> Self {
        Self {
            kind: PrivateKind::HttpResolve,
            protocol: ProtocolVersion(super::PROTOCOL),
            channel: common.channel,
            invocation_id: common.invocation_id,
            host,
            descriptors: DescriptorCount(0),
        }
    }
}

/// One hop, as the authority states it: everything but the channel, the
/// invocation and the descriptor count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopSpec {
    /// Which hop.
    pub hop: HopNumber,
    /// The method.
    pub method: HttpMethod,
    /// The host.
    pub host: EgressHost,
    /// The port.
    pub port: EgressPort,
    /// The request target.
    pub target: HttpTarget,
    /// The caller's headers.
    pub headers: RequestHeaders,
    /// The body.
    pub body: Option<HexContent>,
    /// The pinned addresses.
    pub addresses: NetAddresses,
    /// The response bound.
    pub response_limit: ResponseLimit,
    /// The credential, if this hop carries one.
    pub credential: Option<HttpCredential>,
}

impl HttpExchangeAuthorisation {
    /// An exchange of `spec`: `broker.http_credential_exchange` with one
    /// descriptor when it carries a credential, `broker.http_exchange` with
    /// none otherwise.
    #[must_use]
    pub fn new(common: super::Common, spec: HopSpec) -> Self {
        let (kind, descriptors) = if spec.credential.is_some() {
            (PrivateKind::HttpCredentialExchange, 1)
        } else {
            (PrivateKind::HttpExchange, 0)
        };
        Self {
            kind,
            protocol: ProtocolVersion(super::PROTOCOL),
            channel: common.channel,
            invocation_id: common.invocation_id,
            hop: spec.hop,
            method: spec.method,
            host: spec.host,
            port: spec.port,
            target: spec.target,
            headers: spec.headers,
            body: spec.body,
            addresses: spec.addresses,
            response_limit: spec.response_limit,
            credential: spec.credential,
            descriptors: DescriptorCount(descriptors),
        }
    }

    /// The canonical URL this hop requests: the origin and the target, parsed
    /// back.
    ///
    /// # Errors
    ///
    /// The target does not parse back to a canonical URL of the origin.
    pub fn url(&self) -> Result<HttpsUrl, ProtocolError> {
        let text = format!(
            "https://{}:{}{}",
            self.host.as_str(),
            self.port.get(),
            self.target.as_str()
        );
        let url = HttpsUrl::parse(&text).map_err(|_| {
            ProtocolError::schema(
                Violation::InvalidFormat,
                "/target",
                "not a canonical request target",
            )
        })?;
        if url.request_target() != self.target.as_str() {
            return Err(ProtocolError::schema(
                Violation::InvalidFormat,
                "/target",
                "the request target is not in its canonical spelling",
            ));
        }
        Ok(url)
    }
}

fn inconsistent(path: &str, why: &str) -> ProtocolError {
    ProtocolError::schema(Violation::Inconsistent, path, why)
}

/// The exchange's own consistency, beyond its fields' types: the decoder's
/// last step, and the encoder's first.
///
/// # Errors
///
/// The first inconsistency.
pub(super) fn check_exchange(exchange: &HttpExchangeAuthorisation) -> Result<(), ProtocolError> {
    let credential = match exchange.kind {
        PrivateKind::HttpExchange => false,
        PrivateKind::HttpCredentialExchange => true,
        _ => return Err(inconsistent("/kind", "not an exchange")),
    };
    if credential != exchange.credential.is_some() {
        return Err(inconsistent(
            "/credential",
            "a credential exchange names its credential, and only it does",
        ));
    }
    exchange.url()?;
    if exchange.body.is_some() && !exchange.method.permits_body() {
        return Err(inconsistent(
            "/body",
            "a body on a method that carries none",
        ));
    }
    if exchange
        .body
        .as_ref()
        .is_some_and(|body| body.byte_len() > crate::limits::MAX_NET_REQUEST_BODY_BYTES)
    {
        return Err(inconsistent("/body", "the body is past its bound"));
    }
    if exchange.addresses.is_empty() {
        return Err(inconsistent(
            "/addresses",
            "an exchange dials at least one address",
        ));
    }
    let reserved: Vec<&str> = exchange
        .credential
        .as_ref()
        .map(|c| c.header_name.as_str())
        .into_iter()
        .collect();
    // The operator's header name may be in any case; the caller's are
    // lowercase, so compare lowercase.
    let reserved_lower: Vec<String> = reserved.iter().map(|n| n.to_ascii_lowercase()).collect();
    let reserved_refs: Vec<&str> = reserved_lower.iter().map(String::as_str).collect();
    http::judge_request_headers(
        exchange
            .headers
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_str())),
        &reserved_refs,
    )
    .map_err(|_| inconsistent("/headers", "a header the caller may not set"))?;
    Ok(())
}

/// A kept response header value, if it is in its one spelling and within the
/// bound that comes back.
#[must_use]
pub fn kept_value(value: &str) -> Option<HttpHeaderValue> {
    if http::is_header_value_within(value, http::MAX_KEPT_HEADER_VALUE_BYTES) {
        HttpHeaderValue::new(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{NetAddress, valid_address};
    use crate::wire::guard::Address;

    #[test]
    fn an_address_has_one_private_spelling() {
        let v4 = Address::V4([127, 0, 0, 1]);
        assert_eq!(NetAddress::from_address(v4).as_str(), "7f000001");
        assert_eq!(NetAddress::from_address(v4).to_address(), v4);
        let mut octets = [0u8; 16];
        if let Some(last) = octets.last_mut() {
            *last = 1;
        }
        let v6 = Address::V6(octets);
        assert_eq!(
            NetAddress::from_address(v6).as_str(),
            "00000000000000000000000000000001"
        );
        assert_eq!(NetAddress::from_address(v6).to_address(), v6);
        for bad in ["", "7f00001", "7F000001", "127.0.0.1", "::1", "7f0000010"] {
            assert!(!valid_address(bad), "{bad}");
        }
    }
}
