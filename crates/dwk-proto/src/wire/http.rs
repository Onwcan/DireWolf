//! The HTTP vocabulary both daemons judge `net.http` by (M5c, ADR-0050 §§3–4,
//! 9): which request headers a caller may set, which response headers ever
//! come back, the one spelling of a header name and value, and the bounds.
//!
//! **One table, two judges.** The authority refuses a request whose headers
//! break these rules before anything is resolved (`HEADER_FORBIDDEN`,
//! `HEADER_INVALID`); the broker applies the same functions again to the
//! authorisation it renders from, and to the response it reads. Neither keeps
//! a second list, so they cannot drift.
//!
//! # Request headers: an allowlist
//!
//! A caller may set only the content-negotiation and conditional headers in
//! [`REQUEST_HEADERS`] and application headers named `x-…` — and of those, not
//! the ones proxies and frameworks read as routing, identity or method
//! overrides ([`OVERRIDE_PREFIXES`], [`OVERRIDE_HEADERS`]). Everything else is
//! refused, among it every header that frames, routes or authenticates a
//! request: `host`, `content-length`, `transfer-encoding`, `connection`,
//! `keep-alive`, `upgrade`, `te`, `trailer`, `expect`, `proxy-*`,
//! `forwarded`, `cookie`, `authorization`, `accept-encoding` (always
//! `identity`, D7) and `user-agent` (fixed). The broker sets the framing
//! headers itself, from typed fields; a credential header is composed only by
//! the broker, from the operator's metadata, never from a caller's header.
//!
//! # Response headers: a keep-list
//!
//! Only [`RESPONSE_HEADERS`] cross back to the authority, and from it to the
//! runtime. `set-cookie` never does: there is no cookie jar, and a cookie is a
//! credential the server issued.
//!
//! Pure functions over text: no `std::net`, no I/O (TX002).

/// The longest header name, in bytes.
pub const MAX_HEADER_NAME_BYTES: usize = 64;

/// The longest request header value, in bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 4096;

/// The most headers one request may carry from its caller.
pub const MAX_REQUEST_HEADERS: usize = 32;

/// The most bytes all of one request's caller headers may hold together:
/// every name and every value.
pub const MAX_REQUEST_HEADER_BYTES: usize = 8192;

/// The most response headers the broker parses; a response with more is
/// malformed.
pub const MAX_RESPONSE_HEADERS: usize = 100;

/// The most bytes of a response's status line and header block the broker
/// reads; a longer head is malformed.
pub const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;

/// The most kept response headers that come back.
pub const MAX_KEPT_RESPONSE_HEADERS: usize = 16;

/// The longest kept response header value that comes back; a longer one is
/// dropped (and counted), never cut.
pub const MAX_KEPT_HEADER_VALUE_BYTES: usize = 2048;

/// The most redirects one request follows: at most this many hops after the
/// first (D5).
pub const MAX_REDIRECTS: usize = 5;

/// The most hops one request makes: the first and its redirects.
pub const MAX_HOPS: usize = MAX_REDIRECTS + 1;

/// Request headers a caller may set, besides application `x-…` headers.
pub const REQUEST_HEADERS: [&str; 10] = [
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "pragma",
    "range",
];

/// `x-…` prefixes refused: routing and client-identity headers a proxy or a
/// framework believes.
pub const OVERRIDE_PREFIXES: [&str; 4] =
    ["x-forwarded-", "x-original-", "x-http-method", "x-proxy-"];

/// `x-…` names refused: routing, identity and method overrides.
pub const OVERRIDE_HEADERS: [&str; 7] = [
    "x-real-ip",
    "x-client-ip",
    "x-host",
    "x-method-override",
    "x-rewrite-url",
    "x-cluster-client-ip",
    "x-envoy-original-path",
];

/// Response headers that come back. `location` comes back only as the
/// authority canonicalised it.
pub const RESPONSE_HEADERS: [&str; 8] = [
    "cache-control",
    "content-length",
    "content-type",
    "etag",
    "last-modified",
    "link",
    "location",
    "retry-after",
];

/// Whether `byte` is an RFC 9110 `tchar` in its lowercase spelling.
const fn lower_tchar(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A header name in its one spelling: an RFC 9110 token, lowercase, 1 to
/// [`MAX_HEADER_NAME_BYTES`] bytes. `Accept` is refused rather than folded,
/// so a header has one written form on both wires.
#[must_use]
pub fn is_header_name(name: &str) -> bool {
    (1..=MAX_HEADER_NAME_BYTES).contains(&name.len()) && name.bytes().all(lower_tchar)
}

/// A header value in its one spelling: visible ASCII and interior spaces, no
/// leading or trailing space, at most `max` bytes, possibly empty. No CR, LF,
/// NUL, tab or other control — nothing that could end the header or fold it —
/// and nothing outside ASCII.
#[must_use]
pub fn is_header_value_within(value: &str, max: usize) -> bool {
    value.len() <= max
        && value.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
        && !value.starts_with(' ')
        && !value.ends_with(' ')
}

/// [`is_header_value_within`] at [`MAX_HEADER_VALUE_BYTES`].
#[must_use]
pub fn is_header_value(value: &str) -> bool {
    is_header_value_within(value, MAX_HEADER_VALUE_BYTES)
}

/// Whether a caller may set the request header `name` (already a lowercase
/// token). The credential headers of configured secrets are refused by the
/// authority on top of this, from the operator's metadata.
#[must_use]
pub fn request_header_allowed(name: &str) -> bool {
    if REQUEST_HEADERS.contains(&name) {
        return true;
    }
    let Some(rest) = name.strip_prefix("x-") else {
        return false;
    };
    !rest.is_empty()
        && !OVERRIDE_HEADERS.contains(&name)
        && !OVERRIDE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Whether the response header `name` (lowercase) comes back.
#[must_use]
pub fn response_header_kept(name: &str) -> bool {
    RESPONSE_HEADERS.contains(&name)
}

/// Why a caller's header set is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderRefusal {
    /// A name or value is not in its one spelling, a name repeats, or the set
    /// is past its bounds.
    Invalid,
    /// A name the caller may not set.
    Forbidden,
}

/// Judge a caller's whole header set: every name allowed and spelled once,
/// every value spelled, the count and the total within bounds. `reserved`
/// names more forbidden headers (the operator's credential headers).
///
/// # Errors
///
/// The first refusal: [`HeaderRefusal::Invalid`] before
/// [`HeaderRefusal::Forbidden`] for the same header.
pub fn judge_request_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    reserved: &[&str],
) -> Result<(), HeaderRefusal> {
    let mut seen: Vec<&str> = Vec::new();
    let mut total = 0usize;
    for (name, value) in headers {
        if !is_header_name(name) || !is_header_value(value) || seen.contains(&name) {
            return Err(HeaderRefusal::Invalid);
        }
        seen.push(name);
        if seen.len() > MAX_REQUEST_HEADERS {
            return Err(HeaderRefusal::Invalid);
        }
        total = total.saturating_add(name.len()).saturating_add(value.len());
        if total > MAX_REQUEST_HEADER_BYTES {
            return Err(HeaderRefusal::Invalid);
        }
        if !request_header_allowed(name) || reserved.contains(&name) {
            return Err(HeaderRefusal::Forbidden);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HeaderRefusal, MAX_REQUEST_HEADER_BYTES, is_header_name, is_header_value,
        judge_request_headers, request_header_allowed, response_header_kept,
    };

    #[test]
    fn names_and_values_have_one_spelling() {
        for good in [
            "accept",
            "x-api-version",
            "x-a",
            "if-none-match",
            "x-!#$%&'*+.^_`|~",
        ] {
            assert!(is_header_name(good), "{good}");
        }
        for bad in ["", "Accept", "x api", "x:a", "x\r", "é", &"x".repeat(65)] {
            assert!(!is_header_name(bad), "{bad:?}");
        }
        for good in ["", "text/plain", "a b", "W/\"etag\"", &"v".repeat(4096)] {
            assert!(is_header_value(good), "{good:?}");
        }
        for bad in [
            " a",
            "a ",
            "a\r\nb",
            "a\nb",
            "a\0b",
            "a\tb",
            "é",
            &"v".repeat(4097),
        ] {
            assert!(!is_header_value(bad), "{bad:?}");
        }
    }

    #[test]
    fn framing_routing_and_credentials_are_never_the_callers() {
        for refused in [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
            "trailer",
            "expect",
            "proxy-authorization",
            "proxy-connection",
            "forwarded",
            "cookie",
            "authorization",
            "accept-encoding",
            "user-agent",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-real-ip",
            "x-original-url",
            "x-http-method-override",
            "x-method-override",
            "x-host",
            "x-rewrite-url",
            "x-",
            "origin",
            "referer",
        ] {
            assert!(!request_header_allowed(refused), "{refused}");
        }
        for allowed in [
            "accept",
            "content-type",
            "range",
            "x-api-version",
            "x-request-id",
        ] {
            assert!(request_header_allowed(allowed), "{allowed}");
        }
    }

    #[test]
    fn a_header_set_is_judged_whole() {
        assert_eq!(judge_request_headers([("accept", "*/*")], &[]), Ok(()));
        assert_eq!(
            judge_request_headers([("accept", "a"), ("accept", "b")], &[]),
            Err(HeaderRefusal::Invalid)
        );
        assert_eq!(
            judge_request_headers([("Accept", "a")], &[]),
            Err(HeaderRefusal::Invalid)
        );
        assert_eq!(
            judge_request_headers([("authorization", "Bearer x")], &[]),
            Err(HeaderRefusal::Forbidden)
        );
        // An operator's credential header is the caller's to set never.
        assert_eq!(
            judge_request_headers([("x-api-key", "k")], &["x-api-key"]),
            Err(HeaderRefusal::Forbidden)
        );
        let big = "v".repeat(4096);
        let names: Vec<String> = (0..3).map(|i| format!("x-h{i}")).collect();
        let set: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), big.as_str())).collect();
        const { assert!(3 * 4096 > MAX_REQUEST_HEADER_BYTES) };
        assert_eq!(judge_request_headers(set, &[]), Err(HeaderRefusal::Invalid));
        let many: Vec<String> = (0..33).map(|i| format!("x-h{i}")).collect();
        assert_eq!(
            judge_request_headers(many.iter().map(|n| (n.as_str(), "v")), &[]),
            Err(HeaderRefusal::Invalid)
        );
    }

    #[test]
    fn only_the_keep_list_comes_back() {
        for kept in ["content-type", "etag", "location", "retry-after"] {
            assert!(response_header_kept(kept), "{kept}");
        }
        for dropped in [
            "set-cookie",
            "authorization",
            "www-authenticate",
            "server",
            "x-a",
        ] {
            assert!(!response_header_kept(dropped), "{dropped}");
        }
    }
}
