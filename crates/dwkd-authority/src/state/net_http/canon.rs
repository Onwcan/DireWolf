//! Step 1 of a `net.http` hop: the call, typed and canonical, before anything
//! is resolved (ADR-0050 §4). Pure: the request, the operator's reserved
//! header names and a detector for configured secret values in, a canonical
//! request or a typed refusal out.

use dwk_proto::dwkp::netops::{HttpMethod, NetHttpCall};
use dwk_proto::wire::guard;
use dwk_proto::wire::http::{self as rules, HeaderRefusal};
use dwk_proto::wire::scalar::HexContent;
use dwk_proto::wire::url::HttpsUrl;

use dwk_proto::dwkp::netops::ToolRefusalReasonV4 as Refusal;

/// A `net.http` call, canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Canonical {
    /// The method.
    pub(crate) method: HttpMethod,
    /// The URL, in its one spelling.
    pub(crate) url: HttpsUrl,
    /// The caller's headers, judged: lowercase names, each once.
    pub(crate) headers: Vec<(String, String)>,
    /// The body's bytes: empty for a method that carries none.
    pub(crate) body: Vec<u8>,
    /// The credential handle the call names, as text.
    pub(crate) credential: Option<String>,
    /// Whether redirects are followed.
    pub(crate) follow_redirects: bool,
    /// The caller's narrowing of the response bound.
    pub(crate) max_response_bytes: Option<u32>,
}

/// Whether `text` starts with a URI scheme other than `https`: plaintext
/// HTTP, a WebSocket, a file URL. A malformed URL is not a scheme question.
fn other_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    let shaped = bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    shaped && !scheme.eq_ignore_ascii_case("https")
}

/// Canonicalise `call`. `reserved` are the header names of every configured
/// credential, lowercase: the caller may never set one. `holds_secret` says
/// whether bytes hold a configured secret's value.
///
/// # Errors
///
/// The refusal, in the order the checks run: scheme, URL, metadata name,
/// headers, body, configured secret value.
pub(crate) fn canonicalize(
    call: &NetHttpCall,
    reserved: &[String],
    holds_secret: &dyn Fn(&[u8]) -> bool,
) -> Result<Canonical, Refusal> {
    let text = call.url.as_str();
    if other_scheme(text) {
        return Err(Refusal::PlaintextUnsupported);
    }
    let url = HttpsUrl::parse(text).map_err(|_| Refusal::UrlInvalid)?;
    // A metadata name is refused by name, before any resolution, whatever
    // a grant says (NETWORK_SECURITY.md §3).
    if guard::name_blocked(url.origin().host()) {
        return Err(Refusal::AddressBlocked);
    }
    let headers: Vec<(String, String)> = call
        .headers
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|h| (h.name.as_str().to_owned(), h.value.as_str().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let reserved: Vec<&str> = reserved.iter().map(String::as_str).collect();
    rules::judge_request_headers(
        headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        &reserved,
    )
    .map_err(|refusal| match refusal {
        HeaderRefusal::Invalid => Refusal::HeaderInvalid,
        HeaderRefusal::Forbidden => Refusal::HeaderForbidden,
    })?;
    let body = call
        .body
        .as_ref()
        .map_or_else(Vec::new, HexContent::to_bytes);
    if call.body.is_some() && !call.method.permits_body() {
        return Err(Refusal::BodyNotPermitted);
    }
    // A configured secret's value anywhere in what would be sent is
    // exfiltration: the runtime should never hold one (ADR-0050 §5 step 8).
    let carries = holds_secret(url.canonical().as_bytes())
        || headers.iter().any(|(_, v)| holds_secret(v.as_bytes()))
        || holds_secret(&body);
    if carries {
        return Err(Refusal::SecretInRequest);
    }
    Ok(Canonical {
        method: call.method,
        url,
        headers,
        body,
        credential: call
            .credential_handle
            .as_ref()
            .map(|h| h.as_str().to_owned()),
        follow_redirects: call.follow_redirects,
        max_response_bytes: call
            .max_response_bytes
            .map(dwk_proto::dwkp::netops::ResponseLimit::get),
    })
}

#[cfg(test)]
mod tests {
    use dwk_proto::dwkp::netops::{
        HttpHeader, HttpHeaderName, HttpHeaderValue, HttpMethod, HttpUrlText, NetHttpCall,
        RequestHeaders, ToolRefusalReasonV4 as R,
    };
    use dwk_proto::wire::scalar::HexContent;

    use super::canonicalize;

    fn call(method: HttpMethod, url: &str) -> NetHttpCall {
        NetHttpCall {
            method,
            url: HttpUrlText::new(url).unwrap_or_else(|| unreachable!("{url}")),
            headers: None,
            body: None,
            credential_handle: None,
            follow_redirects: false,
            max_response_bytes: None,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> Option<RequestHeaders> {
        RequestHeaders::new(
            pairs
                .iter()
                .map(|(n, v)| HttpHeader {
                    name: HttpHeaderName::new(*n).unwrap_or_else(|| unreachable!()),
                    value: HttpHeaderValue::new(*v).unwrap_or_else(|| unreachable!()),
                })
                .collect(),
        )
    }

    fn none(_: &[u8]) -> bool {
        false
    }

    #[test]
    fn the_scheme_the_url_and_the_name_are_judged_before_anything_else() {
        let cases = [
            ("http://api.example.com/", R::PlaintextUnsupported),
            ("wss://api.example.com/", R::PlaintextUnsupported),
            ("file:///etc/passwd", R::PlaintextUnsupported),
            ("HTTP://api.example.com/", R::PlaintextUnsupported),
            ("https://127.0.0.1/", R::UrlInvalid),
            ("https://2130706433/", R::UrlInvalid),
            ("https://0x7f.0.0.1/", R::UrlInvalid),
            ("https://[::1]/", R::UrlInvalid),
            ("https://user@api.example.com/", R::UrlInvalid),
            (
                "https://api.example.com.evil.test@other.test/",
                R::UrlInvalid,
            ),
            ("https://API.example.com/", R::UrlInvalid),
            ("https://api.example.com./", R::UrlInvalid),
            ("https://xn--80ak6aa92e.com/%2e%2e/", R::UrlInvalid),
            ("https://api.example.com/a/../b", R::UrlInvalid),
            ("https://api.example.com/#frag", R::UrlInvalid),
            ("https://api.example.com:0/", R::UrlInvalid),
            ("https://api.example.com:08443/", R::UrlInvalid),
            ("https://api.example.com\\@evil.test/", R::UrlInvalid),
            (
                "https://metadata.google.internal/computeMetadata/v1/",
                R::AddressBlocked,
            ),
            ("https://x.metadata.goog/", R::AddressBlocked),
        ];
        for (url, expected) in cases {
            assert_eq!(
                canonicalize(&call(HttpMethod::Get, url), &[], &none).map(|_| ()),
                Err(expected),
                "{url}"
            );
        }
        let ok = canonicalize(
            &call(HttpMethod::Get, "https://api.example.com"),
            &[],
            &none,
        );
        assert_eq!(
            ok.map(|c| c.url.canonical()).as_deref(),
            Ok("https://api.example.com:443/")
        );
    }

    #[test]
    fn headers_and_bodies_follow_the_shared_rules() {
        let mut forbidden = call(HttpMethod::Get, "https://a.b/");
        forbidden.headers = headers(&[("authorization", "Bearer x")]);
        assert_eq!(
            canonicalize(&forbidden, &[], &none).map(|_| ()),
            Err(R::HeaderForbidden)
        );
        // The operator's credential header, whatever its spelling there.
        let mut reserved = call(HttpMethod::Get, "https://a.b/");
        reserved.headers = headers(&[("x-api-key", "k")]);
        assert_eq!(
            canonicalize(&reserved, &["x-api-key".to_owned()], &none).map(|_| ()),
            Err(R::HeaderForbidden)
        );
        let mut twice = call(HttpMethod::Get, "https://a.b/");
        twice.headers = headers(&[("accept", "a"), ("accept", "b")]);
        assert_eq!(
            canonicalize(&twice, &[], &none).map(|_| ()),
            Err(R::HeaderInvalid)
        );
        let mut get_body = call(HttpMethod::Get, "https://a.b/");
        get_body.body = HexContent::from_bytes(b"x");
        assert_eq!(
            canonicalize(&get_body, &[], &none).map(|_| ()),
            Err(R::BodyNotPermitted)
        );
        let mut post = call(HttpMethod::Post, "https://a.b/");
        post.body = HexContent::from_bytes(b"{}");
        post.headers = headers(&[("content-type", "application/json")]);
        let canonical = canonicalize(&post, &[], &none).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(canonical.body, b"{}");
        assert_eq!(canonical.headers.len(), 1);
    }

    #[test]
    fn a_configured_secret_anywhere_in_the_request_refuses_it() {
        let secret = |bytes: &[u8]| bytes.windows(6).any(|w| w == b"s3cr3t");
        let mut in_url = call(HttpMethod::Get, "https://a.b/?token=s3cr3t");
        assert_eq!(
            canonicalize(&in_url, &[], &secret).map(|_| ()),
            Err(R::SecretInRequest)
        );
        in_url.url = HttpUrlText::new("https://a.b/").unwrap_or_else(|| unreachable!());
        in_url.headers = headers(&[("x-token", "s3cr3t")]);
        assert_eq!(
            canonicalize(&in_url, &[], &secret).map(|_| ()),
            Err(R::SecretInRequest)
        );
        let mut in_body = call(HttpMethod::Post, "https://a.b/");
        in_body.body = HexContent::from_bytes(b"{\"k\":\"s3cr3t\"}");
        assert_eq!(
            canonicalize(&in_body, &[], &secret).map(|_| ()),
            Err(R::SecretInRequest)
        );
    }
}
