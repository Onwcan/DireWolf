//! An HTTPS URL, as DireWolf spells it (ADR-0050 §4): the one parser behind
//! every `net.http` request and every redirect `Location`, so a URL has one
//! canonical text and one [`Origin`], compared byte for byte with grants,
//! credential metadata and the hops already taken.
//!
//! * The scheme is exactly `https`: plain HTTP, an uppercase scheme and every
//!   other scheme are refused — never upgraded, never lowered.
//! * The host is a canonical host by [`super::host`]: lowercase labels, no
//!   Unicode, no trailing dot, never an address literal (dotted, decimal, hex,
//!   octal or bracketed). Userinfo (`user@host`) is refused, never stripped.
//! * The port is strict decimal, 1–65535, `443` when absent, and is always
//!   part of the origin.
//! * The path starts with `/` (an empty one is `/`) and holds only RFC 3986
//!   path characters. A percent escape is two hex digits, written uppercase in
//!   the canonical text; an escaped control byte is refused. **Dot segments,
//!   raw or escaped (`.`, `..`, `%2e`), are refused rather than removed**, so a
//!   path has no second spelling a server might normalise differently.
//! * The query keeps its bytes (RFC 3986 query characters, escapes checked,
//!   `%00` refused). A fragment is refused: it is never sent, so it can only
//!   ever be a difference between what was checked and what was meant.
//! * Every byte is visible ASCII. Whitespace, controls and non-ASCII are
//!   refused, wherever they are.
//!
//! A redirect's `Location` is an RFC 3986 reference resolved against the hop's
//! URL ([`HttpsUrl::resolve`]) and then parsed by the same rules: a reference
//! with a scheme or `//` names its own origin, a path or query is this
//! origin's, and anything the rules above refuse ends the chain.
//!
//! Pure functions over text: no resolution, no I/O.

use core::fmt;

use super::host::{is_address_literal, is_host};

/// The longest URL, in bytes.
pub const MAX_URL_BYTES: usize = 8192;

/// The port an `https` URL names when it names none.
pub const HTTPS_DEFAULT_PORT: u16 = 443;

/// Why a URL or a reference was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlError {
    /// Nothing to parse.
    Empty,
    /// Longer than [`MAX_URL_BYTES`].
    TooLong,
    /// A byte that is not visible ASCII.
    NotVisibleAscii,
    /// A scheme other than exactly `https`.
    NotHttps,
    /// No `//` authority after the scheme.
    MissingAuthority,
    /// A `user@` or `user:password@` part.
    Userinfo,
    /// A host that is not canonical.
    Host,
    /// A host spelled as an address, in any form.
    AddressLiteral,
    /// A port that is not strict decimal within 1–65535.
    Port,
    /// A path byte outside RFC 3986's path characters.
    Path,
    /// A `.` or `..` segment, raw or escaped.
    DotSegment,
    /// A `%` not followed by two hex digits, or an escaped control byte.
    PercentEncoding,
    /// A query byte outside RFC 3986's query characters.
    Query,
    /// A `#` fragment.
    Fragment,
}

impl UrlError {
    /// The refusal code, as the protocol and the audit spell it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "URL_EMPTY",
            Self::TooLong => "URL_TOO_LONG",
            Self::NotVisibleAscii => "URL_NOT_VISIBLE_ASCII",
            Self::NotHttps => "URL_NOT_HTTPS",
            Self::MissingAuthority => "URL_MISSING_AUTHORITY",
            Self::Userinfo => "URL_USERINFO",
            Self::Host => "URL_HOST",
            Self::AddressLiteral => "URL_ADDRESS_LITERAL",
            Self::Port => "URL_PORT",
            Self::Path => "URL_PATH",
            Self::DotSegment => "URL_DOT_SEGMENT",
            Self::PercentEncoding => "URL_PERCENT_ENCODING",
            Self::Query => "URL_QUERY",
            Self::Fragment => "URL_FRAGMENT",
        }
    }
}

/// Where an `https` URL goes: its canonical host and its port. Credential
/// binding, destination novelty, pinning and redirect decisions compare
/// origins, never URL text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    /// An origin from a host and a port, each checked as a URL's would be.
    ///
    /// # Errors
    ///
    /// [`UrlError::Host`], [`UrlError::AddressLiteral`] or [`UrlError::Port`].
    pub fn new(host: &str, port: u16) -> Result<Self, UrlError> {
        check_host(host)?;
        if port == 0 {
            return Err(UrlError::Port);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The canonical host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}:{}", self.host, self.port)
    }
}

/// A parsed, canonical `https` URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl {
    origin: Origin,
    path: String,
    query: Option<String>,
}

impl HttpsUrl {
    /// Parse `text` strictly.
    ///
    /// # Errors
    ///
    /// The first [`UrlError`] the rules in the module documentation meet.
    pub fn parse(text: &str) -> Result<Self, UrlError> {
        check_text(text)?;
        let Some(rest) = text.strip_prefix("https:") else {
            return Err(UrlError::NotHttps);
        };
        let rest = rest.strip_prefix("//").ok_or(UrlError::MissingAuthority)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let origin = parse_authority(authority)?;
        let (path, query) = parse_tail(tail)?;
        Ok(Self {
            origin,
            path,
            query,
        })
    }

    /// The origin.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The canonical path: never empty, always starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query, without its `?`, if the URL has one.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The HTTP/1.1 request target: the path and, if present, `?` and the
    /// query (RFC 9112 §3.2.1, origin form).
    #[must_use]
    pub fn request_target(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }

    /// The canonical text: scheme, host, explicit port, path and query.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}{}", self.origin, self.request_target())
    }

    /// Resolve an RFC 3986 reference — a redirect's `Location` — against this
    /// URL, then parse the result by the same rules.
    ///
    /// A reference with a scheme is absolute; one starting `//` takes this
    /// URL's scheme; one starting `/` keeps this origin; one starting `?`
    /// keeps this path; any other relative path is merged with this URL's
    /// directory. A dot segment is refused, never removed, wherever it ends up.
    ///
    /// # Errors
    ///
    /// The first [`UrlError`] the reference or the result meets.
    pub fn resolve(&self, reference: &str) -> Result<Self, UrlError> {
        check_text(reference)?;
        if reference.contains('#') {
            return Err(UrlError::Fragment);
        }
        if reference.starts_with("//") {
            return Self::parse(&format!("https:{reference}"));
        }
        if has_scheme(reference) {
            return Self::parse(reference);
        }
        let joined = if reference.starts_with('/') {
            format!("{}{reference}", self.origin)
        } else if reference.starts_with('?') {
            format!("{}{}{reference}", self.origin, self.path)
        } else {
            let directory = self
                .path
                .rfind('/')
                .and_then(|slash| self.path.get(..=slash))
                .unwrap_or("/");
            format!("{}{directory}{reference}", self.origin)
        };
        Self::parse(&joined)
    }
}

impl fmt::Display for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Length and byte checks every URL and reference passes first.
fn check_text(text: &str) -> Result<(), UrlError> {
    if text.is_empty() {
        return Err(UrlError::Empty);
    }
    if text.len() > MAX_URL_BYTES {
        return Err(UrlError::TooLong);
    }
    if !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(UrlError::NotVisibleAscii);
    }
    Ok(())
}

/// Whether a reference begins with an RFC 3986 scheme: a letter, then
/// letters, digits, `+`, `-` or `.`, then `:` — before any `/`, `?` or `#`.
fn has_scheme(reference: &str) -> bool {
    let Some(colon) = reference.find(':') else {
        return false;
    };
    let Some(scheme) = reference.get(..colon) else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn check_host(host: &str) -> Result<(), UrlError> {
    if host.starts_with('[') {
        return Err(UrlError::AddressLiteral);
    }
    if !is_host(host) {
        return Err(UrlError::Host);
    }
    if is_address_literal(host) {
        return Err(UrlError::AddressLiteral);
    }
    Ok(())
}

fn parse_authority(authority: &str) -> Result<Origin, UrlError> {
    if authority.is_empty() {
        return Err(UrlError::MissingAuthority);
    }
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }
    let (host, port) = match authority.split_once(':') {
        None => (authority, HTTPS_DEFAULT_PORT),
        Some((host, port)) => {
            check_host(host)?;
            (host, parse_port(port)?)
        }
    };
    Origin::new(host, port)
}

/// A strict decimal port: 1 to 5 digits, no leading zero, 1–65535.
fn parse_port(text: &str) -> Result<u16, UrlError> {
    if text.is_empty()
        || text.len() > 5
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(UrlError::Port);
    }
    text.parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or(UrlError::Port)
}

fn parse_tail(tail: &str) -> Result<(String, Option<String>), UrlError> {
    if tail.contains('#') {
        return Err(UrlError::Fragment);
    }
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (tail, None),
    };
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        canonical_path(path)?
    };
    let query = query.map(canonical_query).transpose()?;
    Ok((path, query))
}

/// RFC 3986 `unreserved` and `sub-delims`, plus `:` and `@`: a `pchar`
/// without its percent escapes.
const fn is_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

/// Copy `text`, checking each byte with `allowed` and each escape, and
/// writing escapes in uppercase. `controls` refuses an escaped control byte
/// (`%00`–`%1F`, `%7F`); `%00` is refused in every case.
fn canonical_escapes(
    text: &str,
    allowed: fn(u8) -> bool,
    controls: bool,
    refusal: UrlError,
) -> Result<String, UrlError> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    while let Some(&b) = bytes.get(index) {
        if b == b'%' {
            let (Some(&high), Some(&low)) = (bytes.get(index + 1), bytes.get(index + 2)) else {
                return Err(UrlError::PercentEncoding);
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return Err(UrlError::PercentEncoding);
            }
            let (high, low) = (high.to_ascii_uppercase(), low.to_ascii_uppercase());
            let value = hex_value(high) * 16 + hex_value(low);
            if value == 0 || (controls && (value < 0x20 || value == 0x7f)) {
                return Err(UrlError::PercentEncoding);
            }
            out.push('%');
            out.push(char::from(high));
            out.push(char::from(low));
            index += 3;
        } else if allowed(b) {
            out.push(char::from(b));
            index += 1;
        } else {
            return Err(refusal);
        }
    }
    Ok(out)
}

const fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

fn canonical_path(path: &str) -> Result<String, UrlError> {
    if !path.starts_with('/') {
        return Err(UrlError::Path);
    }
    let canonical = canonical_escapes(path, |b| is_pchar(b) || b == b'/', true, UrlError::Path)?;
    for segment in canonical.split('/') {
        // `%2E` is the only escape that can spell a dot; the escapes are
        // already uppercase.
        let dots = segment.replace("%2E", ".");
        if dots == "." || dots == ".." {
            return Err(UrlError::DotSegment);
        }
    }
    Ok(canonical)
}

fn canonical_query(query: &str) -> Result<String, UrlError> {
    canonical_escapes(
        query,
        |b| is_pchar(b) || b == b'/' || b == b'?',
        false,
        UrlError::Query,
    )
}

#[cfg(test)]
mod tests {
    use super::{HttpsUrl, MAX_URL_BYTES, Origin, UrlError};

    fn canonical(text: &str) -> Result<String, UrlError> {
        HttpsUrl::parse(text).map(|url| url.canonical())
    }

    #[test]
    fn canonical_vectors() {
        for (input, expected) in [
            ("https://api.example.com", "https://api.example.com:443/"),
            ("https://api.example.com/", "https://api.example.com:443/"),
            (
                "https://api.example.com:443/v1",
                "https://api.example.com:443/v1",
            ),
            (
                "https://api.example.com:8443/a/b",
                "https://api.example.com:8443/a/b",
            ),
            ("https://a.b/x?q=1&r=2", "https://a.b:443/x?q=1&r=2"),
            ("https://a.b?q", "https://a.b:443/?q"),
            ("https://a.b/x?", "https://a.b:443/x?"),
            ("https://a.b/%7euser", "https://a.b:443/%7Euser"),
            ("https://a.b/p?x=%0a", "https://a.b:443/p?x=%0A"),
            (
                "https://a.b/a:b@c!$&'()*+,;=",
                "https://a.b:443/a:b@c!$&'()*+,;=",
            ),
            (
                "https://xn--bcher-kva.example/",
                "https://xn--bcher-kva.example:443/",
            ),
            ("https://a.b/x//y", "https://a.b:443/x//y"),
            ("https://a.b/x?y=/z?w", "https://a.b:443/x?y=/z?w"),
        ] {
            assert_eq!(canonical(input).as_deref(), Ok(expected), "{input}");
        }
        let url = HttpsUrl::parse("https://a.b:444/p?q").unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(
            url.origin(),
            &Origin::new("a.b", 444).unwrap_or_else(|e| unreachable!("{e:?}"))
        );
        assert_eq!(url.request_target(), "/p?q");
        assert_eq!(url.origin().to_string(), "https://a.b:444");
    }

    #[test]
    fn hostile_and_ambiguous_urls_are_refused() {
        let long = format!("https://a.b/{}", "x".repeat(MAX_URL_BYTES));
        for (input, error) in [
            ("", UrlError::Empty),
            (long.as_str(), UrlError::TooLong),
            ("https://a.b/ x", UrlError::NotVisibleAscii),
            ("https://a.b/\u{e9}", UrlError::NotVisibleAscii),
            ("https://a.b/\r\nHost: evil", UrlError::NotVisibleAscii),
            ("https://a.b\t/", UrlError::NotVisibleAscii),
            ("http://a.b/", UrlError::NotHttps),
            ("HTTPS://a.b/", UrlError::NotHttps),
            ("Https://a.b/", UrlError::NotHttps),
            ("ftp://a.b/", UrlError::NotHttps),
            ("javascript:alert(1)", UrlError::NotHttps),
            ("//a.b/", UrlError::NotHttps),
            ("https:a.b/", UrlError::MissingAuthority),
            ("https:/a.b/", UrlError::MissingAuthority),
            ("https:///x", UrlError::MissingAuthority),
            ("https://user@a.b/", UrlError::Userinfo),
            ("https://user:pass@a.b/", UrlError::Userinfo),
            ("https://a.b@evil.test/", UrlError::Userinfo),
            ("https://@a.b/", UrlError::Userinfo),
            ("https://A.b/", UrlError::Host),
            ("https://a.b./", UrlError::Host),
            ("https://.a.b/", UrlError::Host),
            ("https://a..b/", UrlError::Host),
            ("https://a_b.c/", UrlError::Host),
            ("https://a%2eb/", UrlError::Host),
            ("https://a.b\\evil.test/", UrlError::Host),
            ("https://127.0.0.1/", UrlError::AddressLiteral),
            ("https://2130706433/", UrlError::AddressLiteral),
            ("https://0x7f000001/", UrlError::AddressLiteral),
            ("https://0177.0.0.1/", UrlError::AddressLiteral),
            ("https://127.1/", UrlError::AddressLiteral),
            ("https://[::1]/", UrlError::AddressLiteral),
            ("https://[::ffff:127.0.0.1]:443/", UrlError::AddressLiteral),
            ("https://a.b:/", UrlError::Port),
            ("https://a.b:0/", UrlError::Port),
            ("https://a.b:0443/", UrlError::Port),
            ("https://a.b:65536/", UrlError::Port),
            ("https://a.b:443:443/", UrlError::Port),
            ("https://a.b:+443/", UrlError::Port),
            ("https://a.b:44a/", UrlError::Port),
            ("https://a.b/x<y", UrlError::Path),
            ("https://a.b/x\\y", UrlError::Path),
            ("https://a.b/x\"y", UrlError::Path),
            ("https://a.b/x{y}", UrlError::Path),
            ("https://a.b/x|y", UrlError::Path),
            ("https://a.b/[x]", UrlError::Path),
            ("https://a.b/x/./y", UrlError::DotSegment),
            ("https://a.b/x/../y", UrlError::DotSegment),
            ("https://a.b/..", UrlError::DotSegment),
            ("https://a.b/x/%2e%2e/y", UrlError::DotSegment),
            ("https://a.b/x/.%2E/y", UrlError::DotSegment),
            ("https://a.b/%2e", UrlError::DotSegment),
            ("https://a.b/%zz", UrlError::PercentEncoding),
            ("https://a.b/%4", UrlError::PercentEncoding),
            ("https://a.b/%", UrlError::PercentEncoding),
            ("https://a.b/x%00y", UrlError::PercentEncoding),
            ("https://a.b/x%0d%0aHost:evil", UrlError::PercentEncoding),
            ("https://a.b/x%7f", UrlError::PercentEncoding),
            ("https://a.b/x?y=%00", UrlError::PercentEncoding),
            ("https://a.b/x?y=<z>", UrlError::Query),
            ("https://a.b/x?y=a\\b", UrlError::Query),
            ("https://a.b/x#frag", UrlError::Fragment),
            ("https://a.b#frag", UrlError::Fragment),
        ] {
            assert_eq!(canonical(input), Err(error), "{input:?}");
        }
    }

    #[test]
    fn locations_resolve_against_the_hop_and_are_parsed_again() {
        let base = HttpsUrl::parse("https://api.example.com/v1/items/list?page=2")
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        for (reference, expected) in [
            ("https://other.example/x", "https://other.example:443/x"),
            ("//other.example:8443/y", "https://other.example:8443/y"),
            ("/root?a=b", "https://api.example.com:443/root?a=b"),
            (
                "?page=3",
                "https://api.example.com:443/v1/items/list?page=3",
            ),
            ("next", "https://api.example.com:443/v1/items/next"),
            (
                "sub/next?x",
                "https://api.example.com:443/v1/items/sub/next?x",
            ),
        ] {
            assert_eq!(
                base.resolve(reference).map(|u| u.canonical()).as_deref(),
                Ok(expected),
                "{reference}"
            );
        }
        for (reference, error) in [
            ("", UrlError::Empty),
            ("http://api.example.com/", UrlError::NotHttps),
            ("javascript:alert(1)", UrlError::NotHttps),
            ("data:text/html,x", UrlError::NotHttps),
            ("file:///etc/passwd", UrlError::NotHttps),
            ("HTTPS://api.example.com/", UrlError::NotHttps),
            ("https://127.0.0.1/", UrlError::AddressLiteral),
            ("//169.254.169.254/latest", UrlError::AddressLiteral),
            ("https://user@api.example.com/", UrlError::Userinfo),
            ("../escape", UrlError::DotSegment),
            ("./here", UrlError::DotSegment),
            ("/a/%2e%2e/b", UrlError::DotSegment),
            ("/x#frag", UrlError::Fragment),
            ("/x y", UrlError::NotVisibleAscii),
            ("/\\evil.test", UrlError::Path),
            ("\\\\evil.test", UrlError::Path),
        ] {
            assert_eq!(base.resolve(reference), Err(error), "{reference:?}");
        }
    }

    #[test]
    fn origins_compare_by_host_and_port() {
        let a = HttpsUrl::parse("https://a.b/x").unwrap_or_else(|e| unreachable!("{e:?}"));
        let b = HttpsUrl::parse("https://a.b:443/y?z").unwrap_or_else(|e| unreachable!("{e:?}"));
        let c = HttpsUrl::parse("https://a.b:8443/x").unwrap_or_else(|e| unreachable!("{e:?}"));
        let d = HttpsUrl::parse("https://x.a.b/x").unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(a.origin(), b.origin());
        assert_ne!(a.origin(), c.origin());
        assert_ne!(a.origin(), d.origin());
        assert_eq!(Origin::new("a.b", 0), Err(UrlError::Port));
        assert_eq!(Origin::new("10.0.0.1", 443), Err(UrlError::AddressLiteral));
    }
}
