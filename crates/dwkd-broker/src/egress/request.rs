//! The CONNECT request (M5b, ADR-0048): one request line and its headers,
//! read as hostile, bounded, and accepted only in its one strict form.
//!
//! ```text
//! CONNECT <host>:<port> HTTP/1.1\r\n
//! <Name>: <value>\r\n          (at most REQUEST_MAX_HEADERS)
//! \r\n
//! ```
//!
//! * The request line is exactly three words separated by single spaces; the
//!   method is exactly `CONNECT`; the version `HTTP/1.1` or `HTTP/1.0`.
//! * The target is `host:port`: a canonical host (`dwk_proto::wire::host`) —
//!   never userinfo, a bracketed address, an address literal, uppercase or a
//!   trailing dot — and a port of 1 to 5 digits, 1–65535, no leading zero.
//! * Every line ends `\r\n`; a bare `\r` or `\n`, a NUL or any other control
//!   byte, a non-ASCII byte, a folded header or a header name that is not a
//!   token is malformed.
//! * A request that names a body (`Content-Length`, `Transfer-Encoding`) is
//!   malformed: a CONNECT has none, and one that claimed one would be a second
//!   request smuggled behind the first. A `Host` header, if present, must be
//!   the target exactly, and there may be at most one.
//! * Bytes after the blank line are the tunnel's first bytes, never another
//!   request: there is exactly one request per connection.

use dwk_proto::brokerp::egress::EgressDisposition;
use dwk_proto::wire::host;

use super::{REQUEST_MAX_BYTES, REQUEST_MAX_HEADERS};

/// What a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The canonical host.
    pub(crate) host: String,
    /// The port.
    pub(crate) port: u16,
}

/// The parse of what has arrived so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// Not the whole request yet, and nothing wrong so far.
    Need,
    /// The request, and how many bytes it was: what follows is the tunnel's.
    Done {
        /// The target.
        target: Target,
        /// The request's length, its blank line included.
        consumed: usize,
    },
}

/// A token character (RFC 9110 §5.6.2).
const fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
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

/// A port: 1 to 5 digits, no leading zero, 1–65535.
fn port(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse::<u16>().ok().filter(|p| *p != 0)
}

/// The target, from the request line's middle word.
fn target(authority: &str) -> Result<Target, EgressDisposition> {
    let refused = EgressDisposition::TargetNotCanonical;
    if authority.contains('@') || authority.starts_with('[') {
        return Err(refused);
    }
    let (name, number) = authority.split_once(':').ok_or(refused)?;
    if number.contains(':') || !host::is_host(name) || host::is_address_literal(name) {
        return Err(refused);
    }
    let port = port(number).ok_or(refused)?;
    Ok(Target {
        host: name.to_owned(),
        port,
    })
}

/// Parse what has arrived.
///
/// # Errors
///
/// The disposition of a request that is not, and cannot become, the one
/// strict form: nothing more is read once one is found.
pub(crate) fn parse(bytes: &[u8]) -> Result<Parsed, EgressDisposition> {
    let malformed = EgressDisposition::Malformed;
    // Bytes that are wrong however the request ends are refused at once,
    // not after the bound is filled.
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let head = match end {
        Some(at) => bytes.get(..at).ok_or(malformed)?,
        None => bytes,
    };
    // A `\r` that ends what has arrived may yet be followed by its `\n`; one
    // that ends a complete head is followed by the blank line's `\r`.
    let complete = end.is_some();
    for (i, b) in head.iter().enumerate() {
        let last = i + 1 == head.len();
        let lone_cr = *b == b'\r' && head.get(i + 1) != Some(&b'\n') && (complete || !last);
        let lone_lf = *b == b'\n' && (i == 0 || head.get(i - 1) != Some(&b'\r'));
        let control = b.is_ascii_control() && !matches!(b, b'\r' | b'\n' | b'\t');
        if lone_cr || lone_lf || control || !b.is_ascii() {
            return Err(malformed);
        }
    }
    let Some(at) = end else {
        return if bytes.len() >= REQUEST_MAX_BYTES {
            Err(malformed)
        } else {
            Ok(Parsed::Need)
        };
    };
    let consumed = at + 4;
    if consumed > REQUEST_MAX_BYTES {
        return Err(malformed);
    }
    let text = core::str::from_utf8(head).map_err(|_| malformed)?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or(malformed)?;
    if line.contains('\t') {
        return Err(malformed);
    }
    let words: Vec<&str> = line.split(' ').collect();
    let [method, authority, version] = words.as_slice() else {
        return Err(malformed);
    };
    if *method != "CONNECT" {
        // A different method, well-formed: said so; anything else, malformed.
        return Err(if !method.is_empty() && method.bytes().all(tchar) {
            EgressDisposition::NotConnect
        } else {
            malformed
        });
    }
    if *version != "HTTP/1.1" && *version != "HTTP/1.0" {
        return Err(malformed);
    }
    let target = target(authority)?;
    let mut headers = 0usize;
    let mut host_seen = false;
    for line in lines {
        headers += 1;
        if headers > REQUEST_MAX_HEADERS {
            return Err(malformed);
        }
        // Folding (a continuation line) is obsolete and ambiguous.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(malformed);
        }
        let (name, value) = line.split_once(':').ok_or(malformed)?;
        if name.is_empty() || !name.bytes().all(tchar) {
            return Err(malformed);
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            "content-length" | "transfer-encoding" => return Err(malformed),
            "host" => {
                if host_seen || value != *authority {
                    return Err(malformed);
                }
                host_seen = true;
            }
            _ => {}
        }
    }
    Ok(Parsed::Done { target, consumed })
}

#[cfg(test)]
mod tests {
    use dwk_proto::brokerp::egress::EgressDisposition as D;

    use super::{Parsed, REQUEST_MAX_BYTES, REQUEST_MAX_HEADERS, Target, parse};

    fn done(host: &str, port: u16, consumed: usize) -> Parsed {
        Parsed::Done {
            target: Target {
                host: host.to_owned(),
                port,
            },
            consumed,
        }
    }

    #[test]
    fn the_one_strict_form_is_accepted() {
        let r = b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\nUser-Agent: pip\r\n\r\n";
        assert_eq!(parse(r), Ok(done("pypi.org", 443, r.len())));
        let bare = b"CONNECT pypi.org:443 HTTP/1.0\r\n\r\n";
        assert_eq!(parse(bare), Ok(done("pypi.org", 443, bare.len())));
        // What follows the blank line is the tunnel's, not a second request.
        let mut early = bare.to_vec();
        early.extend_from_slice(b"\x16\x03\x01");
        assert_eq!(parse(&early), Ok(done("pypi.org", 443, bare.len())));
    }

    #[test]
    fn a_partial_request_waits_and_an_oversized_one_is_refused() {
        assert_eq!(parse(b"CONNECT pypi.org:4"), Ok(Parsed::Need));
        assert_eq!(parse(b""), Ok(Parsed::Need));
        let mut long = b"CONNECT pypi.org:443 HTTP/1.1\r\nX: ".to_vec();
        long.resize(REQUEST_MAX_BYTES, b'a');
        assert_eq!(parse(&long), Err(D::Malformed));
        let mut many = b"CONNECT pypi.org:443 HTTP/1.1\r\n".to_vec();
        for i in 0..=REQUEST_MAX_HEADERS {
            many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(parse(&many), Err(D::Malformed));
    }

    #[test]
    fn methods_and_request_lines_have_one_spelling() {
        for (bad, why) in [
            (&b"GET / HTTP/1.1\r\n\r\n"[..], D::NotConnect),
            (b"POST pypi.org:443 HTTP/1.1\r\n\r\n", D::NotConnect),
            (b"connect pypi.org:443 HTTP/1.1\r\n\r\n", D::NotConnect),
            (b"CONNECT  pypi.org:443 HTTP/1.1\r\n\r\n", D::Malformed),
            (b"CONNECT\tpypi.org:443 HTTP/1.1\r\n\r\n", D::Malformed),
            (b"CONNECT pypi.org:443 HTTP/2\r\n\r\n", D::Malformed),
            (b"CONNECT pypi.org:443\r\n\r\n", D::Malformed),
            (b"CONNECT pypi.org:443 HTTP/1.1 extra\r\n\r\n", D::Malformed),
            (b" CONNECT pypi.org:443 HTTP/1.1\r\n\r\n", D::Malformed),
            (b"\r\n\r\n", D::Malformed),
        ] {
            assert_eq!(parse(bad), Err(why), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_target_is_a_canonical_host_and_a_strict_port() {
        for target in [
            "PyPI.org:443",
            "pypi.org.:443",
            "user@pypi.org:443",
            "user:pass@pypi.org:443",
            "[::1]:443",
            "[2001:db8::1]:443",
            "10.0.0.1:443",
            "2130706433:443",
            "0x7f000001:443",
            "0177.0.0.1:443",
            "pypi.0x1:443",
            "pypi.org",
            "pypi.org:",
            ":443",
            "pypi.org:0",
            "pypi.org:65536",
            "pypi.org:0443",
            "pypi.org:+443",
            "pypi.org:443:443",
            "pypi.org:44 3",
            "bücher.example:443",
            "*.pypi.org:443",
            "pypi..org:443",
        ] {
            let request = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            assert!(
                matches!(
                    parse(request.as_bytes()),
                    Err(D::TargetNotCanonical | D::Malformed)
                ),
                "{target}"
            );
        }
    }

    #[test]
    fn control_bytes_and_smuggled_bodies_are_refused() {
        for bad in [
            &b"CONNECT pypi.org:443 HTTP/1.1\nHost: pypi.org:443\r\n\r\n"[..],
            b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\rX: y\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: a\r\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: a\x00b\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: \x7f\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: \x1b[31m\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: caf\xc3\xa9\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\nHost: pypi.org:443\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nX: a\r\n folded\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nBad Name: v\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\nNoColon\r\n\r\n",
            b"CONNECT pypi.org:443 HTTP/1.1\r\n: v\r\n\r\n",
        ] {
            assert_eq!(
                parse(bad),
                Err(D::Malformed),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_second_request_line_is_only_ever_tunnel_bytes() {
        let first = b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n";
        let mut pipelined = first.to_vec();
        pipelined.extend_from_slice(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n");
        assert_eq!(parse(&pipelined), Ok(done("pypi.org", 443, first.len())));
    }
}
