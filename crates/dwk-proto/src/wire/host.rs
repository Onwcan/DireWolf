//! A DNS host, as DireWolf spells it: the one implementation of a host's
//! canonical form, shared by the authority's capability grammar
//! (`network.https:<host>:<port>`, CAPABILITIES.md) and the broker's egress
//! proxy (M5b, ADR-0048), so a granted host, a CONNECT target and a TLS
//! server name are compared in exactly one spelling, byte for byte.
//!
//! * A **label** is 1 to 63 bytes of `[a-z0-9-]`, not starting or ending with
//!   `-`. Uppercase is **refused, not folded**: DNS is case-insensitive, so
//!   folding would be defensible, but a scope with two spellings has two
//!   canonical forms, and no comparison may depend on a normalisation step
//!   being remembered.
//! * A **host** is 1 to [`MAX_LABELS`] labels joined by `.`, at most
//!   [`MAX_HOST_BYTES`] bytes. An empty label is refused, so a trailing dot,
//!   a leading dot and `a..b` are all refused rather than stripped.
//! * There is **no Unicode**. A U-label is refused, and an A-label
//!   (`xn--…`) is compared as the bytes it is: the protocol depends on no
//!   Unicode database (ADR-0034), so IDNA mapping and mixed-script confusable
//!   detection are not performed here. A confusable A-label is an A-label
//!   like any other; only an exact, granted spelling is ever reachable.
//!
//! Pure functions over text, and nothing else: no resolution, no I/O.

/// The longest label, per RFC 1035.
pub const MAX_LABEL_BYTES: usize = 63;

/// The most labels a host may have.
pub const MAX_LABELS: usize = 16;

/// The longest host, per RFC 1035's 255-byte name less its framing.
pub const MAX_HOST_BYTES: usize = 253;

/// Whether `text` is one label: lowercase alphanumerics and hyphens, not
/// starting or ending with a hyphen, 1 to [`MAX_LABEL_BYTES`] bytes.
#[must_use]
pub fn is_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LABEL_BYTES
        && !text.starts_with('-')
        && !text.ends_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `text` is a host in canonical form: labels per [`is_label`],
/// joined by single dots, within [`MAX_LABELS`] and [`MAX_HOST_BYTES`].
#[must_use]
pub fn is_host(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_HOST_BYTES {
        return false;
    }
    let mut labels = 0usize;
    for label in text.split('.') {
        labels += 1;
        if labels > MAX_LABELS || !is_label(label) {
            return false;
        }
    }
    true
}

/// Whether `host` (canonical) is spelled like an address rather than a name:
/// its last label is all digits, or `0x` and hex digits — the WHATWG URL
/// standard's "ends in a number", and what a C resolver's `inet_aton` reads
/// as IPv4 (`10.0.0.1`, `2130706433`, `0x7f000001`, `1.0x1`). No top-level
/// domain is all-numeric (RFC 3696 §2) or starts `0x` followed only by hex
/// digits, so such a host is a literal, which a TLS client never sends as a
/// server name and which the egress proxy therefore refuses rather than
/// resolves.
#[must_use]
pub fn is_address_literal(host: &str) -> bool {
    host.rsplit('.').next().is_some_and(|last| {
        let decimal = !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit());
        let hex = last
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
        decimal || hex
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_HOST_BYTES, is_address_literal, is_host, is_label};

    #[test]
    fn labels_are_lowercase_ldh_and_bounded() {
        for good in ["a", "api", "xn--bcher-kva", "a-b", "0", "9z"] {
            assert!(is_label(good), "{good}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "API",
            "Api",
            "a_b",
            "a b",
            "a.b",
            "bücher",
            "a\u{0}",
            "a\r",
            &"a".repeat(64),
        ] {
            assert!(!is_label(bad), "{bad:?}");
        }
    }

    #[test]
    fn hosts_have_one_spelling() {
        for good in [
            "api.github.com",
            "a.b",
            "localhost",
            "xn--bcher-kva.example",
        ] {
            assert!(is_host(good), "{good}");
        }
        let long = format!("{}.com", "a".repeat(250));
        for bad in [
            "",
            ".",
            "example.com.",
            ".example.com",
            "a..b",
            "API.github.com",
            "api.github.com:443",
            "[::1]",
            "user@host",
            "host/path",
            "*.example.com",
            long.as_str(),
            "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q",
        ] {
            assert!(!is_host(bad), "{bad:?}");
        }
        assert!(is_host(&format!("{}.b", "a".repeat(63))));
        assert!(format!("{}.com", "a".repeat(250)).len() > MAX_HOST_BYTES);
    }

    #[test]
    fn an_all_numeric_last_label_is_an_address() {
        for literal in [
            "10.0.0.1",
            "127.1",
            "2130706433",
            "1.2.3.4",
            "0177.0.0.1",
            "0x7f000001",
            "0x7f.0.0.1",
            "1.0x1",
            "0x",
            "a.0xff",
        ] {
            assert!(is_host(literal), "{literal}");
            assert!(is_address_literal(literal), "{literal}");
        }
        for name in [
            "example.com",
            "a1.b2",
            "1.example",
            "x10",
            "0x7f.example",
            "0xg",
            "a.0xfg",
            "x0x1",
        ] {
            assert!(!is_address_literal(name), "{name}");
        }
    }
}
