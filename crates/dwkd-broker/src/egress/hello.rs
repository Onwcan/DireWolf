//! The TLS `ClientHello`'s server name (M5b, ADR-0048): read from the first
//! bytes of a granted tunnel, before any connection is made, and nothing else
//! of TLS is read at all.
//!
//! The hello may arrive in any number of records and reads; each record is
//! checked as it completes and its fragment appended, and what is buffered is
//! bounded ([`HELLO_MAX_BUFFERED`]) however small the fragments are:
//!
//! * every record is a handshake record (type 22), of TLS 1.0–1.2 framing,
//!   with a fragment of 1 to 2^14 bytes;
//! * the first handshake message is a `ClientHello` of at most
//!   [`HELLO_MAX_BYTES`], and the records that carry it carry nothing else;
//! * the hello parses exactly — every length agrees with what encloses it —
//!   and names each extension at most once;
//! * `server_name` holds exactly one `host_name` (none: `SNI_MISSING`; more:
//!   `SNI_AMBIGUOUS`), of at most 253 bytes;
//! * an `encrypted_client_hello` extension is refused (`ECH_REFUSED`): its
//!   outer name is not the name the inner hello is for.
//!
//! Whether the name is the CONNECT host is the tunnel's comparison, by bytes.

use std::collections::BTreeSet;

use dwk_proto::brokerp::egress::EgressDisposition;

use super::{HELLO_MAX_BUFFERED, HELLO_MAX_BYTES};

/// The record type of a handshake record.
const HANDSHAKE: u8 = 22;
/// The handshake type of a `ClientHello`.
const CLIENT_HELLO: u8 = 1;
/// The largest record fragment (RFC 8446 §5.1).
const RECORD_MAX: usize = 1 << 14;
/// The `server_name` extension (RFC 6066 §3).
const SERVER_NAME: u16 = 0;
/// The `encrypted_client_hello` extension.
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// The longest server name accepted: a DNS name's limit.
const NAME_MAX: usize = 253;

/// A bounds-checked reader over a byte string.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EgressDisposition> {
        let head = self
            .0
            .get(..n)
            .ok_or(EgressDisposition::ClientHelloMalformed)?;
        self.0 = self.0.get(n..).unwrap_or_default();
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, EgressDisposition> {
        let [b] = self.take(1)? else {
            return Err(EgressDisposition::ClientHelloMalformed);
        };
        Ok(*b)
    }

    fn u16(&mut self) -> Result<u16, EgressDisposition> {
        let [a, b] = self.take(2)? else {
            return Err(EgressDisposition::ClientHelloMalformed);
        };
        Ok(u16::from_be_bytes([*a, *b]))
    }

    fn u24(&mut self) -> Result<usize, EgressDisposition> {
        let [a, b, c] = self.take(3)? else {
            return Err(EgressDisposition::ClientHelloMalformed);
        };
        Ok((usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c))
    }

    const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The hello as it arrives.
#[derive(Debug, Default)]
pub(crate) struct Hello {
    /// Where the first record not yet read starts.
    end: usize,
    /// The handshake bytes the records read so far carried.
    handshake: Vec<u8>,
}

impl Hello {
    /// Read the records that have completed in `bytes` — everything the
    /// tunnel has received, from its first byte — and, once the hello is
    /// whole, return the one server name it carries.
    ///
    /// # Errors
    ///
    /// The disposition of a hello that is not, or cannot become, a strict
    /// `ClientHello` with exactly one server name and no ECH.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, EgressDisposition> {
        let malformed = EgressDisposition::ClientHelloMalformed;
        if bytes.len() > HELLO_MAX_BUFFERED {
            return Err(malformed);
        }
        loop {
            let mut rest = Cursor(bytes.get(self.end..).ok_or(malformed)?);
            if rest.0.len() < 5 {
                return Ok(None);
            }
            let kind = rest.u8()?;
            let version = rest.u16()?;
            let length = usize::from(rest.u16()?);
            if kind != HANDSHAKE
                || !(0x0301..=0x0303).contains(&version)
                || length == 0
                || length > RECORD_MAX
            {
                return Err(malformed);
            }
            if rest.0.len() < length {
                return Ok(None);
            }
            self.handshake.extend_from_slice(rest.take(length)?);
            self.end += 5 + length;
            let mut message = Cursor(&self.handshake);
            if message.0.len() < 4 {
                continue;
            }
            if message.u8()? != CLIENT_HELLO {
                return Err(malformed);
            }
            let declared = message.u24()?;
            if declared > HELLO_MAX_BYTES || message.0.len() > declared {
                // Too large, or the records carry more than the hello.
                return Err(malformed);
            }
            if message.0.len() == declared {
                return server_name(message.0).map(Some);
            }
        }
    }
}

/// The server name a whole `ClientHello` body carries (RFC 8446 §4.1.2).
fn server_name(body: &[u8]) -> Result<Vec<u8>, EgressDisposition> {
    let malformed = EgressDisposition::ClientHelloMalformed;
    let mut hello = Cursor(body);
    let version = hello.u16()?;
    if !(0x0301..=0x0303).contains(&version) {
        return Err(malformed);
    }
    hello.take(32)?;
    let session = usize::from(hello.u8()?);
    if session > 32 {
        return Err(malformed);
    }
    hello.take(session)?;
    let suites = usize::from(hello.u16()?);
    if suites < 2 || suites % 2 != 0 {
        return Err(malformed);
    }
    hello.take(suites)?;
    let compression = usize::from(hello.u8()?);
    if compression < 1 {
        return Err(malformed);
    }
    hello.take(compression)?;
    if hello.is_empty() {
        // No extensions at all: no name.
        return Err(EgressDisposition::SniMissing);
    }
    let length = usize::from(hello.u16()?);
    let mut extensions = Cursor(hello.take(length)?);
    if !hello.is_empty() {
        return Err(malformed);
    }
    let mut seen = BTreeSet::new();
    let mut name = None;
    let mut ech = false;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let length = usize::from(extensions.u16()?);
        let data = extensions.take(length)?;
        if !seen.insert(kind) {
            return Err(malformed);
        }
        match kind {
            SERVER_NAME => name = Some(host_name(data)?),
            ENCRYPTED_CLIENT_HELLO => ech = true,
            _ => {}
        }
    }
    if ech {
        return Err(EgressDisposition::EchRefused);
    }
    name.ok_or(EgressDisposition::SniMissing)
}

/// The one `host_name` a `server_name` extension carries (RFC 6066 §3).
fn host_name(data: &[u8]) -> Result<Vec<u8>, EgressDisposition> {
    let malformed = EgressDisposition::ClientHelloMalformed;
    let mut extension = Cursor(data);
    let length = usize::from(extension.u16()?);
    let mut list = Cursor(extension.take(length)?);
    if !extension.is_empty() || list.is_empty() {
        return Err(malformed);
    }
    let mut names = Vec::new();
    while !list.is_empty() {
        let kind = list.u8()?;
        let length = usize::from(list.u16()?);
        let name = list.take(length)?;
        if kind != 0 || name.is_empty() || name.len() > NAME_MAX {
            return Err(malformed);
        }
        names.push(name);
    }
    match names.as_slice() {
        [one] => Ok(one.to_vec()),
        [] => Err(EgressDisposition::SniMissing),
        _ => Err(EgressDisposition::SniAmbiguous),
    }
}

/// `ClientHello`s for tests, built field by field so each test can break
/// exactly one thing.
#[cfg(test)]
pub(crate) mod build {
    /// One extension.
    pub(crate) fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A `server_name` extension holding these `(type, name)` entries.
    pub(crate) fn server_name(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in entries {
            list.push(*kind);
            list.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
            list.extend_from_slice(name);
        }
        let mut data = u16::try_from(list.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        data.extend_from_slice(&list);
        extension(0, &data)
    }

    /// A `ClientHello` handshake message with these extensions.
    pub(crate) fn message(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);
        let all: Vec<u8> = extensions.concat();
        body.extend_from_slice(&u16::try_from(all.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&all);
        let length = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
        let mut out = vec![1];
        out.extend_from_slice(length.get(1..).unwrap_or_default());
        out.extend_from_slice(&body);
        out
    }

    /// `message` in handshake records of at most `fragment` bytes each.
    pub(crate) fn records(message: &[u8], fragment: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in message.chunks(fragment.max(1)) {
            out.extend_from_slice(&[22, 0x03, 0x01]);
            out.extend_from_slice(&u16::try_from(chunk.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    /// A hello naming `name`, in one record.
    pub(crate) fn hello(name: &str) -> Vec<u8> {
        records(
            &message(&[
                extension(0x000a, &[0x00, 0x02, 0x00, 0x1d]),
                server_name(&[(0, name.as_bytes())]),
                extension(0x002b, &[0x02, 0x03, 0x04]),
            ]),
            1 << 14,
        )
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use dwk_proto::brokerp::egress::EgressDisposition as D;

    use super::build::{extension, hello, message, records, server_name};
    use super::{HELLO_MAX_BUFFERED, HELLO_MAX_BYTES, Hello};

    fn whole(bytes: &[u8]) -> Result<Option<Vec<u8>>, D> {
        Hello::default().feed(bytes)
    }

    #[test]
    fn a_hello_with_one_name_yields_the_name() {
        assert_eq!(whole(&hello("pypi.org")), Ok(Some(b"pypi.org".to_vec())));
    }

    #[test]
    fn a_fragmented_hello_is_reassembled_byte_by_byte_and_record_by_record() {
        let message = message(&[server_name(&[(0, b"pypi.org")])]);
        for fragment in [1, 2, 7, 64, 1 << 14] {
            let bytes = records(&message, fragment);
            let mut hello = Hello::default();
            let mut got = None;
            for end in 1..=bytes.len() {
                match hello.feed(bytes.get(..end).unwrap_or_default()) {
                    Ok(None) => {}
                    Ok(Some(name)) => {
                        assert_eq!(end, bytes.len(), "{fragment}");
                        got = Some(name);
                    }
                    Err(e) => panic!("{fragment}: {e:?}"),
                }
            }
            assert_eq!(got, Some(b"pypi.org".to_vec()), "{fragment}");
        }
    }

    #[test]
    fn a_truncated_hello_never_completes() {
        let bytes = hello("pypi.org");
        for end in 0..bytes.len() {
            assert_eq!(
                whole(bytes.get(..end).unwrap_or_default()),
                Ok(None),
                "{end}"
            );
        }
    }

    #[test]
    fn missing_ambiguous_and_ech_names_are_refused() {
        let none = records(&message(&[extension(0x000a, &[0, 2, 0, 0x1d])]), 1 << 14);
        assert_eq!(whole(&none), Err(D::SniMissing));
        let no_extensions = {
            let mut m = message(&[]);
            // Drop the (empty) extension block's length too.
            m.truncate(m.len() - 2);
            let length = u32::try_from(m.len() - 4).unwrap_or(0).to_be_bytes();
            if let Some(field) = m.get_mut(1..4) {
                field.copy_from_slice(length.get(1..).unwrap_or_default());
            }
            records(&m, 1 << 14)
        };
        assert_eq!(whole(&no_extensions), Err(D::SniMissing));
        let two = records(
            &message(&[server_name(&[(0, b"pypi.org"), (0, b"evil.example")])]),
            1 << 14,
        );
        assert_eq!(whole(&two), Err(D::SniAmbiguous));
        let ech = records(
            &message(&[
                server_name(&[(0, b"pypi.org")]),
                extension(0xfe0d, &[0, 1, 2, 3]),
            ]),
            1 << 14,
        );
        assert_eq!(whole(&ech), Err(D::EchRefused));
    }

    #[test]
    fn duplicate_extensions_and_odd_name_entries_are_malformed() {
        for extensions in [
            vec![
                server_name(&[(0, b"pypi.org")]),
                server_name(&[(0, b"pypi.org")]),
            ],
            vec![server_name(&[(1, b"pypi.org")])],
            vec![server_name(&[(0, b"")])],
            vec![server_name(&[])],
            vec![server_name(&[(0, "a".repeat(254).as_bytes())])],
            vec![extension(0, &[0, 9, 0, 0, 3, b'a', b'b', b'c'])],
            vec![extension(0x000a, &[0, 2]), extension(0x000a, &[0, 2])],
        ] {
            let bytes = records(&message(&extensions), 1 << 14);
            assert_eq!(
                whole(&bytes),
                Err(D::ClientHelloMalformed),
                "{extensions:?}"
            );
        }
    }

    #[test]
    fn records_that_are_not_a_hello_are_malformed() {
        let good = hello("pypi.org");
        let mut wrong_type = good.clone();
        if let Some(b) = wrong_type.first_mut() {
            *b = 23;
        }
        let mut ssl3 = good.clone();
        if let Some(b) = ssl3.get_mut(2) {
            *b = 0;
        }
        let mut not_hello = good.clone();
        if let Some(b) = not_hello.get_mut(5) {
            *b = 2;
        }
        let empty_record = vec![22, 3, 1, 0, 0];
        let oversized_record = vec![22, 3, 1, 0x40, 0x01];
        let mut trailing = message(&[server_name(&[(0, b"pypi.org")])]);
        trailing.extend_from_slice(&[20, 0, 0, 0]);
        let trailing = records(&trailing, 1 << 14);
        for bad in [
            wrong_type,
            ssl3,
            not_hello,
            empty_record,
            oversized_record,
            trailing,
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        ] {
            assert_eq!(whole(&bad), Err(D::ClientHelloMalformed), "{bad:?}");
        }
    }

    #[test]
    fn an_overlong_hello_is_refused_before_it_is_buffered() {
        // A handshake that declares more than the bound.
        let declared = u32::try_from(HELLO_MAX_BYTES + 1)
            .unwrap_or(0)
            .to_be_bytes();
        let mut head = vec![1];
        head.extend_from_slice(declared.get(1..).unwrap_or_default());
        assert_eq!(
            whole(&records(&head, 1 << 14)),
            Err(D::ClientHelloMalformed)
        );
        // Tiny records: the buffer bound ends it, however it is fragmented.
        let message = message(&[
            server_name(&[(0, b"pypi.org")]),
            extension(0x0015, &vec![0; HELLO_MAX_BYTES - 200]),
        ]);
        let tiny = records(&message, 1);
        assert!(tiny.len() > HELLO_MAX_BUFFERED);
        assert_eq!(
            Hello::default().feed(tiny.get(..=HELLO_MAX_BUFFERED).unwrap_or_default()),
            Err(D::ClientHelloMalformed)
        );
    }

    #[test]
    fn length_fields_that_disagree_are_malformed() {
        let mut bytes = hello("pypi.org");
        // The session id length, made larger than its body.
        if let Some(b) = bytes.get_mut(5 + 4 + 2 + 32) {
            *b = 33;
        }
        assert_eq!(whole(&bytes), Err(D::ClientHelloMalformed));
    }
}
