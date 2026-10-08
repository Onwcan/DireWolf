//! The one place a credential header is composed (TX045; ADR-0050 §8,
//! ADR-0046 §12): `name: prefix value`, from the operator's header and prefix
//! the authorisation names and the value in the one descriptor it carries.
//!
//! The value is read once from the pipe into a `Zeroizing` buffer
//! (`crate::secret::read_value`), checked — no CR, LF or NUL, and nothing a
//! header value cannot hold — and composed into another `Zeroizing` buffer
//! sized once, so it never reallocates. That buffer becomes the header value
//! **without a copy**: a `Bytes` whose owner is the buffer, so the composed
//! header lives in exactly one place, which is scrubbed when the request that
//! holds it is dropped at the end of the exchange. The header is marked
//! sensitive, so no `Debug` rendering of the request shows it.
//!
//! The value read from the pipe is moved, not copied, into the hop's
//! [`Needle`]: the response to this hop is redacted of it in the broker
//! (D11, ADR-0050 §8), and it is zeroed when the exchange ends.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use bytes::Bytes;
use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::http::HttpCredential;
use ureq_proto::http::{HeaderName, HeaderValue};
use zeroize::Zeroizing;

use crate::secret::Needle;

/// A hop's credential: its header, and the needle its response is redacted
/// with.
pub(crate) struct Credential {
    pub(crate) name: HeaderName,
    pub(crate) value: HeaderValue,
    pub(crate) needle: Arc<Needle>,
}

/// A buffer that is scrubbed when the last `Bytes` over it is dropped.
struct Scrubbed(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Scrubbed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Compose the credential header for `credential` from the value in `fd`.
///
/// # Errors
///
/// The descriptor is not a closed pipe holding 1 to 32 KiB
/// (`SECRET_DESCRIPTOR`, `SECRET_EMPTY`, `SECRET_TOO_LARGE`), or the value
/// cannot be carried in a header (`SECRET_UNSAFE_BYTES`). Every buffer that
/// held the value is scrubbed before this returns an error.
pub(crate) fn credential_header(
    credential: &HttpCredential,
    fd: &OwnedFd,
) -> Result<Credential, BrokerRefusal> {
    let value = crate::secret::read_value(fd)?;
    crate::crash::point("http_credential_after_read");
    if value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(BrokerRefusal::SecretUnsafeBytes);
    }
    let name = HeaderName::from_bytes(credential.header_name.as_str().as_bytes())
        .map_err(|_| BrokerRefusal::HttpRequestInvalid)?;
    let prefix = credential
        .header_prefix
        .as_ref()
        .map_or(&b""[..], |p| p.as_str().as_bytes());
    let mut composed = Zeroizing::new(Vec::with_capacity(prefix.len().saturating_add(value.len())));
    composed.extend_from_slice(prefix);
    composed.extend_from_slice(&value);
    // Visible ASCII and spaces, like every other header this client sends,
    // and no space at either end: one spelling, nothing to fold.
    let spelled = composed.iter().all(|b| *b == b' ' || b.is_ascii_graphic())
        && composed.first().is_some_and(|b| *b != b' ')
        && composed.last().is_some_and(|b| *b != b' ');
    if !spelled {
        return Err(BrokerRefusal::SecretUnsafeBytes);
    }
    let needle = Needle::new(value, &credential.handle).ok_or(BrokerRefusal::SecretEmpty)?;
    let mut header = HeaderValue::from_maybe_shared(Bytes::from_owner(Scrubbed(composed)))
        .map_err(|_| BrokerRefusal::SecretUnsafeBytes)?;
    header.set_sensitive(true);
    Ok(Credential {
        name,
        value: header,
        needle,
    })
}
