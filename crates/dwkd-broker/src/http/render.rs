//! The one place a credential header is composed (TX045; ADR-0050 §8,
//! ADR-0046 §12): `name: prefix value`, from the operator's header and prefix
//! the authorisation names and the value in the one descriptor it carries.
//!
//! **Two halves, two processes (D11).** The broker reads the value once from
//! the authority's one-shot pipe ([`hand_on`]), refuses a byte a header cannot
//! carry, and puts it in a fresh pipe of its own for the hop's exchange worker
//! (`super::worker`) -- as M4d's launch helper is handed a mode B value -- and
//! its copy is zeroed. The worker reads that pipe once and composes the header
//! ([`credential_header`]); the long-lived broker never holds the header, the
//! request or any byte of the response.
//!
//! Every buffer that holds the value is `Zeroizing`, sized once so it never
//! reallocates. The composed header becomes the header value **without a
//! copy**: a `Bytes` whose owner is the buffer, so it lives in exactly one
//! place, which is scrubbed when the request that holds it is dropped. The
//! header is marked sensitive, so no `Debug` rendering of the request shows
//! it. The value itself is moved, not copied, into the hop's [`Needle`]: the
//! response is redacted of it (ADR-0050 §8), and it is zeroed when the
//! exchange ends.

use std::io::Write as _;
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

/// The operator's prefix, as bytes; empty when there is none.
fn prefix(credential: &HttpCredential) -> &[u8] {
    credential
        .header_prefix
        .as_ref()
        .map_or(&b""[..], |p| p.as_str().as_bytes())
}

/// Whether `prefix value` is a header value in its one spelling: visible
/// ASCII and spaces, like every other header this client sends, no CR, LF or
/// NUL, and no space at either end -- nothing to fold.
fn spelled(prefix: &[u8], value: &[u8]) -> bool {
    let all = || prefix.iter().chain(value);
    all().all(|b| *b == b' ' || b.is_ascii_graphic())
        && all().next().is_some_and(|b| *b != b' ')
        && all().last().is_some_and(|b| *b != b' ')
}

/// The broker's half: read the value once from the authority's pipe `fd`,
/// refuse it if it cannot be carried in `credential`'s header, and hand it on
/// in a fresh pipe, its writer closed -- the worker's one copy. The value
/// (at most 32 KiB) fits a pipe's buffer, so the write never waits.
///
/// # Errors
///
/// The descriptor is not a closed pipe holding 1 to 32 KiB
/// (`SECRET_DESCRIPTOR`, `SECRET_EMPTY`, `SECRET_TOO_LARGE`), or the value
/// cannot be carried in a header (`SECRET_UNSAFE_BYTES`). The buffer that held
/// the value is scrubbed whatever happens.
pub(crate) fn hand_on(credential: &HttpCredential, fd: &OwnedFd) -> Result<OwnedFd, BrokerRefusal> {
    let value = crate::secret::read_value(fd)?;
    crate::crash::point("http_credential_after_read");
    if !spelled(prefix(credential), &value) {
        return Err(BrokerRefusal::SecretUnsafeBytes);
    }
    // No spawn while the writer is open (`crate::process::fork_guard`).
    let _fork = crate::process::fork_guard();
    let (reader, mut writer) = std::io::pipe().map_err(|_| BrokerRefusal::SecretDescriptor)?;
    writer
        .write_all(&value)
        .map_err(|_| BrokerRefusal::SecretDescriptor)?;
    drop(writer);
    Ok(OwnedFd::from(reader))
}

/// The worker's half: compose the credential header for `credential` from
/// the value in `fd`.
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
    let prefix = prefix(credential);
    if !spelled(prefix, &value) {
        return Err(BrokerRefusal::SecretUnsafeBytes);
    }
    let name = HeaderName::from_bytes(credential.header_name.as_str().as_bytes())
        .map_err(|_| BrokerRefusal::HttpRequestInvalid)?;
    let mut composed = Zeroizing::new(Vec::with_capacity(prefix.len().saturating_add(value.len())));
    composed.extend_from_slice(prefix);
    composed.extend_from_slice(&value);
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
