//! The one-shot secret handoff (ADR-0046 §11): the value leaves the authority
//! as the read end of a pipe, never as a message field.
//!
//! [`one_shot`] creates a pipe (both ends close-on-exec), writes the whole
//! value into it, closes the write end, and **drops the material** — zeroing
//! the authority's copy — before anything is sent. What remains is a
//! [`SecretPipe`]: a descriptor holding the value and then end of file, which
//! the broker link sends by `SCM_RIGHTS` with exactly one authorisation on
//! exactly one channel. It cannot be sent twice (the link consumes it), read
//! by the authority again (nothing here reads it), or outlive the exchange
//! (the link's copy closes when the send returns).
//!
//! The value fits the pipe's buffer — 64 KiB on Linux, and a value is at most
//! [`MAX_SECRET_BYTES`] — so the write never waits for a reader.

#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::os::fd::OwnedFd;

use super::SecretError;
#[cfg(unix)]
use super::material::MAX_SECRET_BYTES;
use super::material::SecretMaterial;

/// What a [`SecretPipe`] holds: a descriptor on Unix; nothing that can exist
/// elsewhere, where the broker channel does not (ADR-0043).
#[cfg(unix)]
type Held = OwnedFd;
#[cfg(not(unix))]
type Held = core::convert::Infallible;

/// The read end of a pipe holding one value and then end of file.
#[derive(Debug)]
pub struct SecretPipe(Held);

#[cfg(unix)]
impl SecretPipe {
    /// Release the descriptor for the one send. Only the broker link calls
    /// this (TX014).
    #[must_use]
    pub(crate) fn into_transfer_descriptor(self) -> OwnedFd {
        self.0
    }
}

/// Whether `material` can be carried in an HTTP header value: no CR, LF or
/// NUL, which could end or split the header (ADR-0046 §12). Refused, never
/// sanitised.
pub(crate) fn header_safe(material: &SecretMaterial) -> bool {
    !material
        .expose()
        .iter()
        .any(|b| matches!(b, b'\r' | b'\n' | 0))
}

/// Put `material` in a fresh pipe and zero the authority's copy.
///
/// # Errors
///
/// [`SecretError::BackendUnavailable`] when the operating system gives no
/// pipe or refuses the write; nothing was sent, and the material is zeroed
/// either way.
#[cfg(unix)]
pub(crate) fn one_shot(material: SecretMaterial) -> Result<SecretPipe, SecretError> {
    if material.len() > MAX_SECRET_BYTES {
        return Err(SecretError::TooLarge);
    }
    let (reader, mut writer) = std::io::pipe().map_err(|_| SecretError::BackendUnavailable)?;
    let written = writer.write_all(material.expose());
    // The write end closes, then the material is zeroed: from here the value
    // exists only in the kernel's pipe buffer, until the broker reads it.
    drop(writer);
    drop(material);
    written.map_err(|_| SecretError::BackendUnavailable)?;
    Ok(SecretPipe(OwnedFd::from(reader)))
}

/// Off Unix there is no broker channel to hand a pipe to: the material is
/// zeroed and the use fails, provably without effect.
///
/// # Errors
///
/// Always [`SecretError::BackendUnavailable`].
#[cfg(not(unix))]
pub(crate) fn one_shot(material: SecretMaterial) -> Result<SecretPipe, SecretError> {
    drop(material);
    Err(SecretError::BackendUnavailable)
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Read as _;

    use zeroize::Zeroizing;

    use super::one_shot;
    use crate::secret::material::SecretMaterial;

    #[test]
    fn a_handoff_holds_the_value_then_end_of_file() {
        let value: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let pipe = one_shot(SecretMaterial::new(Zeroizing::new(value.clone())).unwrap()).unwrap();
        let mut reader = std::io::PipeReader::from(pipe.into_transfer_descriptor());
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert!(got == value, "the pipe holds exactly the value");
    }
}
