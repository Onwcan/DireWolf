//! Secret material: the plaintext of one secret, for the shortest time
//! (ADR-0046 §10).
//!
//! A [`SecretMaterial`] owns its bytes in a [`Zeroizing`] buffer, so they are
//! overwritten when it is dropped. It has no `Clone`, no `Display`, no
//! `Serialize`, no `ToString`, no `&str` view and a `Debug` that prints
//! nothing of the value; it is bounded by [`MAX_SECRET_BYTES`] and is never
//! empty. The only way to see the bytes is [`SecretMaterial::expose`], which
//! is visible to this crate alone.
//!
//! What zeroization is **not**: a guarantee against swap, a guarantee that no
//! intermediate copy ever existed in a library the backend called, or a
//! defence against a debugger. The authority disables core dumps and makes
//! itself non-dumpable (`server::hardening`); `mlock` and `MADV_DONTDUMP` are
//! not implemented, because neither is available through a safe API
//! (ADR-0046 §10).

use core::fmt;

use zeroize::Zeroizing;

use super::SecretError;

/// The largest secret this build accepts: 32 KiB. Room for an API token, a
/// password, a connection string, an RSA-8192 private key in PEM (~6.5 KiB)
/// or a key with a short certificate chain; and less than a pipe's default
/// capacity (64 KiB), so the one-shot hand-off to the broker is written in
/// full before the descriptor is sent and never blocks the authority.
/// Anything larger is refused before it is used, never truncated.
pub const MAX_SECRET_BYTES: usize = dwk_proto::brokerp::MAX_SECRET_BYTES;

/// The plaintext of one secret.
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    /// Take ownership of a value a backend read into a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`SecretError::MaterialInvalid`] for an empty value and
    /// [`SecretError::TooLarge`] for one over [`MAX_SECRET_BYTES`]; the buffer
    /// is zeroized either way.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            return Err(SecretError::MaterialInvalid);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretError::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// A zeroizing buffer with room for the largest value and one byte more,
    /// so a backend can detect an over-long value without growing (and so
    /// copying) the buffer.
    #[must_use]
    pub fn buffer() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES.saturating_add(1)))
    }

    /// The bytes. Crate-private: the injector writes them into a one-shot
    /// descriptor and the redaction index fingerprints them; nothing else
    /// reads them.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The number of bytes. Crate-private, and never recorded: for many token
    /// formats a length is part of an oracle.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial(..)")
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{MAX_SECRET_BYTES, SecretError, SecretMaterial};

    #[test]
    fn material_is_bounded_never_empty_and_prints_nothing() {
        assert_eq!(
            SecretMaterial::new(Zeroizing::new(Vec::new())).err(),
            Some(SecretError::MaterialInvalid)
        );
        assert_eq!(
            SecretMaterial::new(Zeroizing::new(vec![b'x'; MAX_SECRET_BYTES + 1])).err(),
            Some(SecretError::TooLarge)
        );
        let material = SecretMaterial::new(Zeroizing::new(b"m4e-debug-probe".to_vec()));
        let Ok(material) = material else {
            unreachable!("a small value is material")
        };
        let shown = format!("{material:?}");
        assert!(!shown.contains("m4e-debug-probe"));
        assert_eq!(material.len(), 15);
        let buffer = SecretMaterial::buffer();
        assert!(buffer.capacity() > MAX_SECRET_BYTES);
    }
}
