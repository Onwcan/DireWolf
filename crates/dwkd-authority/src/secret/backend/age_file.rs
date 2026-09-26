//! The age backend (ADR-0046 §8): an age-encrypted file at an operator-chosen
//! path, decrypted by the reviewed `age` implementation with an identity held
//! in the keychain. We write no cryptography.
//!
//! The file must be a regular file owned by root or the authority, readable by
//! nobody else (mode `0600` or tighter), under directories only root or the
//! authority can change, reached without following a symlink, and at most
//! [`MAX_CIPHERTEXT_BYTES`]. Anything else is [`SecretError::StoreUntrusted`].
//! There is no plaintext fallback: a file that fails any check, or fails to
//! decrypt, yields no value.

use std::io::Read as _;

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::secret::SecretError;
use crate::secret::material::{MAX_SECRET_BYTES, SecretMaterial};
use crate::secret::metadata::{AgeFile, AgeIdentityKind};

/// The largest age file read: the largest secret plus the format's overhead
/// (a header of a few hundred bytes and 16 bytes per 64 KiB chunk), rounded
/// up generously. A larger file is refused before it is decrypted.
#[cfg(target_os = "linux")]
pub(super) const MAX_CIPHERTEXT_BYTES: u64 = 64 * 1024;

#[cfg(target_os = "linux")]
pub(super) fn open(file: &AgeFile, trusted_owner: u32) -> Result<Vec<u8>, SecretError> {
    super::trusted_file::read(file, trusted_owner, MAX_CIPHERTEXT_BYTES, 0o077)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open(_file: &AgeFile, _trusted_owner: u32) -> Result<Vec<u8>, SecretError> {
    Err(SecretError::BackendUnavailable)
}

/// Decrypt `ciphertext` with the identity in `identity` (an X25519 secret key
/// or a passphrase, as `kind` says) into secret material.
///
/// # Errors
///
/// [`SecretError::DecryptFailed`] for a malformed, truncated or wrongly keyed
/// file or an unusable identity; [`SecretError::TooLarge`] for a plaintext
/// over the bound. No `age` error text survives.
pub(crate) fn decrypt(
    ciphertext: &[u8],
    identity: &SecretMaterial,
    kind: AgeIdentityKind,
) -> Result<SecretMaterial, SecretError> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| SecretError::DecryptFailed)?;
    let reader = match kind {
        AgeIdentityKind::X25519 => {
            let text =
                core::str::from_utf8(identity.expose()).map_err(|_| SecretError::DecryptFailed)?;
            let key: age::x25519::Identity = text
                .trim()
                .parse()
                .map_err(|_| SecretError::DecryptFailed)?;
            let key: &dyn age::Identity = &key;
            decryptor
                .decrypt(core::iter::once(key))
                .map_err(|_| SecretError::DecryptFailed)?
        }
        AgeIdentityKind::Scrypt => {
            // The passphrase moves into age's own zeroizing string; the one
            // copy made here is scrubbed when it is dropped.
            let text = Zeroizing::new(
                core::str::from_utf8(identity.expose())
                    .map_err(|_| SecretError::DecryptFailed)?
                    .trim_end_matches(['\n', '\r'])
                    .to_owned(),
            );
            let passphrase = SecretString::from(text.as_str().to_owned());
            let key = age::scrypt::Identity::new(passphrase);
            let key: &dyn age::Identity = &key;
            decryptor
                .decrypt(core::iter::once(key))
                .map_err(|_| SecretError::DecryptFailed)?
        }
    };
    let mut plaintext = SecretMaterial::buffer();
    let limit = u64::try_from(MAX_SECRET_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    reader
        .take(limit)
        .read_to_end(&mut plaintext)
        .map_err(|_| SecretError::DecryptFailed)?;
    SecretMaterial::new(plaintext)
}
