//! The keychain backend (ADR-0046 §6).
//!
//! **Linux: the kernel keyring.** A secret is a key of type `user` whose
//! description is the configured entry name, in the authority uid's **user
//! keyring** (`@u`). It lives in kernel memory, never on disk, and survives
//! until reboot; the operator loads it with `keyctl padd user <entry> @u` as
//! the authority's user. The value is read into a zeroizing buffer the
//! authority allocated, so no intermediate copy is made on the way. There is
//! no D-Bus and no native library, so it works on a headless host, which the
//! desktop Secret Service does not.
//!
//! **macOS and Windows**: the Keychain and the Credential Manager through
//! `keyring`'s native backends, service `direwolf`, account = the entry name.
//! The authority serves DWKP only on Linux, so neither is ever served: the
//! Windows backend is exercised by the crate's own tests against the real
//! Credential Manager (`windows_tests.rs`); the macOS backend is COMPILE-ONLY
//! (ADR-0046 §6).

use crate::secret::SecretError;
#[cfg(target_os = "linux")]
use crate::secret::material::MAX_SECRET_BYTES;
use crate::secret::material::SecretMaterial;
use crate::secret::metadata::KeychainEntry;

#[cfg(target_os = "linux")]
pub(super) fn read(entry: &KeychainEntry) -> Result<SecretMaterial, SecretError> {
    use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier};

    let classify = |error: KeyError| match error {
        // A key that was revoked, invalidated or has expired is gone for every
        // purpose DireWolf has: the operator's remedy is the same as for one
        // never added. (An invalidated key can answer `EKEYREVOKED` until the
        // kernel collects it, so treating the two apart would make a removal
        // read differently depending on the collector's timing.)
        KeyError::KeyDoesNotExist
        | KeyError::KeyringDoesNotExist
        | KeyError::KeyRevoked
        | KeyError::KeyExpired => SecretError::BackendItemMissing,
        KeyError::AccessDenied | KeyError::KeyRejected => SecretError::BackendDenied,
        // `OperationNotSupported` (no keyring on this kernel) and every other
        // failure: the backend cannot answer.
        _ => SecretError::BackendUnavailable,
    };
    let ring = KeyRing::from_special_id(KeyRingIdentifier::User, false).map_err(classify)?;
    let key = ring.search(entry.as_str()).map_err(classify)?;
    let mut buffer = SecretMaterial::buffer();
    // Within the reserved capacity: no reallocation, so no second copy.
    buffer.resize(MAX_SECRET_BYTES.saturating_add(1), 0);
    let length = key.read(&mut *buffer).map_err(classify)?;
    if length > MAX_SECRET_BYTES {
        return Err(SecretError::TooLarge);
    }
    buffer.truncate(length);
    SecretMaterial::new(buffer)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn read(entry: &KeychainEntry) -> Result<SecretMaterial, SecretError> {
    let classify = |error: keyring::Error| match error {
        keyring::Error::NoEntry => SecretError::BackendItemMissing,
        keyring::Error::NoStorageAccess(_) => SecretError::BackendDenied,
        _ => SecretError::BackendUnavailable,
    };
    let item = keyring::Entry::new("direwolf", entry.as_str()).map_err(classify)?;
    let value = zeroize::Zeroizing::new(item.get_secret().map_err(classify)?);
    SecretMaterial::new(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn read(_entry: &KeychainEntry) -> Result<SecretMaterial, SecretError> {
    let _ = MAX_SECRET_BYTES;
    Err(SecretError::BackendUnavailable)
}

/// Test support: seed and remove kernel-keyring keys in this process's user
/// keyring, the way an operator's `keyctl padd` would. **`#[cfg(test)]`**.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod test_support {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    /// Add (or replace) `entry` with `value`. `None` where the host has no
    /// usable keyring, so the caller can report it NOT EXERCISED.
    pub(crate) fn seed(entry: &str, value: &[u8]) -> Option<()> {
        let ring = KeyRing::from_special_id(KeyRingIdentifier::User, true).ok()?;
        ring.add_key(entry, value).ok().map(|_| ())
    }

    /// Remove `entry`, if present.
    pub(crate) fn remove(entry: &str) {
        if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false)
            && let Ok(key) = ring.search(entry)
        {
            let _ = key.invalidate();
        }
    }
}
