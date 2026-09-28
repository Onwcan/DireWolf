//! The keychain backend (ADR-0046 §6).
//!
//! **Linux: the kernel keyring.** A secret is a key of type `user` whose
//! description is the configured entry name, in the authority uid's **user
//! keyring** (`@u`). It lives in kernel memory, never on disk, and survives
//! until reboot. The value is read into a zeroizing buffer the authority
//! allocated, so no intermediate copy is made on the way. There is no D-Bus
//! and no native library, so it works on a headless host, which the desktop
//! Secret Service does not.
//!
//! **Provisioning contract.** The authority reads a key by searching `@u` and
//! then reading the key by its serial. A service does not *possess* `@u` (a
//! systemd service gets a private session keyring, and so does a CI runner),
//! so only the key's **owner** bits apply to that read — and the kernel's
//! default mask for a new key, `0x3f010000`, gives the owner VIEW alone. A key
//! for the authority must therefore be created by (or `chown`ed to) the
//! authority's uid with exactly this mask:
//!
//! | class | permissions |
//! |---|---|
//! | possessor | all |
//! | owning uid | view, read, search |
//! | group | none |
//! | others | none |
//!
//! that is `0x3f0b0000`. Setting a mask needs SETATTR, which under the default
//! mask only a possessor has, so the key is staged in a keyring the
//! provisioning shell possesses and then linked into `@u` — with the value on
//! stdin, never in argv:
//!
//! ```text
//! id=$(keyctl padd user <entry> @s)        # the value on stdin
//! keyctl setperm "$id" 0x3f0b0000
//! keyctl link "$id" @u && keyctl unlink "$id" @s
//! ```
//!
//! The reader never changes a key's permissions: a key provisioned without
//! the owner's READ fails closed, `BACKEND_DENIED`. Other uids have their own
//! `@u` and, with no group or other bits, cannot read this key even by serial.
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

/// Test support: provision and remove kernel-keyring keys in this process's
/// user keyring exactly as the module's provisioning contract requires of an
/// operator — so a test passes where the authority would, whether or not the
/// test's session possesses `@u`. **`#[cfg(test)]`**.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod test_support {
    use linux_keyutils::{
        Key, KeyPermissions, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission,
    };

    use crate::secret::material::MAX_SECRET_BYTES;

    /// The provisioning contract's mask, `0x3f0b0000`: the possessor may do
    /// anything; the owning uid may view, read and search; its group and
    /// everyone else, nothing.
    pub(crate) fn authority_permissions() -> KeyPermissions {
        KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .user(Permission::VIEW | Permission::READ | Permission::SEARCH)
            .group(Permission::empty())
            .world(Permission::empty())
            .build()
    }

    /// Add (or replace) `entry` with `value` under `perms`, as an operator
    /// must: staged in this process's own keyring, which it possesses, linked
    /// into `@u` and given `perms` while still possessed (setting a mask needs
    /// SETATTR, which the default mask gives only a possessor), then unlinked
    /// from the staging keyring. `None` where the host has no usable keyring,
    /// so the caller can report it NOT EXERCISED.
    pub(crate) fn seed_with(entry: &str, value: &[u8], perms: KeyPermissions) -> Option<Key> {
        let staging = KeyRing::from_special_id(KeyRingIdentifier::Process, true).ok()?;
        let user = KeyRing::from_special_id(KeyRingIdentifier::User, true).ok()?;
        let key = staging.add_key(entry, value).ok()?;
        let placed = user.link_key(key).and_then(|()| key.set_perms(perms));
        let _ = staging.unlink_key(key);
        if placed.is_err() {
            let _ = user.unlink_key(key);
            return None;
        }
        Some(key)
    }

    /// [`seed_with`] under the provisioning contract.
    pub(crate) fn seed(entry: &str, value: &[u8]) -> Option<()> {
        seed_with(entry, value, authority_permissions()).map(|_| ())
    }

    /// Remove `entry`, if present and searchable.
    pub(crate) fn remove(entry: &str) {
        if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false)
            && let Ok(key) = ring.search(entry)
        {
            let _ = key.invalidate();
        }
    }

    /// Remove `key` by its serial: unlinking needs no permission on the key,
    /// so this also removes a key its owner may not search.
    pub(crate) fn remove_key(key: Key) {
        let _ = key.invalidate();
        if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false) {
            let _ = ring.unlink_key(key);
        }
    }

    /// Whether this process possesses `entry` — whether its session keyring
    /// links `@u`, as a login session's usually does and a service's does not.
    /// A possessor that may search can read a key without its READ bit
    /// (`keyctl_read(2)`), so a denial by the owner's bits is only observable
    /// where the key is not possessed.
    pub(crate) fn possessed(entry: &str) -> bool {
        KeyRing::from_special_id(KeyRingIdentifier::Session, false)
            .and_then(|session| session.search(entry))
            .is_ok()
    }

    /// Which step of the production path — `search` in `@u`, then `read` by
    /// serial — refuses `entry`, for an assertion message: `search: <error>`,
    /// `read: <error>` or `none`. The error's name only: never the value, a
    /// prefix of it or its length.
    pub(crate) fn refused_stage(entry: &str) -> String {
        let key = match KeyRing::from_special_id(KeyRingIdentifier::User, false)
            .and_then(|ring| ring.search(entry))
        {
            Ok(key) => key,
            Err(error) => return format!("search: {error:?}"),
        };
        let mut probe = zeroize::Zeroizing::new(vec![0u8; MAX_SECRET_BYTES + 1]);
        match key.read(&mut *probe) {
            Ok(_) => "none".to_owned(),
            Err(error) => format!("read: {error:?}"),
        }
    }
}
