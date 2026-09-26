//! Secret backends (ADR-0046 §§6–8): where a value is read from, **after** both
//! gates allowed a use and its intent is durable — or once at start, to
//! fingerprint it for the redaction index (ADR-0046 §21). Nothing else reads a
//! value, and nothing here returns one to anyone but its caller in the state
//! layer.
//!
//! | storage | Linux | macOS | Windows |
//! |---|---|---|---|
//! | `keychain` | the kernel keyring: a `user` key in the authority's user keyring | Keychain (`keyring`, apple-native) | Credential Manager (`keyring`, windows-native) |
//! | `age` | an age file, opened beneath trusted directories without following a symlink, decrypted with the `[age]` identity from the keychain | unavailable | unavailable |
//! | `env`, `exec` | refused at load: deferred (ADR-0046 §7) | | |
//!
//! Every failure is a typed [`SecretError`]; no backend error text — which could
//! carry bytes from a decrypted document or a platform message — reaches a log,
//! an audit record or a runtime.

mod age_file;
mod keychain;
#[cfg(target_os = "linux")]
mod trusted_file;

use super::SecretError;
use super::material::SecretMaterial;
use super::metadata::{AgeIdentitySource, Storage};

/// Read one secret's value.
///
/// `age` is the configuration's `[age]` identity source (required for an age
/// secret); `trusted_owner` is the authority's uid, which with root is the
/// only owner an age file and its directories may have.
///
/// # Errors
///
/// A typed [`SecretError`]: the backend's own failure, never its text.
pub fn read(
    storage: &Storage,
    age: Option<&AgeIdentitySource>,
    trusted_owner: u32,
) -> Result<SecretMaterial, SecretError> {
    count_read();
    match storage {
        Storage::Keychain(entry) => keychain::read(entry),
        Storage::Age(file) => {
            let source = age.ok_or(SecretError::BackendUnavailable)?;
            let ciphertext = age_file::open(file, trusted_owner)?;
            let identity = keychain::read(&source.keychain)?;
            age_file::decrypt(&ciphertext, &identity, source.kind)
        }
    }
}

/// Read the operator's metadata file (`--secrets-file`): owned by root or the
/// authority, writable by nobody else, reached without following a symlink,
/// at most [`super::metadata::MAX_CONFIG_BYTES`]. Not a backend read: it holds
/// no value.
///
/// # Errors
///
/// A message naming the refusal.
pub fn read_metadata_file(path: &str, trusted_owner: u32) -> Result<String, String> {
    let file = super::metadata::AgeFile::new(path).ok_or_else(|| {
        format!("--secrets-file {path}: not an absolute path of plain components ([A-Za-z0-9._-])")
    })?;
    #[cfg(target_os = "linux")]
    {
        let limit = u64::try_from(super::metadata::MAX_CONFIG_BYTES).unwrap_or(u64::MAX);
        let bytes = trusted_file::read(&file, trusted_owner, limit, 0o022).map_err(|error| {
            format!(
                "--secrets-file {path}: {error} (a regular file owned by root or the authority, \
                 writable by nobody else, under directories only they can change)"
            )
        })?;
        String::from_utf8(bytes).map_err(|_| format!("--secrets-file {path}: not UTF-8"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, trusted_owner);
        Err("--secrets-file is supported on Linux only".to_owned())
    }
}

#[cfg(test)]
thread_local! {
    static READS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg_attr(not(test), allow(clippy::missing_const_for_fn))]
fn count_read() {
    #[cfg(test)]
    READS.with(|count| count.set(count.get().saturating_add(1)));
}

/// How many backend reads this thread has made. **Test observation**: it
/// proves that admission, admission replay and stored-grant rehydration read
/// no value (ADR-0046 §5). The suites that read it run where the pipeline's
/// do: Linux.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn reads_on_this_thread() -> u64 {
    READS.with(core::cell::Cell::get)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(all(test, windows))]
mod windows_tests;

#[cfg(all(test, target_os = "linux"))]
pub(crate) use keychain::test_support as keychain_test_support;
