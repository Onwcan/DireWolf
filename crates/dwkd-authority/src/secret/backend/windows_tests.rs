//! The keychain backend against the real Windows Credential Manager (ADR-0046
//! §6): a generic credential under the `direwolf` target, written by this
//! test through the same `keyring` crate, read through the backend, then
//! deleted. Values are generated at run time and compared by digest.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sha2::{Digest as _, Sha256};

use super::read;
use crate::secret::SecretError;
use crate::secret::metadata::{KeychainEntry, Storage};

/// The credential, deleted when dropped (even when the test fails).
struct Seeded(keyring::Entry);

impl Drop for Seeded {
    fn drop(&mut self) {
        let _ = self.0.delete_credential();
    }
}

#[test]
fn the_windows_credential_manager_round_trips_a_value_and_answers_missing() {
    let name = format!("direwolf-test/windows-{}", std::process::id());
    let value: Vec<u8> = Sha256::digest(name.as_bytes())
        .iter()
        .map(|b| b'a' + b % 26)
        .collect();
    let entry = keyring::Entry::new("direwolf", &name).unwrap();
    if entry.set_secret(&value).is_err() {
        println!("NOT EXERCISED: the Windows Credential Manager refused a test credential");
        return;
    }
    let seeded = Seeded(entry);
    let got = read(
        &Storage::Keychain(KeychainEntry::new(&name).unwrap()),
        None,
        0,
    );
    let digest = got
        .as_ref()
        .ok()
        .map(|m| Sha256::digest(m.expose()).to_vec());
    assert!(
        digest == Some(Sha256::digest(&value).to_vec()),
        "the value round-trips"
    );
    drop(seeded);
    assert_eq!(
        read(
            &Storage::Keychain(KeychainEntry::new(&name).unwrap()),
            None,
            0
        )
        .err(),
        Some(SecretError::BackendItemMissing),
        "a removed credential is missing"
    );
    let never = KeychainEntry::new("direwolf-test/never-seeded").unwrap();
    assert_eq!(
        read(&Storage::Keychain(never), None, 0).err(),
        Some(SecretError::BackendItemMissing)
    );
}
