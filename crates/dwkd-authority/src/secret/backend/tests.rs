//! The backends against the real kernel keyring and real age files (ADR-0046
//! §§6–8), including every hostile case. Values are generated at run time and
//! compared by digest, so no assertion can print one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

use age::secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};

use super::keychain::test_support;
use super::read;
use crate::scratch::Scratch;
use crate::secret::SecretError;
use crate::secret::material::{MAX_SECRET_BYTES, SecretMaterial};
use crate::secret::metadata::{
    AgeFile, AgeIdentityKind, AgeIdentitySource, KeychainEntry, Storage,
};

/// One line of the secret evidence (`make secret-broker-evidence`), printed
/// only after the assertions before it held.
fn evidence(suite: &str, case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn value(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| b'a' + u8::try_from((i * 7 + usize::from(seed)) % 26).unwrap())
        .collect()
}

/// A unique entry name, removed when dropped (even when the test fails).
struct Seeded(String);

impl Seeded {
    fn new(tag: &str, bytes: &[u8]) -> Option<Self> {
        let name = format!("direwolf-test/{tag}-{}", std::process::id());
        test_support::seed(&name, bytes)?;
        Some(Self(name))
    }
    fn entry(&self) -> KeychainEntry {
        KeychainEntry::new(&self.0).unwrap()
    }
}

impl Drop for Seeded {
    fn drop(&mut self) {
        test_support::remove(&self.0);
    }
}

fn exposed_digest(material: &Result<SecretMaterial, SecretError>) -> Option<[u8; 32]> {
    material.as_ref().ok().map(|m| digest(m.expose()))
}

fn own_uid(dir: &std::path::Path) -> u32 {
    std::fs::metadata(dir).unwrap().uid()
}

#[test]
fn the_kernel_keyring_round_trips_a_value_and_answers_missing_and_oversized_by_type() {
    let secret = value(1, 48);
    let Some(seeded) = Seeded::new("roundtrip", &secret) else {
        println!("NOT EXERCISED: no usable kernel keyring on this host");
        return;
    };
    let got = read(&Storage::Keychain(seeded.entry()), None, 0);
    assert_eq!(exposed_digest(&got), Some(digest(&secret)));

    let missing = KeychainEntry::new("direwolf-test/never-seeded").unwrap();
    assert_eq!(
        read(&Storage::Keychain(missing), None, 0).err(),
        Some(SecretError::BackendItemMissing)
    );

    // A `user` key holds at most 32 767 bytes, and a non-root user's keys
    // share a quota (`/proc/sys/kernel/keys/maxbytes`, 20 000 by default): the
    // kernel itself refuses a value over the authority's bound, so a keyring
    // value can never exceed it. Large values (a key with a certificate
    // chain) belong in an age file; the age path proves the authority's own
    // refusal of an oversized value.
    assert!(Seeded::new("large", &vec![b'x'; MAX_SECRET_BYTES + 1]).is_none());
    let practical = Seeded::new("practical", &vec![b'x'; 8 * 1024]).unwrap();
    let got = read(&Storage::Keychain(practical.entry()), None, 0);
    assert_eq!(exposed_digest(&got), Some(digest(&vec![b'x'; 8 * 1024])));

    // Removed: the next read fails closed.
    drop(seeded);
    let again =
        KeychainEntry::new(&format!("direwolf-test/roundtrip-{}", std::process::id())).unwrap();
    assert!(read(&Storage::Keychain(again), None, 0).is_err());
    evidence("secret-backend", "keyring-round-trip", "digest-equal");
    evidence(
        "secret-backend",
        "keyring-item-missing",
        "BACKEND_ITEM_MISSING",
    );
    evidence(
        "secret-backend",
        "keyring-oversized-refused-by-kernel",
        "refused",
    );
    evidence("secret-backend", "keyring-removed-fails-closed", "error");
}

struct AgeFixture {
    scratch: Scratch,
    identity: Seeded,
    recipient: age::x25519::Recipient,
}

fn age_fixture(tag: &str) -> Option<AgeFixture> {
    let key = age::x25519::Identity::generate();
    let recipient = key.to_public();
    let identity = Seeded::new(
        &format!("{tag}-id"),
        key.to_string().expose_secret().as_bytes(),
    )?;
    Some(AgeFixture {
        scratch: Scratch::new(tag),
        identity,
        recipient,
    })
}

impl AgeFixture {
    fn source(&self) -> AgeIdentitySource {
        AgeIdentitySource {
            keychain: self.identity.entry(),
            kind: AgeIdentityKind::X25519,
        }
    }
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let recipient: &dyn age::Recipient = &self.recipient;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        out
    }
    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> Storage {
        let dir = std::fs::canonicalize(self.scratch.path()).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        Storage::Age(AgeFile::new(path.to_str().unwrap()).unwrap())
    }
    fn uid(&self) -> u32 {
        own_uid(self.scratch.path())
    }
}

#[test]
fn an_age_file_decrypts_with_the_keychain_identity_and_every_hostile_file_is_refused() {
    let Some(fx) = age_fixture("age-backend") else {
        println!("NOT EXERCISED: no usable kernel keyring on this host");
        return;
    };
    let secret = value(2, 64);
    let ciphertext = fx.encrypt(&secret);
    let uid = fx.uid();
    let good = fx.write("good.age", &ciphertext, 0o600);
    assert_eq!(
        exposed_digest(&read(&good, Some(&fx.source()), uid)),
        Some(digest(&secret))
    );

    // No [age] identity, no value.
    assert_eq!(
        read(&good, None, uid).err(),
        Some(SecretError::BackendUnavailable)
    );
    // A file anyone else may read or write.
    let loose = fx.write("loose.age", &ciphertext, 0o644);
    assert_eq!(
        read(&loose, Some(&fx.source()), uid).err(),
        Some(SecretError::StoreUntrusted)
    );
    // Owned by someone the authority does not trust.
    assert_eq!(
        read(&good, Some(&fx.source()), uid.wrapping_add(1)).err(),
        Some(SecretError::StoreUntrusted)
    );
    // A symlink substituted for the file.
    let dir = std::fs::canonicalize(fx.scratch.path()).unwrap();
    symlink(dir.join("good.age"), dir.join("link.age")).unwrap();
    let link = Storage::Age(AgeFile::new(dir.join("link.age").to_str().unwrap()).unwrap());
    assert_eq!(
        read(&link, Some(&fx.source()), uid).err(),
        Some(SecretError::StoreUntrusted)
    );
    // Truncated, garbage, and too large.
    let truncated = fx.write("truncated.age", &ciphertext[..ciphertext.len() - 10], 0o600);
    assert_eq!(
        read(&truncated, Some(&fx.source()), uid).err(),
        Some(SecretError::DecryptFailed)
    );
    let garbage = fx.write("garbage.age", b"not an age file at all", 0o600);
    assert_eq!(
        read(&garbage, Some(&fx.source()), uid).err(),
        Some(SecretError::DecryptFailed)
    );
    let huge = fx.write("huge.age", &vec![0u8; 70 * 1024], 0o600);
    assert_eq!(
        read(&huge, Some(&fx.source()), uid).err(),
        Some(SecretError::StoreUntrusted)
    );
    // A plaintext over the bound, correctly encrypted: refused, not truncated.
    let over = fx.write(
        "over.age",
        &fx.encrypt(&vec![b'y'; MAX_SECRET_BYTES + 1]),
        0o600,
    );
    assert_eq!(
        read(&over, Some(&fx.source()), uid).err(),
        Some(SecretError::TooLarge)
    );
    // Missing.
    let missing = Storage::Age(AgeFile::new(dir.join("absent.age").to_str().unwrap()).unwrap());
    assert_eq!(
        read(&missing, Some(&fx.source()), uid).err(),
        Some(SecretError::BackendItemMissing)
    );

    // The wrong identity.
    let Some(other) = age_fixture("age-wrong") else {
        return;
    };
    let wrong = fx.write("wrong.age", &other.encrypt(&secret), 0o600);
    assert_eq!(
        read(&wrong, Some(&fx.source()), uid).err(),
        Some(SecretError::DecryptFailed)
    );
    evidence("secret-backend", "age-decrypt", "digest-equal");
    evidence("secret-backend", "age-no-identity", "BACKEND_UNAVAILABLE");
    evidence(
        "secret-backend",
        "age-store-readable-by-others",
        "STORE_UNTRUSTED",
    );
    evidence(
        "secret-backend",
        "age-store-foreign-owner",
        "STORE_UNTRUSTED",
    );
    evidence("secret-backend", "age-store-symlink", "STORE_UNTRUSTED");
    evidence("secret-backend", "age-truncated", "DECRYPT_FAILED");
    evidence("secret-backend", "age-garbage", "DECRYPT_FAILED");
    evidence("secret-backend", "age-oversized-file", "STORE_UNTRUSTED");
    evidence(
        "secret-backend",
        "age-oversized-plaintext",
        "SECRET_TOO_LARGE",
    );
    evidence("secret-backend", "age-missing", "BACKEND_ITEM_MISSING");
    evidence("secret-backend", "age-wrong-identity", "DECRYPT_FAILED");
}

#[test]
fn a_passphrase_identity_decrypts_an_scrypt_file() {
    let passphrase = "correct horse battery staple m4e";
    let Some(identity) = Seeded::new("scrypt-pass", passphrase.as_bytes()) else {
        println!("NOT EXERCISED: no usable kernel keyring on this host");
        return;
    };
    let secret = value(3, 30);
    let encryptor = age::Encryptor::with_user_passphrase(passphrase.to_owned().into());
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(&secret).unwrap();
    writer.finish().unwrap();
    let scratch = Scratch::new("age-scrypt");
    let dir = std::fs::canonicalize(scratch.path()).unwrap();
    let path = dir.join("s.age");
    std::fs::write(&path, &ciphertext).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let source = AgeIdentitySource {
        keychain: identity.entry(),
        kind: AgeIdentityKind::Scrypt,
    };
    let storage = Storage::Age(AgeFile::new(path.to_str().unwrap()).unwrap());
    let got = read(&storage, Some(&source), own_uid(scratch.path()));
    assert_eq!(exposed_digest(&got), Some(digest(&secret)));
    evidence("secret-backend", "age-scrypt-passphrase", "digest-equal");
}
