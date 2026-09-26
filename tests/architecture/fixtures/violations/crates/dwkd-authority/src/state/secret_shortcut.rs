// Violation fixture (M4e, TX025-TX027): the state layer reaching a keychain
// itself, taking a value out of its type, and offering it to a caller.
use linux_keyutils::KeyRing;

pub fn export_secret(material: &SecretMaterial) -> Vec<u8> {
    let _ring = KeyRing::from_special_id(linux_keyutils::KeyRingIdentifier::User, false);
    material.expose().to_vec()
}

pub fn secret_value(handle: &str) -> Option<Vec<u8>> {
    let _ = hmac::Hmac::<sha2::Sha256>::new_from_slice(handle.as_bytes());
    None
}
