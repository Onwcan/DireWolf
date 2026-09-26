// Violation fixture (M4e, TX028-TX029): the broker opening a secret store of
// its own, and a broker-held value leaving for a launch's argv.
pub fn resolve(entry: &str) -> Vec<u8> {
    let store = linux_keyutils::KeyRing::from_special_id(KEY_SPEC_USER_KEYRING, false);
    let _store = std::path::Path::new("/etc/direwolf/secrets/deploy.age");
    let _meta = "secrets.toml";
    let _ = (store, entry);
    Vec::new()
}

pub fn argv(needle: &Needle) -> Vec<Vec<u8>> {
    vec![b"--token".to_vec(), needle.value().to_vec()]
}
