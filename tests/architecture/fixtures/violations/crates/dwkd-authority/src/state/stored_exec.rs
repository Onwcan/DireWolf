//! FIXTURE: an executable identity minted from a new declaration by grammar
//! alone (TX024). This comment names stored_executable_identity and must not
//! itself be a finding.

pub fn mint(path: &str, sha256: &str) -> bool {
    crate::resource::exec::stored_executable_identity(path, sha256)
}

pub fn forge(
    path: crate::resource::CanonicalPath,
    digest: crate::resource::Sha256Digest,
) -> crate::resource::ExecutableIdentity {
    crate::resource::ExecutableIdentity::new(path, digest)
}
