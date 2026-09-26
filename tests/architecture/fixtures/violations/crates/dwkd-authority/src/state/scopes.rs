//! FIXTURE: the one module that re-reads a stored executable identity (TX024
//! exempts it by name). Not a finding.

pub fn rehydrate(path: &str, sha256: &str) -> bool {
    crate::resource::exec::stored_executable_identity(path, sha256)
}
