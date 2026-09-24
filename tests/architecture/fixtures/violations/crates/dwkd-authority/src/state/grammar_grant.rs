//! FIXTURE: a new declaration given authority by the grammar alone (TX017).
//! This comment names stored_canonical_path and must not itself be a finding.

pub fn mint(declared: &crate::capability::DeclaredPath) -> bool {
    crate::resource::fs::stored_canonical_path(declared).is_ok()
}
