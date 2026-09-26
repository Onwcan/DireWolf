//! FIXTURE: the executable module's own definitions -- the release of an
//! `ExecHandoff`'s descriptors (TX014) and the grammar-only reader of a stored
//! identity (TX024) -- which this file alone may name. Not findings.

pub struct ExecHandoff;

impl ExecHandoff {
    pub fn into_transfer_descriptor(self) {}
}

pub fn stored_executable_identity(path: &str, sha256: &str) -> bool {
    !path.is_empty() && sha256.len() == 64
}
