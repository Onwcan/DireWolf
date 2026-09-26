//! FIXTURE: the policy engine resolving an executable itself (TX011), instead
//! of receiving its canonical path and digest as values. This comment names
//! crate::resource::exec and must not itself be a finding.

use crate::resource::{CanonicalPath, exec};

pub fn which(name: &str) -> Option<CanonicalPath> {
    crate::resource::exec::resolve(name, 0).ok().map(|r| r.path())
}

pub fn digest(name: &str) -> bool {
    exec::resolve(name, 0).is_ok()
}
