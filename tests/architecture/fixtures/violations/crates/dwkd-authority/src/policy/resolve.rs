//! FIXTURE: the policy engine asking the filesystem resolver what a declared
//! path means (TX011), instead of receiving the canonical path as a value the
//! state layer derived. This comment names crate::resource::fs and must not
//! itself be a finding.

use crate::resource::{CanonicalPath, fs};

pub fn covers(root: &fs::PinnedRoot, declared: &str) -> Option<CanonicalPath> {
    crate::resource::fs::resolve(root, declared).ok()
}
