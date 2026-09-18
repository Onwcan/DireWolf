//! FIXTURE: a capability core that decides authority by reading the filesystem
//! (TX003). This comment mentions std::fs and must not itself be a finding.

use std::fs;

/// The bug ADR-0037 exists to prevent, in one function: a path compared as
/// authority, resolved by looking at the world, at the moment somebody asked.
pub fn covers(parent: &str, child: &str) -> bool {
    let parent = fs::canonicalize(parent).unwrap_or_default();
    let child = fs::canonicalize(child).unwrap_or_default();
    child.starts_with(parent)
}
