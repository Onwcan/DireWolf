//! FIXTURE: a policy engine that reads the process environment to decide what
//! `${WORKSPACE}` means (TX004). This comment mentions std::env and must not
//! itself be a finding.

use std::env;

/// The bug TX004 exists to prevent. `${WORKSPACE}` is a closed symbolic anchor
/// resolved from kernel-owned state; asking the environment for it hands the
/// meaning of every workspace rule to whoever set the variable.
pub fn workspace_root() -> String {
    env::var("WORKSPACE").unwrap_or_else(|_| "/".to_owned())
}

/// And the other half: a policy decision that depends on a file nobody
/// canonicalised, made by the engine rather than by the canonicaliser.
pub fn allowed(path: &str) -> bool {
    std::fs::metadata(path).is_ok() && path.starts_with(&workspace_root())
}
