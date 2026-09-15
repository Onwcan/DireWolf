//! Build provenance, captured by `build.rs` at compile time.
//!
//! Nothing here reads the environment at runtime: a binary should be able to
//! state what it is without trusting the process that launched it.

/// Semantic version, synchronised with the repository-root `VERSION` file.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit the binary was built from, or `unknown` outside a checkout.
pub(crate) const GIT_COMMIT: &str = env!("DIREWOLF_GIT_COMMIT");

/// Cargo profile: `debug`, `release`, or a custom profile name.
pub(crate) const PROFILE: &str = env!("DIREWOLF_PROFILE");

/// Target triple this binary was compiled for.
pub(crate) const TARGET: &str = env!("DIREWOLF_TARGET");

#[cfg(test)]
mod tests {
    use super::{GIT_COMMIT, PROFILE, TARGET, VERSION};

    #[test]
    fn build_info_is_populated() {
        assert!(!VERSION.is_empty());
        assert!(!GIT_COMMIT.is_empty());
        assert!(!PROFILE.is_empty());
        assert!(!TARGET.is_empty());
    }
}
