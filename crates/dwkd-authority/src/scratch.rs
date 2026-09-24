//! Scratch directories for unit tests that need real files. Test-only.
//!
//! It lives here, outside `state/`, on purpose: TX006 keeps ambient effects —
//! `std::env`, `std::process` — out of the state layer, its tests included,
//! and asking the process for its temporary directory is one. The state
//! layer's unit tests take a directory from here instead of reaching for the
//! environment themselves.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A fresh directory under the system temporary directory, removed when
/// dropped. On macOS that directory is under `/var`, itself a symlink — which
/// the state layer's path handling must cope with, so the tests see it too.
///
/// **Private whatever the umask**: on Unix it is `0700`, created so, then set
/// and verified. The socket tests bind beneath one, and the authority rightly
/// refuses a socket below a directory another user may write — which a
/// directory left to a umask of `0002` is. A test that needs more widens it
/// itself.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("dw-unit-{tag}-{}-{nanos}-{n}", std::process::id()));
        if let Err(error) = private_dir(&path) {
            unreachable!("a scratch directory: {error}");
        }
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create `path` as a directory only its owner can use: made `0700`, then set
/// to exactly `0700` — a umask only removes bits, and must not lock the owner
/// out either — and verified.
#[cfg(unix)]
fn private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() && meta.permissions().mode() & 0o7777 == 0o700 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{} is not a private directory",
            path.display()
        )))
    }
}

/// Elsewhere there is no mode to set: the host's own defaults apply.
#[cfg(not(unix))]
fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::Scratch;

    #[test]
    fn a_scratch_directory_is_private_whatever_the_umask() {
        let scratch = Scratch::new("contract");
        let mode = std::fs::symlink_metadata(scratch.path())
            .map(|m| m.permissions().mode() & 0o7777)
            .ok();
        assert_eq!(mode, Some(0o700));
    }
}
