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
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("dw-unit-{tag}-{}-{nanos}-{n}", std::process::id()));
        if let Err(error) = std::fs::create_dir_all(&path) {
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
