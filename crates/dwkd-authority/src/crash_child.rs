//! The real-process crash children's side (M6.2.1), in Linux unit-test
//! builds only.
//!
//! `make approval-registry-crash-evidence` (`scripts/dw.py`) runs this crate's
//! unit-test executable as a child, selects one `#[ignore]`d child test by its
//! exact name, and names the case, the directory and the handshake file in
//! the child's environment. The child builds its authority in that
//! directory, arms its crash hook, and at the case's window writes the
//! handshake file and stands still: the supervisor -- never this crate --
//! then ends the process with `SIGKILL`, with no unwinding, no destructor, no
//! rollback and no flush, and runs a separate recovery child on the files the
//! dead one left.
//!
//! It lives outside `state/` for the reason `scratch.rs` does (TX006): reading
//! the process's environment is an ambient effect the state layer's code and
//! tests never make. It starts, signals and waits for no process (TX010). It
//! is compiled only into `cfg(test)` builds for Linux: no release artifact
//! holds it, and no environment variable means anything to one.

use std::path::{Path, PathBuf};

use crate::state::CrashPoint;

/// The variable naming a crash child's case.
const CASE: &str = "DW_M621_CRASH_CASE";
/// The variable naming a recovery child's case.
const RECOVER: &str = "DW_M621_RECOVER_CASE";
/// The directory both children work in.
const DIR: &str = "DW_M621_DIR";
/// The handshake file a crash child writes at its window.
const READY: &str = "DW_M621_READY";

/// What the supervisor asked of this child.
#[derive(Debug, Clone)]
pub(crate) struct Assignment {
    /// The case's name, one of the supervisor's.
    pub(crate) case: String,
    /// The directory the case's authority lives in, the supervisor's.
    pub(crate) dir: PathBuf,
    ready: Option<PathBuf>,
}

fn read(case: &str, ready: bool) -> Option<Assignment> {
    let case = std::env::var(case).ok()?;
    let dir = PathBuf::from(std::env::var(DIR).ok()?);
    let ready = if ready {
        Some(PathBuf::from(std::env::var(READY).ok()?))
    } else {
        None
    };
    Some(Assignment { case, dir, ready })
}

/// A crash child's assignment, if the supervisor started this process as one.
pub(crate) fn crash() -> Option<Assignment> {
    read(CASE, true)
}

/// A recovery child's assignment, if the supervisor started this process as
/// one.
pub(crate) fn recovery() -> Option<Assignment> {
    read(RECOVER, false)
}

impl Assignment {
    /// The directory the case's authority lives in.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Report that the case's window is reached -- the case and the point,
    /// written to a temporary name and renamed, so the supervisor never reads
    /// half a line -- and stand still there until the supervisor ends the
    /// process. Never returns.
    pub(crate) fn reached(&self, point: CrashPoint) -> ! {
        if let Some(ready) = &self.ready {
            let partial = ready.with_extension("partial");
            let line = format!("{} {}\n", self.case, point.letter());
            if std::fs::write(&partial, line).is_ok() {
                let _ = std::fs::rename(&partial, ready);
            }
        }
        loop {
            std::thread::park();
        }
    }
}
