//! The state directory: layout, permissions, the process lock and the
//! quarantine marker.
//!
//! # The directory is part of the claim
//!
//! A process that cannot write `kernel.db` but can write the directory holding
//! it can still **replace** it: create a new file and rename it over the old
//! one. So the authority's state lives in a directory of its own, private to
//! the authority user (`0700`), and not directly in `$DIREWOLF_HOME`, which the
//! runtime also writes. Files are created `0600`.
//!
//! These are **code-level** checks and they are necessary, not sufficient.
//! Mode bits say what the kernel will enforce for a *different* user; whether
//! the runtime actually runs as a different user is a deployment fact, and it
//! is verified by attempting the writes as that user
//! (`tests/authority/runtime_write_probe.py`), never by reading these bits.
//!
//! # Platforms
//!
//! On Unix the directory and every state file must be owned by the authority's
//! own uid and carry no group or other permission bits. On Windows no
//! ownership or ACL check is performed: native Windows is a documented
//! reduced-assurance target (ADR-0029), and emulating Unix ownership there
//! would be a check that proves nothing. Symlinks are refused everywhere.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::error::StartError;

/// Where each state file lives.
#[derive(Debug, Clone)]
pub(super) struct StatePaths {
    pub(super) dir: PathBuf,
    pub(super) db: PathBuf,
    pub(super) wal: PathBuf,
    pub(super) shm: PathBuf,
    pub(super) audit: PathBuf,
    pub(super) lock: PathBuf,
    pub(super) quarantine: PathBuf,
}

/// The kernel store's file name.
pub const KERNEL_DB: &str = "kernel.db";
/// The authoritative audit log's file name.
pub const AUDIT_LOG: &str = "audit.log";
/// The process lock's file name.
pub const LOCK_FILE: &str = "authority.lock";
/// The quarantine marker's file name. Written **beside** the store, never in
/// it ([`STORAGE.md`] §3).
///
/// [`STORAGE.md`]: ../../../../../docs/STORAGE.md
pub const QUARANTINE_MARKER: &str = "kernel.quarantined";

impl StatePaths {
    pub(super) fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            db: dir.join(KERNEL_DB),
            wal: dir.join(format!("{KERNEL_DB}-wal")),
            shm: dir.join(format!("{KERNEL_DB}-shm")),
            audit: dir.join(AUDIT_LOG),
            lock: dir.join(LOCK_FILE),
            quarantine: dir.join(QUARANTINE_MARKER),
        }
    }
}

/// What the directory held when the authority started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layout {
    /// Nothing: a new store may be created.
    Fresh,
    /// `kernel.db` and `audit.log` both exist.
    Existing,
}

fn io(context: &str, error: &std::io::Error) -> StartError {
    StartError::Io(format!("{context}: {error}"))
}

/// Create the state directory if it is absent, private from the first moment.
pub(super) fn prepare_directory(dir: &Path) -> Result<(), StartError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(dir)
                .map_err(|e| io("creating the state directory", &e))?;
            if let Some(parent) = dir.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(io("inspecting the state directory", &error)),
    }
}

/// Refuse a state directory the authority does not privately own.
pub(super) fn check_directory(dir: &Path) -> Result<(), StartError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| io("inspecting the state directory", &e))?;
    if meta.file_type().is_symlink() {
        return Err(StartError::Permissions(format!(
            "{} is a symlink; the state directory must be a real directory",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(StartError::Layout(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(StartError::Permissions(format!(
                "{} has mode {mode:o}; the state directory must be private (0700): a user who can \
                 write the directory can replace kernel.db without writing it",
                dir.display()
            )));
        }
        let owner = effective_uid(dir)?;
        if meta.uid() != owner {
            return Err(StartError::Permissions(format!(
                "{} is owned by uid {}, not by the authority (uid {owner})",
                dir.display(),
                meta.uid()
            )));
        }
    }
    Ok(())
}

/// Refuse a state file that is a symlink, not a regular file, or not private.
/// A file that does not exist passes: absence is judged by [`layout`].
pub(super) fn check_file(path: &Path) -> Result<(), StartError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io("inspecting a state file", &error)),
    };
    if meta.file_type().is_symlink() {
        return Err(StartError::Permissions(format!(
            "{} is a symlink; a state file must be a real file in the state directory",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(StartError::Layout(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(StartError::Permissions(format!(
                "{} has mode {mode:o}; state files must be private (0600)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Which files exist, and whether that combination is one the authority may
/// proceed from.
///
/// **A missing `kernel.db` beside surviving state is not a fresh start.** If
/// `audit.log` or a WAL file survives without the database, something removed
/// the store the runtime is constrained by, and creating an empty one would be
/// the fail-open this module exists to prevent.
pub(super) fn layout(paths: &StatePaths) -> Result<Layout, StartError> {
    let exists = |path: &Path| fs::symlink_metadata(path).is_ok();
    let db = exists(&paths.db);
    let audit = exists(&paths.audit);
    let wal = exists(&paths.wal);
    let shm = exists(&paths.shm);
    match (db, audit, wal || shm) {
        (false, false, false) => Ok(Layout::Fresh),
        (true, true, _) => Ok(Layout::Existing),
        (false, _, _) => Err(StartError::Layout(
            "kernel.db is missing while other authority state survives; refusing to create an \
             empty store over it"
                .to_owned(),
        )),
        (true, false, _) => Err(StartError::Layout(
            "audit.log is missing beside an existing kernel.db; the audit chain is not recreated"
                .to_owned(),
        )),
    }
}

/// Create a new private file, failing if it already exists.
pub(super) fn create_private_file(path: &Path) -> Result<File, StartError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| io("creating a state file", &e))?;
    file.sync_all()
        .map_err(|e| io("syncing a new state file", &e))?;
    Ok(file)
}

/// Take the directory's exclusive lock, held for the life of the authority.
///
/// One authority process per state directory. A second start — in another
/// process or in this one — fails rather than sharing a store whose
/// single-writer discipline assumes one owner. The operating system releases
/// the lock when the process dies, so a crash never leaves it held.
pub(super) fn lock(paths: &StatePaths) -> Result<File, StartError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|e| io("opening the authority lock", &e))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(StartError::Locked),
        Err(fs::TryLockError::Error(error)) => Err(io("taking the authority lock", &error)),
    }
}

/// The quarantine marker's contents, if one is present.
pub(super) fn quarantine_marker(paths: &StatePaths) -> Option<String> {
    fs::symlink_metadata(&paths.quarantine).ok()?;
    Some(
        fs::read_to_string(&paths.quarantine)
            .unwrap_or_else(|_| "an unreadable quarantine marker is present".to_owned()),
    )
}

/// Write the quarantine marker. Best effort: if the directory cannot be
/// written, the in-memory poison still holds, and the next start re-verifies
/// the store from its files and refuses on the same evidence.
pub(super) fn write_quarantine(paths: &StatePaths, reason: &str) {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(&paths.quarantine) {
        let _ = file.write_all(reason.as_bytes());
        let _ = file.write_all(b"\n");
        let _ = file.sync_all();
        let _ = sync_directory(&paths.dir);
    }
}

/// Make a directory's entries durable: a new file or a rename is not crash-safe
/// until the directory itself is synced.
pub(super) fn sync_directory(dir: &Path) -> Result<(), StartError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|e| io("syncing a directory", &e))?;
    }
    #[cfg(not(unix))]
    {
        // Windows cannot open a directory as a file without a flag std does
        // not expose; NTFS journals directory entries itself.
        let _ = dir;
    }
    Ok(())
}

/// The authority's effective uid, without `libc`.
///
/// The standard library does not expose `geteuid`. A file created with
/// `O_EXCL` is owned by the creating process's effective uid, so creating one
/// and reading its owner answers the question with no dependency and no
/// assumption about `/proc`.
#[cfg(unix)]
fn effective_uid(dir: &Path) -> Result<u32, StartError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static PROBES: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // `O_EXCL` makes a name collision an error rather than a shared file, so a
    // few attempts with fresh names are enough and none can read a stale probe.
    for _ in 0..8 {
        let attempt = PROBES.fetch_add(1, Ordering::Relaxed);
        let probe = dir.join(format!(".uid-probe-{nanos}-{attempt}"));
        let file = match create_private_file(&probe) {
            Ok(file) => file,
            Err(StartError::Io(_)) if fs::symlink_metadata(&probe).is_ok() => continue,
            Err(other) => return Err(other),
        };
        let uid = file
            .metadata()
            .map_err(|e| io("reading the uid probe", &e))?
            .uid();
        drop(file);
        fs::remove_file(&probe).map_err(|e| io("removing the uid probe", &e))?;
        return Ok(uid);
    }
    Err(StartError::Io(
        "could not create a uid probe in the state directory".to_owned(),
    ))
}
