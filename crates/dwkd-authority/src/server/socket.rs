//! The socket's name is part of the security boundary.
//!
//! Peer credentials stop another local process from impersonating the
//! **runtime** to the authority. They do nothing to stop the runtime from
//! impersonating the **authority** to anyone else: a process that could unlink
//! `kernel.sock`, rename something over it or bind its own socket at that name
//! would receive every later connection — from the CLI, from a restarted
//! runtime — and answer as the authority. So the name is protected by the
//! filesystem, and this module refuses to serve from a name it cannot protect
//! ([ADR-0041]).
//!
//! # The rules
//!
//! * The socket path is **absolute** and its final component is never
//!   followed: a symlink there is refused, whatever it points at.
//! * Its parent — the **IPC directory** — is a real directory, owned by the
//!   authority's uid, and **not writable by group or other**. Only the
//!   authority can create, remove or rename a name in it. The authority
//!   creates it (mode `0711`: others may reach the socket, not list or change
//!   the directory) when it is absent; an operator who wants the filesystem to
//!   narrow who can even connect pre-creates it `0710` with the runtime's group
//!   and the authority accepts that.
//! * Every **ancestor** of the IPC directory, after resolving symlinks once and
//!   proving by `(device, inode)` that the resolution is the directory that was
//!   checked, is owned by root or by the authority and is not writable by group
//!   or other — unless it is sticky (`/tmp`), where no one can rename or remove
//!   an entry they do not own. A writable ancestor would let its writer move
//!   the IPC directory aside and put its own in its place.
//! * The socket is bound only after all of that holds, so there is no moment
//!   at which an unchecked directory holds the listening socket. Its mode is
//!   then set to `0666`: the file mode is **not** DireWolf's access control —
//!   the kernel-reported uid is — and the default mode a bind produces is never
//!   wider than `0666` in any way that matters for a socket (`connect` needs
//!   write permission, which both grant), so there is no pre-permission window
//!   to close.
//!
//! # Stale sockets
//!
//! A killed authority leaves its socket file behind. At startup, under an
//! exclusive lock on `<name>.lock` in the IPC directory, the name is inspected
//! **without following it** and removed only when every one of these holds:
//! it is a socket, it is owned by the authority's uid, it is in the checked
//! IPC directory, and connecting to it is refused — no listener owns it. A
//! regular file, a directory, a symlink, a FIFO, a socket owned by anyone else
//! or a socket something is listening on is **never** removed: the server
//! refuses to start and names what it found.
//!
//! [ADR-0041]: ../../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

use core::fmt;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
    PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};

/// The mode the authority gives an IPC directory it creates.
pub(crate) const IPC_DIR_MODE: u32 = 0o711;

/// The mode the bound socket is given. Not an access control: see the module
/// documentation.
pub(crate) const SOCKET_MODE: u32 = 0o666;

/// Why the socket path cannot be served from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketError(String);

impl SocketError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn io(context: &str, path: &Path, error: &std::io::Error) -> SocketError {
    SocketError::new(format!("{context} {}: {error}", path.display()))
}

/// A checked IPC directory and the socket name in it, under the startup lock.
#[derive(Debug)]
pub(crate) struct SocketPlace {
    /// The IPC directory, ancestors resolved.
    dir: PathBuf,
    /// The socket's full path in it.
    path: PathBuf,
    /// Held for the life of the process: one server per socket name.
    _lock: File,
}

impl SocketPlace {
    /// The socket path the server binds and clients connect to.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// The authority's effective uid, learnt without `libc`: a file created
/// `O_EXCL` is owned by the creating process's effective uid.
///
/// The probe is created in the IPC directory, which is the one place the
/// authority must be able to create files anyway.
fn effective_uid(dir: &Path) -> Result<u32, SocketError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for attempt in 0..8u32 {
        let probe = dir.join(format!(
            ".uid-probe-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io("creating a uid probe in", dir, &error)),
        };
        let uid = file
            .metadata()
            .map_err(|e| io("reading the uid probe in", dir, &e))?
            .uid();
        drop(file);
        fs::remove_file(&probe).map_err(|e| io("removing the uid probe in", dir, &e))?;
        return Ok(uid);
    }
    Err(SocketError::new(format!(
        "could not create a uid probe in {}",
        dir.display()
    )))
}

/// Split an absolute socket path into its directory and a plain final name.
fn split(socket: &Path) -> Result<(PathBuf, OsString), SocketError> {
    if !socket.is_absolute() {
        return Err(SocketError::new(format!(
            "{} is not absolute",
            socket.display()
        )));
    }
    let Some(Component::Normal(name)) = socket.components().next_back() else {
        return Err(SocketError::new(format!(
            "{} does not end in a plain file name",
            socket.display()
        )));
    };
    let Some(dir) = socket.parent() else {
        return Err(SocketError::new(format!(
            "{} has no directory",
            socket.display()
        )));
    };
    Ok((dir.to_path_buf(), name.to_os_string()))
}

/// Create the IPC directory if it is absent — only the final component: its
/// ancestors are the operator's to provide — with mode [`IPC_DIR_MODE`] set
/// explicitly, so no umask decides it.
fn prepare_directory(dir: &Path) -> Result<(), SocketError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| io("creating the IPC directory", dir, &e))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(IPC_DIR_MODE))
                .map_err(|e| io("setting the mode of the IPC directory", dir, &e))
        }
        Err(error) => Err(io("inspecting the IPC directory", dir, &error)),
    }
}

/// The IPC directory must be a real directory the authority owns that no one
/// else can write.
fn check_directory(dir: &Path, owner: u32) -> Result<fs::Metadata, SocketError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| io("inspecting", dir, &e))?;
    if meta.file_type().is_symlink() {
        return Err(SocketError::new(format!(
            "the IPC directory {} is a symlink; it must be a real directory",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(SocketError::new(format!(
            "the IPC directory {} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != owner {
        return Err(SocketError::new(format!(
            "the IPC directory {} is owned by uid {}, not by the authority (uid {owner})",
            dir.display(),
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(SocketError::new(format!(
            "the IPC directory {} has mode {mode:o}; a group or other write bit would let \
             someone else remove or replace the socket",
            dir.display()
        )));
    }
    Ok(meta)
}

/// Resolve the IPC directory's ancestors once and prove the result is the
/// directory that was checked.
fn resolve(dir: &Path, checked: &fs::Metadata) -> Result<PathBuf, SocketError> {
    let resolved = fs::canonicalize(dir).map_err(|e| io("resolving", dir, &e))?;
    let target = fs::symlink_metadata(&resolved).map_err(|e| io("inspecting", &resolved, &e))?;
    let same = !target.file_type().is_symlink()
        && target.is_dir()
        && (target.dev(), target.ino()) == (checked.dev(), checked.ino());
    if same {
        Ok(resolved)
    } else {
        Err(SocketError::new(format!(
            "{} resolved to {}, which is not the directory that was checked",
            dir.display(),
            resolved.display()
        )))
    }
}

/// Every ancestor of the resolved IPC directory is owned by root or the
/// authority, and is not writable by group or other unless it is sticky.
fn check_ancestors(resolved: &Path, owner: u32) -> Result<(), SocketError> {
    for ancestor in resolved.ancestors().skip(1) {
        let meta = fs::symlink_metadata(ancestor).map_err(|e| io("inspecting", ancestor, &e))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(SocketError::new(format!(
                "{} is not a directory after resolution",
                ancestor.display()
            )));
        }
        if meta.uid() != 0 && meta.uid() != owner {
            return Err(SocketError::new(format!(
                "{} is owned by uid {}; every directory above the socket must belong to root \
                 or to the authority (uid {owner}), or its owner could replace the IPC \
                 directory",
                ancestor.display(),
                meta.uid()
            )));
        }
        let mode = meta.permissions().mode() & 0o7777;
        let sticky = mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !sticky {
            return Err(SocketError::new(format!(
                "{} has mode {mode:o}; a directory above the socket that others can write, \
                 without the sticky bit, lets them rename the IPC directory away",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// Take the socket name's exclusive lock, held for the life of the process.
fn lock(dir: &Path, name: &OsString) -> Result<File, SocketError> {
    let mut lock_name = name.clone();
    lock_name.push(".lock");
    let path = dir.join(lock_name);
    if let Ok(meta) = fs::symlink_metadata(&path)
        && !meta.is_file()
    {
        return Err(SocketError::new(format!(
            "{} exists and is not a regular file",
            path.display()
        )));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| io("opening the socket lock", &path, &e))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(SocketError::new(format!(
            "another authority holds {}",
            path.display()
        ))),
        Err(fs::TryLockError::Error(error)) => Err(io("taking the socket lock", &path, &error)),
    }
}

/// What a stale-socket inspection decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existing {
    /// Nothing is at the name.
    Absent,
    /// A socket this authority left behind, which no one is listening on. It
    /// was removed.
    StaleRemoved,
}

/// Inspect whatever occupies the socket name, and remove it only if it is
/// provably this authority's own dead socket.
fn clear_stale(path: &Path, owner: u32) -> Result<Existing, SocketError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Existing::Absent),
        Err(error) => return Err(io("inspecting", path, &error)),
    };
    let kind = meta.file_type();
    let what = if kind.is_symlink() {
        Some("a symlink")
    } else if kind.is_dir() {
        Some("a directory")
    } else if kind.is_file() {
        Some("a regular file")
    } else if kind.is_fifo() {
        Some("a FIFO")
    } else if !kind.is_socket() {
        Some("not a socket")
    } else {
        None
    };
    if let Some(what) = what {
        return Err(SocketError::new(format!(
            "{} is {what}; the authority never removes anything at its socket path that is not \
             its own dead socket",
            path.display()
        )));
    }
    if meta.uid() != owner {
        return Err(SocketError::new(format!(
            "{} is a socket owned by uid {}, not by the authority (uid {owner}); it is not removed",
            path.display(),
            meta.uid()
        )));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(SocketError::new(format!(
            "{} is a live socket: something is listening on it",
            path.display()
        ))),
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            // Re-check that the name still holds the object that was
            // inspected: only the authority's uid can change this directory,
            // and the lock excludes another authority, so this guards against
            // a bug rather than an attacker.
            let again = fs::symlink_metadata(path).map_err(|e| io("inspecting", path, &e))?;
            if (again.dev(), again.ino()) != (meta.dev(), meta.ino()) {
                return Err(SocketError::new(format!(
                    "{} changed while it was being inspected",
                    path.display()
                )));
            }
            fs::remove_file(path).map_err(|e| io("removing the stale socket", path, &e))?;
            Ok(Existing::StaleRemoved)
        }
        Err(error) => Err(io("probing the existing socket", path, &error)),
    }
}

/// Check everything about where the socket will live, take the lock, and
/// clear the name if it holds this authority's own dead socket. Returns the
/// place, the authority's effective uid (learnt by a probe in the IPC
/// directory) and what occupied the name.
///
/// # Errors
///
/// [`SocketError`] naming what is wrong. Nothing is removed on any error path.
pub(crate) fn prepare(socket: &Path) -> Result<(SocketPlace, u32, Existing), SocketError> {
    let (dir, name) = split(socket)?;
    prepare_directory(&dir)?;
    let first = fs::symlink_metadata(&dir).map_err(|e| io("inspecting", &dir, &e))?;
    if first.file_type().is_symlink() || !first.is_dir() {
        return Err(SocketError::new(format!(
            "the IPC directory {} must be a real directory",
            dir.display()
        )));
    }
    let owner = effective_uid(&dir)?;
    let checked = check_directory(&dir, owner)?;
    let resolved = resolve(&dir, &checked)?;
    check_directory(&resolved, owner)?;
    check_ancestors(&resolved, owner)?;
    let lock = lock(&resolved, &name)?;
    let path = resolved.join(&name);
    let existing = clear_stale(&path, owner)?;
    Ok((
        SocketPlace {
            dir: resolved,
            path,
            _lock: lock,
        },
        owner,
        existing,
    ))
}

/// The bound listener, which removes its own socket file when dropped — and
/// only its own: the name is removed only if it still holds the inode that was
/// bound.
#[derive(Debug)]
pub(crate) struct Bound {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Bound {
    /// The listener.
    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && (meta.dev(), meta.ino()) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Bind the socket in the checked place and set its mode.
///
/// # Errors
///
/// The bind failed (the name is taken, or the path is longer than a socket
/// address holds), or the mode could not be set; in the latter case the
/// just-bound socket is removed again.
pub(crate) fn bind(place: &SocketPlace) -> Result<Bound, SocketError> {
    // Re-check the directory immediately before binding: the lock excludes
    // another authority, and nothing else can write it, so this is a
    // belt-and-braces check that the checked place is still the place.
    let meta = fs::symlink_metadata(&place.dir).map_err(|e| io("inspecting", &place.dir, &e))?;
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(SocketError::new(format!(
            "the IPC directory {} changed before the socket was bound",
            place.dir.display()
        )));
    }
    let listener = UnixListener::bind(&place.path).map_err(|e| io("binding", &place.path, &e))?;
    let bound_meta =
        fs::symlink_metadata(&place.path).map_err(|e| io("inspecting", &place.path, &e))?;
    let bound = Bound {
        listener,
        path: place.path.clone(),
        identity: (bound_meta.dev(), bound_meta.ino()),
    };
    fs::set_permissions(&place.path, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| io("setting the mode of", &place.path, &e))?;
    Ok(bound)
}

// Linux only: the server runs nowhere else, and elsewhere a temporary
// directory's path can be longer than a socket address holds.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use super::{Existing, IPC_DIR_MODE, bind, prepare};
    use crate::scratch::Scratch;

    fn must<T, E: core::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{what}: {error:?}"),
        }
    }

    fn refused(socket: &Path) -> String {
        match prepare(socket) {
            Ok(_) => unreachable!("{} was accepted", socket.display()),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_fresh_directory_is_created_owned_and_closed_to_writers() {
        let scratch = Scratch::new("socket-fresh");
        let socket = scratch.path().join("ipc").join("kernel.sock");
        let (place, _, existing) = must(prepare(&socket), "prepare");
        assert_eq!(existing, Existing::Absent);
        let dir = must(fs::symlink_metadata(scratch.path().join("ipc")), "ipc dir");
        assert_eq!(dir.permissions().mode() & 0o7777, IPC_DIR_MODE);
        let bound = must(bind(&place), "bind");
        let meta = must(fs::symlink_metadata(place.path()), "socket");
        assert_eq!(meta.permissions().mode() & 0o777, super::SOCKET_MODE);
        drop(bound);
        assert!(
            fs::symlink_metadata(place.path()).is_err(),
            "removed on drop"
        );
    }

    #[test]
    fn a_second_server_on_the_same_name_is_refused_by_the_lock() {
        let scratch = Scratch::new("socket-lock");
        let socket = scratch.path().join("ipc").join("kernel.sock");
        let held = must(prepare(&socket), "first");
        assert!(refused(&socket).contains("another authority"));
        drop(held);
        assert!(prepare(&socket).is_ok());
    }

    #[test]
    fn a_writable_ipc_directory_is_refused() {
        let scratch = Scratch::new("socket-mode");
        let dir = scratch.path().join("ipc");
        must(fs::create_dir(&dir), "dir");
        for mode in [0o775, 0o733, 0o722, 0o1777] {
            must(
                fs::set_permissions(&dir, fs::Permissions::from_mode(mode)),
                "chmod",
            );
            assert!(
                refused(&dir.join("kernel.sock")).contains("write bit"),
                "{mode:o}"
            );
        }
        must(
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o710)),
            "chmod",
        );
        assert!(
            prepare(&dir.join("kernel.sock")).is_ok(),
            "0710 is an operator choice"
        );
    }

    #[test]
    fn a_symlinked_ipc_directory_or_socket_name_is_never_followed() {
        let scratch = Scratch::new("socket-links");
        let real = scratch.path().join("real");
        must(fs::create_dir(&real), "real");
        must(
            fs::set_permissions(&real, fs::Permissions::from_mode(0o711)),
            "chmod",
        );
        let alias = scratch.path().join("alias");
        must(std::os::unix::fs::symlink(&real, &alias), "dir link");
        assert!(refused(&alias.join("kernel.sock")).contains("real directory"));

        // A symlink AT the socket name, pointing at a socket we own: refused,
        // and the link and its target both survive.
        let target = real.join("elsewhere.sock");
        let listener = must(UnixListener::bind(&target), "a socket elsewhere");
        drop(listener);
        let name = real.join("kernel.sock");
        must(std::os::unix::fs::symlink(&target, &name), "name link");
        assert!(refused(&name).contains("a symlink"));
        assert!(fs::symlink_metadata(&name).is_ok());
        assert!(fs::symlink_metadata(&target).is_ok());
    }

    #[test]
    fn only_a_dead_socket_of_our_own_is_ever_removed() {
        let scratch = Scratch::new("socket-stale");
        let dir = scratch.path().join("ipc");
        must(fs::create_dir(&dir), "dir");
        must(
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)),
            "chmod",
        );
        let name = dir.join("kernel.sock");

        // A regular file, a directory and a FIFO-free set of impostors: each
        // refused, each left exactly where it was.
        must(fs::write(&name, b"not a socket"), "file");
        assert!(refused(&name).contains("a regular file"));
        assert_eq!(must(fs::read(&name), "file survives"), b"not a socket");
        must(fs::remove_file(&name), "cleanup");
        must(fs::create_dir(&name), "directory");
        assert!(refused(&name).contains("a directory"));
        assert!(must(fs::symlink_metadata(&name), "dir survives").is_dir());
        must(fs::remove_dir(&name), "cleanup");

        // A live listener: refused, and it keeps listening.
        let live = must(UnixListener::bind(&name), "live");
        assert!(refused(&name).contains("live socket"));
        assert!(std::os::unix::net::UnixStream::connect(&name).is_ok());
        drop(live);

        // The same socket, dead: removed, and the server binds in its place.
        let (place, _, existing) = must(prepare(&name), "stale");
        assert_eq!(existing, Existing::StaleRemoved);
        assert!(bind(&place).is_ok());
    }

    #[test]
    fn a_relative_or_nameless_socket_path_is_refused() {
        assert!(refused(Path::new("kernel.sock")).contains("not absolute"));
        assert!(refused(Path::new("/")).contains("plain file name"));
    }
}
