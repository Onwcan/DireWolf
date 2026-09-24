//! The broker's one listener: a Unix-domain socket in a directory only the
//! broker can change (M4b, ADR-0043). The only place in the broker that binds
//! or accepts anything (TX009).
//!
//! # Who is read from
//!
//! Every accepted connection is asked, through `SO_PEERCRED`, which uid the
//! kernel recorded when the peer called `connect(2)`. Unless it is the
//! configured authority uid, the connection is closed **before a single byte
//! is read from it or written to it**: the runtime, the CLI, any other local
//! user can reach the socket, and none of them can say anything to the broker.
//! The file mode of the socket is therefore not the access control — the
//! kernel-reported uid is.
//!
//! # Why the name is protected anyway
//!
//! The authority checks the broker's uid in the same way before it sends
//! anything, so a process that bound its own socket at the broker's name would
//! receive nothing. Protecting the name keeps it from becoming a denial of
//! service: the directory is the broker's, is not writable by group or other,
//! and its ancestors are root's or the broker's (sticky directories excepted),
//! exactly the rules the authority applies to its own socket (ADR-0041). The
//! code is not shared: the broker may not depend on the authority (RS002), and
//! each daemon's socket rules are reviewed where they run.
//!
//! # One connection at a time
//!
//! Connections are served in order, each under a deadline. An authorised
//! exchange is one file read of at most 256 KiB, so serialising them bounds
//! the broker's memory and descriptors to one exchange's worth whatever the
//! authority sends; a peer that is not the authority costs one `accept` and
//! one `getsockopt`.

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

use crate::exchange;
use crate::nonce::Channels;

/// The mode the broker gives a socket directory it creates.
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

/// A checked socket directory and the socket name in it, under the lock.
#[derive(Debug)]
pub(crate) struct SocketPlace {
    dir: PathBuf,
    path: PathBuf,
    /// Held for the life of the process: one broker per socket name.
    _lock: File,
}

impl SocketPlace {
    /// The socket path the broker binds.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// The broker's effective uid, learnt without `libc`: a file created `O_EXCL`
/// is owned by the creating process's effective uid.
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

fn prepare_directory(dir: &Path) -> Result<(), SocketError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| io("creating the socket directory", dir, &e))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(IPC_DIR_MODE))
                .map_err(|e| io("setting the mode of the socket directory", dir, &e))
        }
        Err(error) => Err(io("inspecting the socket directory", dir, &error)),
    }
}

fn check_directory(dir: &Path, owner: u32) -> Result<fs::Metadata, SocketError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| io("inspecting", dir, &e))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(SocketError::new(format!(
            "the socket directory {} must be a real directory",
            dir.display()
        )));
    }
    if meta.uid() != owner {
        return Err(SocketError::new(format!(
            "the socket directory {} is owned by uid {}, not by the broker (uid {owner})",
            dir.display(),
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(SocketError::new(format!(
            "the socket directory {} has mode {mode:o}; a group or other write bit would let \
             someone else remove or replace the socket",
            dir.display()
        )));
    }
    Ok(meta)
}

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
                 or to the broker (uid {owner})",
                ancestor.display(),
                meta.uid()
            )));
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(SocketError::new(format!(
                "{} has mode {mode:o}; a directory above the socket that others can write, \
                 without the sticky bit, lets them rename the socket directory away",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

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
            "another broker holds {}",
            path.display()
        ))),
        Err(fs::TryLockError::Error(error)) => Err(io("taking the socket lock", &path, &error)),
    }
}

/// Remove whatever occupies the socket name only if it is provably this
/// broker's own dead socket; refuse and name it otherwise.
fn clear_stale(path: &Path, owner: u32) -> Result<(), SocketError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
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
            "{} is {what}; the broker never removes anything at its socket path that is not \
             its own dead socket",
            path.display()
        )));
    }
    if meta.uid() != owner {
        return Err(SocketError::new(format!(
            "{} is a socket owned by uid {}, not by the broker (uid {owner}); it is not removed",
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
            let again = fs::symlink_metadata(path).map_err(|e| io("inspecting", path, &e))?;
            if (again.dev(), again.ino()) != (meta.dev(), meta.ino()) {
                return Err(SocketError::new(format!(
                    "{} changed while it was being inspected",
                    path.display()
                )));
            }
            fs::remove_file(path).map_err(|e| io("removing the stale socket", path, &e))
        }
        Err(error) => Err(io("probing the existing socket", path, &error)),
    }
}

/// Check where the socket will live, take the lock and clear the name if it
/// holds this broker's own dead socket. Returns the place and the broker's
/// effective uid.
///
/// # Errors
///
/// [`SocketError`] naming what is wrong. Nothing is removed on any error path.
pub(crate) fn prepare(socket: &Path) -> Result<(SocketPlace, u32), SocketError> {
    let (dir, name) = split(socket)?;
    prepare_directory(&dir)?;
    let first = fs::symlink_metadata(&dir).map_err(|e| io("inspecting", &dir, &e))?;
    if first.file_type().is_symlink() || !first.is_dir() {
        return Err(SocketError::new(format!(
            "the socket directory {} must be a real directory",
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
    clear_stale(&path, owner)?;
    Ok((
        SocketPlace {
            dir: resolved,
            path,
            _lock: lock,
        },
        owner,
    ))
}

/// The bound listener, which removes its own socket file when dropped — and
/// only its own.
#[derive(Debug)]
pub(crate) struct Bound {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
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
/// The directory changed, the bind failed, or the mode could not be set (the
/// just-bound socket is then removed again by [`Bound`]'s drop).
pub(crate) fn bind(place: &SocketPlace) -> Result<Bound, SocketError> {
    let meta = fs::symlink_metadata(&place.dir).map_err(|e| io("inspecting", &place.dir, &e))?;
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(SocketError::new(format!(
            "the socket directory {} changed before the socket was bound",
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

/// Serve connections, one at a time, for as long as the process lives.
pub(crate) fn serve(bound: &Bound, authority_uid: u32, own_uid: u32, channels: &mut Channels) {
    for incoming in bound.listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                crate::event(&format!("accept_failed error={:?}", error.kind()));
                continue;
            }
        };
        // Who connected, as the kernel recorded it. Nothing has been read and
        // nothing will be, unless it is the authority.
        let Ok(cred) = rustix::net::sockopt::socket_peercred(&stream) else {
            crate::event("peer_unknown");
            continue;
        };
        let peer = cred.uid.as_raw();
        if peer != authority_uid {
            crate::event(&format!("peer_refused peer_uid={peer}"));
            drop(stream);
            continue;
        }
        crate::event(&format!("connection peer_uid={peer}"));
        exchange::serve_one(&stream, channels.issue(), own_uid);
        crate::event("closed");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    use super::{IPC_DIR_MODE, SOCKET_MODE, bind, prepare};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path =
                std::env::temp_dir().join(format!("dwb-{tag}-{}-{nanos}", std::process::id()));
            must(fs::create_dir(&path), "scratch");
            must(
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)),
                "scratch mode",
            );
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
    fn a_fresh_directory_is_created_closed_to_writers_and_the_socket_removed_on_drop() {
        let scratch = Scratch::new("fresh");
        let socket = scratch.0.join("ipc").join("broker.sock");
        let (place, _) = must(prepare(&socket), "prepare");
        let dir = must(fs::symlink_metadata(scratch.0.join("ipc")), "dir");
        assert_eq!(dir.permissions().mode() & 0o7777, IPC_DIR_MODE);
        let bound = must(bind(&place), "bind");
        let meta = must(fs::symlink_metadata(place.path()), "socket");
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        drop(bound);
        assert!(fs::symlink_metadata(place.path()).is_err());
    }

    #[test]
    fn a_second_broker_on_the_same_name_is_refused_by_the_lock() {
        let scratch = Scratch::new("lock");
        let socket = scratch.0.join("ipc").join("broker.sock");
        let held = must(prepare(&socket), "first");
        assert!(refused(&socket).contains("another broker"));
        drop(held);
        assert!(prepare(&socket).is_ok());
    }

    #[test]
    fn a_writable_or_symlinked_directory_and_a_foreign_name_are_refused() {
        let scratch = Scratch::new("rules");
        let dir = scratch.0.join("ipc");
        must(fs::create_dir(&dir), "dir");
        for mode in [0o775, 0o733, 0o722, 0o1777] {
            must(
                fs::set_permissions(&dir, fs::Permissions::from_mode(mode)),
                "chmod",
            );
            assert!(
                refused(&dir.join("broker.sock")).contains("write bit"),
                "{mode:o}"
            );
        }
        must(
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)),
            "chmod",
        );
        let alias = scratch.0.join("alias");
        must(std::os::unix::fs::symlink(&dir, &alias), "link");
        assert!(refused(&alias.join("broker.sock")).contains("real directory"));

        let name = dir.join("broker.sock");
        must(fs::write(&name, b"not a socket"), "file");
        assert!(refused(&name).contains("a regular file"));
        assert_eq!(must(fs::read(&name), "survives"), b"not a socket");
        must(fs::remove_file(&name), "cleanup");

        let live = must(UnixListener::bind(&name), "live");
        assert!(refused(&name).contains("live socket"));
        drop(live);
        assert!(prepare(&name).is_ok(), "our own dead socket is cleared");
    }

    #[test]
    fn a_relative_or_nameless_socket_path_is_refused() {
        assert!(refused(Path::new("broker.sock")).contains("not absolute"));
        assert!(refused(Path::new("/")).contains("plain file name"));
    }
}
