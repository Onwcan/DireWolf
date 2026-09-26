//! The Linux executable resolver (M4d, [ADR-0045] §5): `openat` relative to
//! held descriptors, one component at a time, through `rustix`'s safe
//! wrappers.
//!
//! ```text
//! dir  = open("/", O_PATH | O_DIRECTORY)
//! for each pending segment:
//!     fd   = openat(dir, name, O_PATH | O_NOFOLLOW)     -- one name, never a path
//!     st   = fstat(fd)
//!     symlink   -> readlinkat(fd, "") ; splice its target in front ; count <= 32
//!     directory -> fstatfs(fd) not proc/sys/network/user-space ;
//!                  owner in {0, authority} ; not group/other-writable unless sticky
//!     regular   -> must be the last segment
//! the file:
//!     execute bit ; no setuid/setgid ; owner in {0, authority} ; not g/o-writable
//!     fstatfs not a network or user-space filesystem ; size <= 512 MiB
//!     file = openat(parent, name, O_RDONLY | O_NOFOLLOW)  == the O_PATH identity
//!     no security.capability ; ELF magic ("#!" is a script)
//!     sha256 by pread ; size, mtime and ctime unchanged across the hash
//!     close file
//! re-walk the canonical components from "/" following NOTHING:
//!     every directory the one recorded, the leaf the one hashed
//! ```
//!
//! **Mount crossings are allowed**, unlike the workspace resolver's: an
//! executable lives where the host installed it, not beneath a root the
//! authority pinned. What a crossing could hide — a filesystem whose bytes a
//! server or a user-space daemon controls — is refused by type instead.
//!
//! One of the files in the authority that may name `rustix` (TX008).
//!
//! [ADR-0045]: ../../../../../docs/adr/0045-m4d-process-execution-broker.md

use std::collections::VecDeque;

use dwk_proto::limits::MAX_EXECUTABLE_BYTES;
use rustix::fd::{AsFd as _, BorrowedFd, OwnedFd};
use rustix::fs::{self as sys, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest as _, Sha256};

use super::{ExecError, Found, MAX_SYMLINKS, Untrusted};
use crate::resource::PathComponent;
use crate::resource::fs::{FileIdentity, single_component};

/// A live descriptor.
pub(super) type Fd = OwnedFd;

/// Filesystems whose content a party other than the local kernel serves or
/// can change without a local write, and the two whose objects are the
/// kernel's own views: `f_type`, as the kernel's `*_MAGIC` constants.
const UNTRUSTED_FILESYSTEMS: [u32; 12] = [
    0x0000_9fa0, // PROC_SUPER_MAGIC
    0x6265_6572, // SYSFS_MAGIC
    0x0000_6969, // NFS_SUPER_MAGIC
    0x0000_517b, // SMB_SUPER_MAGIC
    0xfe53_4d42, // SMB2_MAGIC_NUMBER
    0xff53_4d42, // CIFS_SUPER_MAGIC
    0x0102_1997, // V9FS_MAGIC
    0x6573_5546, // FUSE_SUPER_MAGIC
    0x5346_414f, // AFS_SUPER_MAGIC
    0x6b41_4653, // AFS_FS_MAGIC
    0x00c3_6400, // CEPH_SUPER_MAGIC
    0x7375_7245, // CODA_SUPER_MAGIC
];

/// The ELF magic.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// How much is read per `pread` while hashing.
const HASH_CHUNK: usize = 64 * 1024;

/// Widen a kernel integer without a lossy cast (field widths differ between
/// targets).
fn word<T: Into<i128>>(value: T) -> i128 {
    value.into()
}

/// As [`word`], unsigned: `st_dev` and `st_ino` are `u64` on some targets and
/// narrower on others, so a conversion written once for both would be flagged
/// as useless on one of them.
fn widen<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

fn identity(st: &Stat) -> FileIdentity {
    FileIdentity::new(widen(st.st_dev), widen(st.st_ino))
}

fn io(errno: Errno) -> ExecError {
    ExecError::Io(errno.raw_os_error())
}

/// Where the pending walk goes next.
enum Segment {
    /// Look up one name in the current directory.
    Name(PathComponent),
    /// Go to the current directory's parent (a `..` in a link target).
    Parent,
}

/// One directory on the canonical path, as the walk found it.
struct Directory {
    fd: OwnedFd,
    name: PathComponent,
    identity: FileIdentity,
}

/// Resolve `components` from `/`, following symbolic links, and hash the
/// regular file they end at. `trusted_owner` is the authority's own uid.
pub(super) fn resolve(
    components: &[PathComponent],
    trusted_owner: u32,
) -> Result<Found, ExecError> {
    let root = sys::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let root_st = sys::fstat(&root).map_err(io)?;
    trusted_directory(&root, &root_st, trusted_owner)?;
    let root_id = identity(&root_st);

    let mut stack: Vec<Directory> = Vec::new();
    let mut pending: VecDeque<Segment> = components.iter().cloned().map(Segment::Name).collect();
    let mut symlinks = 0usize;
    let leaf = loop {
        let Some(segment) = pending.pop_front() else {
            // The path ended on a directory.
            return Err(ExecError::NotRegular);
        };
        let name = match segment {
            Segment::Parent => {
                // `..` never climbs above `/`, as the kernel's does not.
                let _ = stack.pop();
                continue;
            }
            Segment::Name(name) => name,
        };
        let parent = stack.last().map_or(root.as_fd(), |d| d.fd.as_fd());
        let fd = sys::openat(
            parent,
            name.as_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(open_error)?;
        let st = sys::fstat(&fd).map_err(io)?;
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Symlink => {
                symlinks = symlinks.saturating_add(1);
                if symlinks > MAX_SYMLINKS {
                    return Err(ExecError::SymlinkLimit);
                }
                // The link this descriptor holds, not whatever the name binds
                // by now.
                let target = sys::readlinkat(&fd, "", Vec::new()).map_err(io)?;
                let target = target.to_str().map_err(|_| ExecError::PathInvalid)?;
                if target.starts_with('/') {
                    stack.clear();
                }
                for segment in link_segments(target)?.into_iter().rev() {
                    pending.push_front(segment);
                }
            }
            FileType::Directory => {
                trusted_directory(&fd, &st, trusted_owner)?;
                stack.push(Directory {
                    fd,
                    name,
                    identity: identity(&st),
                });
            }
            FileType::RegularFile if pending.is_empty() => break (fd, st, name),
            FileType::RegularFile => return Err(ExecError::NotADirectory),
            _ if pending.is_empty() => return Err(ExecError::NotRegular),
            _ => return Err(ExecError::NotADirectory),
        }
    };
    let (leaf, leaf_st, leaf_name) = leaf;
    let object = identity(&leaf_st);
    let size = trusted_file(&leaf, &leaf_st, trusted_owner)?;

    let parent = stack.last().map_or(root.as_fd(), |d| d.fd.as_fd());
    let file = open_regular(parent, &leaf_name, object)?;
    no_file_capabilities(&file)?;
    let digest = hash(&file, &leaf_st, size)?;
    drop(file);

    // Every component again, from the root, following nothing: the canonical
    // path is symlink-free and binds the object that was hashed.
    reverify(&root, root_id, &stack, &leaf_name, object)?;

    let mut canonical: Vec<PathComponent> = stack.iter().map(|d| d.name.clone()).collect();
    canonical.push(leaf_name);
    let parent = match stack.pop() {
        Some(directory) => directory.fd,
        None => root,
    };
    Ok(Found {
        canonical,
        leaf,
        parent,
        object,
        size,
        digest,
        symlinks,
    })
}

/// A link target's segments: absolute or relative, `.` and empty segments
/// dropped, `..` kept as a step up, every name one the grammar accepts. The
/// target is filesystem data, not a request's spelling, so a `..` or `//` in
/// it is read as the kernel reads it; a name the grammar refuses is refused.
fn link_segments(target: &str) -> Result<Vec<Segment>, ExecError> {
    if target.is_empty() || target.len() > dwk_proto::limits::MAX_EXECUTABLE_PATH_BYTES {
        return Err(ExecError::PathInvalid);
    }
    let mut segments = Vec::new();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => segments.push(Segment::Parent),
            name => segments.push(Segment::Name(
                single_component(name).map_err(|_| ExecError::PathInvalid)?,
            )),
        }
    }
    Ok(segments)
}

/// Whether the filesystem an object lives on is one whose bytes the local
/// kernel alone controls.
fn trusted_filesystem(fd: &OwnedFd) -> Result<(), ExecError> {
    let filesystem = sys::fstatfs(fd).map_err(io)?;
    // `f_type` is signed on some targets; compare its low 32 bits, which is
    // all any magic occupies.
    let magic = word(filesystem.f_type) & 0xffff_ffff;
    if UNTRUSTED_FILESYSTEMS.iter().any(|m| word(*m) == magic) {
        return Err(ExecError::Untrusted(Untrusted::Filesystem));
    }
    Ok(())
}

/// A directory on the canonical path: on a trusted filesystem, owned by root
/// or the authority, and not writable by anyone else unless sticky (where only
/// an entry's owner may rename or remove it).
fn trusted_directory(fd: &OwnedFd, st: &Stat, trusted_owner: u32) -> Result<(), ExecError> {
    trusted_filesystem(fd)?;
    let owner = st.st_uid;
    if owner != 0 && owner != trusted_owner {
        return Err(ExecError::Untrusted(Untrusted::Directory));
    }
    let mode = st.st_mode;
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(ExecError::Untrusted(Untrusted::Directory));
    }
    Ok(())
}

/// The file itself: executable, no set-id bit, owned by root or the
/// authority, not writable by group or others, on a trusted filesystem, within
/// the size bound. Returns its size.
fn trusted_file(fd: &OwnedFd, st: &Stat, trusted_owner: u32) -> Result<u64, ExecError> {
    let mode = st.st_mode;
    if mode & 0o111 == 0 {
        return Err(ExecError::NotExecutable);
    }
    if mode & 0o6000 != 0 {
        return Err(ExecError::Untrusted(Untrusted::SetId));
    }
    let owner = st.st_uid;
    if owner != 0 && owner != trusted_owner {
        return Err(ExecError::Untrusted(Untrusted::Owner));
    }
    if mode & 0o022 != 0 {
        return Err(ExecError::Untrusted(Untrusted::Writable));
    }
    trusted_filesystem(fd)?;
    let size = u64::try_from(word(st.st_size)).map_err(|_| ExecError::Race)?;
    if size > MAX_EXECUTABLE_BYTES {
        return Err(ExecError::TooLarge);
    }
    Ok(size)
}

/// Open the checked file for reading, relative to its directory by its one
/// name, and prove it is the object checked. `O_NONBLOCK` keeps a FIFO a racer
/// swapped in from blocking the open; identity then refuses it.
fn open_regular(
    parent: BorrowedFd<'_>,
    name: &PathComponent,
    expected: FileIdentity,
) -> Result<OwnedFd, ExecError> {
    let file = sys::openat(
        parent,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(open_error)?;
    let st = sys::fstat(&file).map_err(io)?;
    if identity(&st) != expected || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(ExecError::Race);
    }
    Ok(file)
}

/// No file capabilities: executing a file that carries them would give the
/// process privileges the broker does not have.
fn no_file_capabilities(file: &OwnedFd) -> Result<(), ExecError> {
    let mut value = [0u8; 64];
    match sys::fgetxattr(file, "security.capability", &mut value[..]) {
        Ok(_) | Err(Errno::RANGE) => Err(ExecError::Untrusted(Untrusted::Capabilities)),
        // None set, or a filesystem that cannot hold one.
        Err(Errno::NODATA | Errno::OPNOTSUPP) => Ok(()),
        Err(other) => Err(io(other)),
    }
}

/// Read exactly `size` bytes through `file`, checking the magic first, and
/// return their SHA-256. The file's size, modification and change times must
/// be the same after as before: a write while hashing is a race, not a digest.
fn hash(file: &OwnedFd, before: &Stat, size: u64) -> Result<[u8; 32], ExecError> {
    let mut magic = [0u8; 4];
    let got = pread_full(file, &mut magic, 0)?;
    if got < 2 {
        return Err(ExecError::NotNative);
    }
    if magic.starts_with(b"#!") {
        return Err(ExecError::Script);
    }
    if got < magic.len() || magic != ELF_MAGIC {
        return Err(ExecError::NotNative);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut offset = 0u64;
    loop {
        let read = pread_full(file, &mut buffer, offset)?;
        if read == 0 {
            break;
        }
        let chunk = buffer.get(..read).ok_or(ExecError::Race)?;
        hasher.update(chunk);
        offset = offset.saturating_add(u64::try_from(read).map_err(|_| ExecError::Race)?);
        if offset > size {
            return Err(ExecError::Race);
        }
    }
    if offset != size {
        return Err(ExecError::Race);
    }
    let after = sys::fstat(file).map_err(io)?;
    let unchanged = word(after.st_size) == word(before.st_size)
        && word(after.st_mtime) == word(before.st_mtime)
        && word(after.st_mtime_nsec) == word(before.st_mtime_nsec)
        && word(after.st_ctime) == word(before.st_ctime)
        && word(after.st_ctime_nsec) == word(before.st_ctime_nsec);
    if !unchanged {
        return Err(ExecError::Race);
    }
    Ok(hasher.finalize().into())
}

/// `pread` until `buffer` is full or the file ends, retrying an interrupted
/// call.
fn pread_full(file: &OwnedFd, buffer: &mut [u8], offset: u64) -> Result<usize, ExecError> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let at = offset.saturating_add(u64::try_from(filled).map_err(|_| ExecError::Race)?);
        let Some(rest) = buffer.get_mut(filled..) else {
            break;
        };
        match rustix::io::pread(file, rest, at) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(other) => return Err(io(other)),
        }
    }
    Ok(filled)
}

/// Walk the canonical components again from a fresh handle on `/`, following
/// nothing: each directory must be the one recorded, and the leaf the object
/// that was hashed.
fn reverify(
    root: &OwnedFd,
    root_id: FileIdentity,
    stack: &[Directory],
    leaf: &PathComponent,
    object: FileIdentity,
) -> Result<(), ExecError> {
    let again = sys::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let st = sys::fstat(&again).map_err(io)?;
    if identity(&st) != root_id || sys::fstat(root).map(|s| identity(&s)) != Ok(root_id) {
        return Err(ExecError::Race);
    }
    let mut current = again;
    for directory in stack {
        let next = sys::openat(
            &current,
            directory.name.as_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecError::Race)?;
        let st = sys::fstat(&next).map_err(io)?;
        if identity(&st) != directory.identity
            || FileType::from_raw_mode(st.st_mode) != FileType::Directory
        {
            return Err(ExecError::Race);
        }
        current = next;
    }
    let st = sys::statat(&current, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecError::Race)?;
    if identity(&st) != object || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(ExecError::Race);
    }
    Ok(())
}

/// The executable descriptor (step 4 of a launch): the name still binds the
/// object, the object is still what was checked, and the file opened for
/// reading by that name is it.
pub(super) fn open_for_exec(
    leaf: &OwnedFd,
    parent: &OwnedFd,
    name: &PathComponent,
    expected: FileIdentity,
    trusted_owner: u32,
) -> Result<OwnedFd, ExecError> {
    let held = sys::fstat(leaf).map_err(io)?;
    if identity(&held) != expected {
        return Err(ExecError::Race);
    }
    let bound = sys::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecError::Race)?;
    if identity(&bound) != expected {
        return Err(ExecError::Race);
    }
    let file = open_regular(parent.as_fd(), name, expected)?;
    let st = sys::fstat(&file).map_err(io)?;
    trusted_file(&file, &st, trusted_owner)?;
    no_file_capabilities(&file)?;
    Ok(file)
}

fn open_error(errno: Errno) -> ExecError {
    match errno {
        Errno::NOENT => ExecError::NotFound,
        Errno::NOTDIR => ExecError::NotADirectory,
        Errno::ACCESS => ExecError::PermissionDenied,
        Errno::NAMETOOLONG => ExecError::PathInvalid,
        // `O_NOFOLLOW` on a symlink swapped in after the `O_PATH` look.
        Errno::LOOP => ExecError::Race,
        other => io(other),
    }
}
