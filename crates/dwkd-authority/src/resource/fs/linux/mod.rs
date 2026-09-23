//! The Linux resolver: `openat2` relative to held descriptors, through
//! `rustix`'s safe wrappers ([ADR-0042] §4).
//!
//! One of the two modules in the authority that may name `rustix` (TX008; the
//! other is `server/peer.rs`). Every call here is relative to a descriptor the
//! caller already holds — the pinned root, or the previous component — except
//! opening the root itself, which is by the operator's recorded path and is
//! then proved against the installed fingerprint.
//!
//! ```text
//! for each component, outermost first:
//!     fd    = openat2(parent, name, O_PATH | O_NOFOLLOW [| O_DIRECTORY],
//!                     RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
//!                   | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)
//!     st    = fstat(fd)                       -- the object's own identity
//!     kind  = directory | regular file        -- anything else refused
//!     list(parent): an entry spelled exactly `name`, and no other entry
//!                   canonically equivalent to it
//! then, leaf first:
//!     statat(parent, name, AT_SYMLINK_NOFOLLOW) == st   -- every link still binds
//! ```
//!
//! `O_PATH` throughout: resolution opens nothing for reading, so a FIFO cannot
//! block it and a device cannot be triggered by it, and it needs no permission
//! on the object beyond reaching it. Listing a directory needs read permission
//! and opens a separate descriptor for it, relative to the held one.
//!
//! **No fallback.** A kernel without `openat2` (before 5.6), or a seccomp
//! filter that refuses it, gets [`ResolveError::Unsupported`]: there is no
//! reduced-assurance walk to fall back to, so nothing is silently weaker.
//!
//! [ADR-0042]: ../../../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

#[cfg(test)]
mod tests;

use rustix::fd::{AsFd as _, BorrowedFd, OwnedFd};
use rustix::fs::{self as sys, AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, StatxFlags};
use rustix::io::Errno;

use super::{
    BirthTime, FileIdentity, PathError, ResolveError, ResourceKind, RootError, RootFingerprint,
    Walked,
};
use crate::resource::PathComponent;

/// A live descriptor.
pub(in crate::resource) type Fd = OwnedFd;

/// The resolution constraints every component is opened under.
///
/// * `BENEATH` — nothing may resolve outside the descriptor it starts from;
///   `..` above it and absolute paths are refused by the kernel.
/// * `NO_SYMLINKS` — no symlink is followed at any position, and it implies
///   `NO_MAGICLINKS`; named anyway so that the intent survives a reading of
///   this line alone.
/// * `NO_MAGICLINKS` — `/proc/<pid>/{cwd,root,exe,fd/N}` are never followed.
/// * `NO_XDEV` — no mount point, bind mount included, is crossed.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

/// The most entries one directory listing may yield in one resolution. A
/// directory larger than this is refused, not partially checked: a
/// normalisation twin could be the entry after the cut.
const MAX_LISTING_ENTRIES: usize = 65_536;

/// sysfs's `f_type`. Not exported by rustix; the value is the kernel's
/// `SYSFS_MAGIC`.
const SYSFS_MAGIC: i128 = 0x6265_6572;

/// Widen a kernel integer without a lossy cast. `st_nlink` is `u32` on some
/// targets and `u64` on others; a conversion written once for both would be
/// flagged as useless on one of them.
fn widen<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

/// As [`widen`], for a signed filesystem word.
fn word<T: Into<i128>>(value: T) -> i128 {
    value.into()
}

fn identity(st: &Stat) -> FileIdentity {
    FileIdentity::new(widen(st.st_dev), widen(st.st_ino))
}

/// Open a workspace root by the operator's path and measure it.
pub(in crate::resource) fn open_root(
    host: &str,
) -> Result<(OwnedFd, FileIdentity, RootFingerprint), RootError> {
    let fd = sys::open(
        host,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| root_error(host, errno))?;
    let st = sys::fstat(&fd).map_err(root_io)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(RootError::NotADirectory);
    }
    let filesystem = sys::fstatfs(&fd).map_err(root_io)?;
    if filesystem.f_type == sys::PROC_SUPER_MAGIC || word(filesystem.f_type) == SYSFS_MAGIC {
        return Err(RootError::UnsupportedFilesystem);
    }
    let id = identity(&st);
    let fingerprint = RootFingerprint::new(id.device(), id.inode(), birth_time(&fd));
    Ok((fd, id, fingerprint))
}

/// The directory's birth time, where the filesystem reports one.
fn birth_time(fd: &OwnedFd) -> Option<BirthTime> {
    let found = sys::statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::BTIME).ok()?;
    if found.stx_mask & StatxFlags::BTIME.bits() == 0 {
        return None;
    }
    Some(BirthTime {
        seconds: found.stx_btime.tv_sec,
        nanoseconds: found.stx_btime.tv_nsec,
    })
}

fn root_error(host: &str, errno: Errno) -> RootError {
    match errno {
        Errno::NOENT => RootError::Missing,
        // `O_NOFOLLOW` on a symlink is `ELOOP`; with `O_PATH | O_DIRECTORY` it
        // can be `ENOTDIR`. Either way, find out which it was — a lookup for
        // the error's name only; nothing is opened by it.
        Errno::LOOP | Errno::NOTDIR => {
            match sys::statat(sys::CWD, host, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
                    RootError::Symlink
                }
                _ => RootError::NotADirectory,
            }
        }
        Errno::ACCESS => RootError::PermissionDenied,
        other => RootError::Io(other.raw_os_error()),
    }
}

fn root_io(errno: Errno) -> RootError {
    RootError::Io(errno.raw_os_error())
}

/// Resolve `names` beneath the pinned root.
pub(in crate::resource) fn walk(
    root: &OwnedFd,
    root_id: FileIdentity,
    names: &[PathComponent],
) -> Result<Walked, ResolveError> {
    if names.is_empty() {
        // `/workspace` itself: a fresh handle on the root, proved to be it.
        let leaf = here(root.as_fd(), 0)?;
        let st = sys::fstat(&leaf).map_err(|errno| io(0, errno))?;
        if identity(&st) != root_id {
            return Err(ResolveError::Race { depth: 0 });
        }
        return Ok(Walked {
            identity: root_id,
            kind: ResourceKind::Directory,
            links: widen(st.st_nlink),
            leaf,
            parent: None,
        });
    }

    let mut opened: Vec<(OwnedFd, FileIdentity)> = Vec::with_capacity(names.len());
    let mut last: Option<(ResourceKind, u64)> = None;
    for (index, name) in names.iter().enumerate() {
        let depth = index + 1;
        let is_leaf = depth == names.len();
        let parent = opened.last().map_or(root.as_fd(), |(fd, _)| fd.as_fd());
        let fd = open_child(parent, name.as_str(), !is_leaf, depth)?;
        let st = sys::fstat(&fd).map_err(|errno| io(depth, errno))?;
        let kind = classify(parent, &st, is_leaf, depth)?;
        verify_entry(parent, name.as_str(), depth)?;
        opened.push((fd, identity(&st)));
        last = Some((kind, widen(st.st_nlink)));
    }
    verify_chain(root.as_fd(), &opened, names)?;

    let Some((kind, links)) = last else {
        return Err(ResolveError::Race { depth: 0 });
    };
    let Some((leaf, leaf_id)) = opened.pop() else {
        return Err(ResolveError::Race { depth: 0 });
    };
    let Some(name) = names.last() else {
        return Err(ResolveError::Race { depth: 0 });
    };
    let parent = if let Some((fd, _)) = opened.pop() {
        fd
    } else {
        // A leaf directly under the root: the parent is the root, so hold a
        // fresh handle on it rather than the root's own.
        let parent = here(root.as_fd(), 0)?;
        let st = sys::fstat(&parent).map_err(|errno| io(0, errno))?;
        if identity(&st) != root_id {
            return Err(ResolveError::Race { depth: 0 });
        }
        parent
    };
    Ok(Walked {
        identity: leaf_id,
        kind,
        links,
        leaf,
        parent: Some((parent, name.clone())),
    })
}

/// A new `O_PATH` handle on the directory `dir` refers to.
fn here(dir: BorrowedFd<'_>, depth: usize) -> Result<OwnedFd, ResolveError> {
    sys::openat2(
        dir,
        ".",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )
    .map_err(|errno| io(depth, errno))
}

/// Open one component beneath `parent`.
fn open_child(
    parent: BorrowedFd<'_>,
    name: &str,
    directory: bool,
    depth: usize,
) -> Result<OwnedFd, ResolveError> {
    let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    sys::openat2(parent, name, flags, Mode::empty(), RESOLVE)
        .map_err(|errno| open_error(parent, name, errno, depth))
}

/// What the opened object is, from its own descriptor.
fn classify(
    parent: BorrowedFd<'_>,
    st: &Stat,
    is_leaf: bool,
    depth: usize,
) -> Result<ResourceKind, ResolveError> {
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => Ok(ResourceKind::Directory),
        FileType::RegularFile if is_leaf => Ok(ResourceKind::RegularFile),
        // `O_PATH | O_NOFOLLOW` on a trailing symlink returns the link itself.
        FileType::Symlink => Err(link_refusal(parent, depth)),
        FileType::RegularFile => Err(ResolveError::NotADirectory { depth }),
        _ if is_leaf => Err(ResolveError::SpecialFile { depth }),
        _ => Err(ResolveError::NotADirectory { depth }),
    }
}

/// Prove the directory holds an entry spelled exactly `name`, and no other
/// entry canonically equivalent to it.
fn verify_entry(parent: BorrowedFd<'_>, name: &str, depth: usize) -> Result<(), ResolveError> {
    verify_entry_within(parent, name, depth, MAX_LISTING_ENTRIES)
}

/// [`verify_entry`] with the listing bound as a parameter, so the bound itself
/// can be tested without creating `MAX_LISTING_ENTRIES` files.
fn verify_entry_within(
    parent: BorrowedFd<'_>,
    name: &str,
    depth: usize,
    limit: usize,
) -> Result<(), ResolveError> {
    let listing = sys::openat2(
        parent,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )
    .map_err(|errno| match errno {
        Errno::ACCESS => ResolveError::PermissionDenied { depth },
        other => io(depth, other),
    })?;
    let entries = sys::Dir::new(listing).map_err(|errno| io(depth, errno))?;
    let mut exact = false;
    for (count, entry) in entries.enumerate() {
        if count >= limit {
            return Err(ResolveError::DirectoryTooLarge { depth });
        }
        let entry = entry.map_err(|errno| io(depth, errno))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == name.as_bytes() {
            exact = true;
        } else if let Ok(sibling) = core::str::from_utf8(bytes)
            && super::names::equivalent(sibling, name)
        {
            return Err(ResolveError::NormalizationAmbiguity { depth });
        }
        // A name that is not UTF-8 cannot equal a UTF-8 name and cannot be
        // spelled in a declaration: it is neither a match nor an ambiguity.
    }
    if exact {
        Ok(())
    } else {
        Err(ResolveError::NameMismatch { depth })
    }
}

/// Every name in the chain still binds to the object opened for it, checked
/// from the leaf up after the whole walk.
fn verify_chain(
    root: BorrowedFd<'_>,
    opened: &[(OwnedFd, FileIdentity)],
    names: &[PathComponent],
) -> Result<(), ResolveError> {
    let parents = core::iter::once(root).chain(opened.iter().map(|(fd, _)| fd.as_fd()));
    let links: Vec<_> = parents.zip(opened.iter()).zip(names.iter()).collect();
    for (index, ((parent, (_, expected)), name)) in links.into_iter().enumerate().rev() {
        let depth = index + 1;
        let bound =
            sys::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map(|st| identity(&st));
        if bound != Ok(*expected) {
            return Err(ResolveError::Race { depth });
        }
    }
    Ok(())
}

/// Whether a resolved object is still the one its name binds to.
pub(in crate::resource) fn still_bound(
    leaf: &OwnedFd,
    parent: Option<(&OwnedFd, &PathComponent)>,
    expected: FileIdentity,
) -> Result<(), ResolveError> {
    let held = sys::fstat(leaf).map(|st| identity(&st));
    if held != Ok(expected) {
        return Err(ResolveError::Race { depth: 0 });
    }
    if let Some((parent, name)) = parent {
        let bound =
            sys::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map(|st| identity(&st));
        if bound != Ok(expected) {
            return Err(ResolveError::Race { depth: 0 });
        }
    }
    Ok(())
}

/// A refusal to follow a link: a magic link when the directory holding it is
/// procfs, a symlink otherwise.
fn link_refusal(parent: BorrowedFd<'_>, depth: usize) -> ResolveError {
    match sys::fstatfs(parent) {
        Ok(filesystem) if filesystem.f_type == sys::PROC_SUPER_MAGIC => {
            ResolveError::MagicLink { depth }
        }
        _ => ResolveError::Symlink { depth },
    }
}

fn open_error(parent: BorrowedFd<'_>, name: &str, errno: Errno, depth: usize) -> ResolveError {
    match errno {
        Errno::NOENT => ResolveError::NotFound { depth },
        Errno::LOOP => link_refusal(parent, depth),
        // An intermediate symlink opened with `O_DIRECTORY` can be `ENOTDIR`;
        // tell it from a plain file. A lookup for the error's name only.
        Errno::NOTDIR => match sys::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
                link_refusal(parent, depth)
            }
            _ => ResolveError::NotADirectory { depth },
        },
        Errno::XDEV => ResolveError::MountCrossing { depth },
        Errno::ACCESS => ResolveError::PermissionDenied { depth },
        // `openat2` reports a concurrent rename it could not rule out.
        Errno::AGAIN => ResolveError::Race { depth },
        Errno::NAMETOOLONG => ResolveError::Path(PathError::NameTooLong { index: depth }),
        // No `openat2` (before 5.6), a seccomp filter refusing it, or a kernel
        // that does not know one of the RESOLVE flags: not supported, and not
        // quietly done some weaker way.
        Errno::NOSYS | Errno::PERM | Errno::INVAL | Errno::TOOBIG => ResolveError::Unsupported,
        other => io(depth, other),
    }
}

fn io(depth: usize, errno: Errno) -> ResolveError {
    ResolveError::Io {
        depth,
        errno: errno.raw_os_error(),
    }
}
