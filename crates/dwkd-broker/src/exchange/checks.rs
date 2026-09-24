//! What a received descriptor must be before anything is done through it.
//!
//! Every descriptor an authorisation carries has one fixed role
//! (`PrivateKind::descriptors`), and each role has one shape:
//!
//! | role | open mode | kind |
//! |---|---|---|
//! | a file to read (`fs_read`, `fs_search`, `fs_patch`'s second) | read-only, not `O_PATH` | regular file |
//! | a directory to list, or whose names change | read-only, not `O_PATH` | directory |
//! | an object to `fstat` (`fs_stat`) | `O_PATH` only | regular file or directory |
//!
//! and its `(st_dev, st_ino)` must be the one the authorisation names. The
//! first mismatch refuses, before a byte is read or a name is touched.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{BrokerRefusal, KernelNumber};
use rustix::fs::{FileType, OFlags, Stat};

/// Widen a kernel integer without a lossy cast.
pub(super) fn widen<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

/// A stat's `(device, inode)`.
pub(super) fn identity(st: &Stat) -> (u64, u64) {
    (widen(st.st_dev), widen(st.st_ino))
}

/// The pair an authorisation names.
pub(super) fn named(device: &KernelNumber, inode: &KernelNumber) -> (u64, u64) {
    (device.value(), inode.value())
}

/// The kinds a read-only descriptor may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// A descriptor open for reading, and only reading, on the object `want` of
/// kind `kind`.
pub(super) fn readable(fd: &OwnedFd, kind: Kind, want: (u64, u64)) -> Result<Stat, BrokerRefusal> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| BrokerRefusal::DescriptorNotReadable)?;
    if flags.contains(OFlags::PATH) || flags & OFlags::RWMODE != OFlags::RDONLY {
        return Err(BrokerRefusal::DescriptorNotReadable);
    }
    let st = rustix::fs::fstat(fd).map_err(|_| BrokerRefusal::ReadFailed)?;
    let found = FileType::from_raw_mode(st.st_mode);
    match kind {
        Kind::File if found != FileType::RegularFile => {
            return Err(BrokerRefusal::DescriptorNotRegular);
        }
        Kind::Directory if found != FileType::Directory => {
            return Err(BrokerRefusal::DescriptorNotDirectory);
        }
        Kind::File | Kind::Directory => {}
    }
    if identity(&st) != want {
        return Err(BrokerRefusal::IdentityMismatch);
    }
    Ok(st)
}

/// An `O_PATH` descriptor — one that can name the object and do nothing else
/// — on the regular file or directory `want`.
pub(super) fn path_only(fd: &OwnedFd, want: (u64, u64)) -> Result<Stat, BrokerRefusal> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| BrokerRefusal::DescriptorNotPath)?;
    if !flags.contains(OFlags::PATH) {
        return Err(BrokerRefusal::DescriptorNotPath);
    }
    let st = rustix::fs::fstat(fd).map_err(|_| BrokerRefusal::ReadFailed)?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile | FileType::Directory => {}
        _ => return Err(BrokerRefusal::DescriptorNotRegular),
    }
    if identity(&st) != want {
        return Err(BrokerRefusal::IdentityMismatch);
    }
    Ok(st)
}
