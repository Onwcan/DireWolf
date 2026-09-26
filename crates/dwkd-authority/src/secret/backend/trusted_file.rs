//! Reading an operator-configured store file on Linux without trusting its
//! path (ADR-0046 §8): each component is opened relative to the previous one
//! with `O_NOFOLLOW`, every directory must be one only root or the authority
//! can change (unless sticky), and the file itself must be regular, owned by
//! root or the authority, accessible by nobody else, and within a size bound.
//!
//! One of the files in the authority that may name `rustix` (TX008).

use std::io::Read as _;
use std::os::fd::OwnedFd;

use rustix::fs::{FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::secret::SecretError;
use crate::secret::metadata::AgeFile;

fn untrusted(_: Errno) -> SecretError {
    SecretError::StoreUntrusted
}

fn open_error(errno: Errno) -> SecretError {
    match errno {
        Errno::NOENT => SecretError::BackendItemMissing,
        Errno::ACCESS | Errno::PERM => SecretError::BackendDenied,
        _ => SecretError::StoreUntrusted,
    }
}

fn trusted_directory(st: &Stat, trusted_owner: u32) -> bool {
    let owner_ok = st.st_uid == 0 || st.st_uid == trusted_owner;
    let mode = st.st_mode;
    let writable_by_others = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    owner_ok
        && FileType::from_raw_mode(mode) == FileType::Directory
        && (!writable_by_others || sticky)
}

/// Read `file` whole, or refuse. `forbidden` are the mode bits the file may
/// not have: `0o077` for a store (nobody else may even read it), `0o022` for
/// the metadata file (nobody else may write it; it holds no value).
pub(super) fn read(
    file: &AgeFile,
    trusted_owner: u32,
    max_bytes: u64,
    forbidden: u32,
) -> Result<Vec<u8>, SecretError> {
    let components: Vec<&str> = file.components().collect();
    let (name, directories) = components.split_last().ok_or(SecretError::StoreUntrusted)?;
    let root = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(untrusted)?;
    let root_st = rustix::fs::fstat(&root).map_err(untrusted)?;
    if !trusted_directory(&root_st, trusted_owner) {
        return Err(SecretError::StoreUntrusted);
    }
    let mut dir: OwnedFd = root;
    for component in directories {
        let next = rustix::fs::openat(
            &dir,
            *component,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(open_error)?;
        let st = rustix::fs::fstat(&next).map_err(untrusted)?;
        if !trusted_directory(&st, trusted_owner) {
            return Err(SecretError::StoreUntrusted);
        }
        dir = next;
    }
    let fd = rustix::fs::openat(
        &dir,
        *name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        if errno == Errno::LOOP {
            SecretError::StoreUntrusted
        } else {
            open_error(errno)
        }
    })?;
    let st = rustix::fs::fstat(&fd).map_err(untrusted)?;
    let size = u64::try_from(st.st_size).map_err(|_| SecretError::StoreUntrusted)?;
    let owner_ok = st.st_uid == 0 || st.st_uid == trusted_owner;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || !owner_ok
        || st.st_mode & forbidden != 0
        || st.st_mode & 0o6000 != 0
        || size > max_bytes
    {
        return Err(SecretError::StoreUntrusted);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    std::fs::File::from(fd)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SecretError::StoreUntrusted)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(SecretError::StoreUntrusted);
    }
    Ok(bytes)
}
