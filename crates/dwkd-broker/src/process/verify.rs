//! The broker's re-proof of a launch's descriptors (ADR-0045 §9), made
//! immediately before the helper is started, through the very descriptor
//! that will be executed — never the authority's word for it.
//!
//! | descriptor | must be |
//! |---|---|
//! | 0, the executable | open read-only (not `O_PATH`), a regular file, the `(st_dev, st_ino)` authorised |
//! | 1, the working directory | open read-only (not `O_PATH`), a directory, the `(st_dev, st_ino)` authorised |
//!
//! and the executable must still meet the byte-stability contract the
//! authority's resolver applied — owner root or the authority, no group or
//! other write, no set-id bit, no file capabilities, not on a network or
//! user-space filesystem, at most 512 MiB — start with the ELF magic, and
//! hash, through this descriptor, to the digest the authority decided on.
//! The first mismatch refuses; nothing is started.
//!
//! What this cannot close is the instant between the hash and `execveat`: a
//! principal who may write the file — root, or the authority's uid — could
//! change it there. No other principal can (that is what the contract
//! checks), and the kernel refuses writes to it once it executes
//! (`ETXTBSY`). ADR-0045 §5 records that residual trust.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{BrokerRefusal, ProcessStartAuthorisation};
use dwk_proto::limits::MAX_EXECUTABLE_BYTES;
use rustix::fs::Stat;
use rustix::io::Errno;
use sha2::{Digest as _, Sha256};

use crate::exchange::checks::{self, Kind};

/// Filesystems whose bytes the local kernel alone does not control, and its
/// own views: `f_type`, as the kernel's `*_MAGIC` constants (the authority's
/// resolver refuses the same set).
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

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

fn word<T: Into<i128>>(value: T) -> i128 {
    value.into()
}

/// Both descriptors of a launch, each its role's mode, kind and object, and
/// the executable its digest.
///
/// # Errors
///
/// The refusal: nothing may be started.
pub(super) fn descriptors(
    start: &ProcessStartAuthorisation,
    executable: &OwnedFd,
    cwd: &OwnedFd,
    authority_uid: u32,
) -> Result<(), BrokerRefusal> {
    let st = checks::readable(
        executable,
        Kind::File,
        checks::named(&start.executable_device, &start.executable_inode),
    )?;
    checks::readable(
        cwd,
        Kind::Directory,
        checks::named(&start.cwd_device, &start.cwd_inode),
    )?;
    trusted(executable, &st, authority_uid)?;
    let digest = hash(executable, &st)?;
    if digest != start.executable_sha256.as_str() {
        return Err(BrokerRefusal::DigestMismatch);
    }
    Ok(())
}

/// The byte-stability contract, and the executable bit.
fn trusted(fd: &OwnedFd, st: &Stat, authority_uid: u32) -> Result<(), BrokerRefusal> {
    let untrusted = Err(BrokerRefusal::ExecutableUntrusted);
    let mode = st.st_mode;
    if mode & 0o111 == 0 || mode & 0o6000 != 0 || mode & 0o022 != 0 {
        return untrusted;
    }
    if st.st_uid != 0 && st.st_uid != authority_uid {
        return untrusted;
    }
    let size = u64::try_from(word(st.st_size)).map_err(|_| BrokerRefusal::ExecutableUntrusted)?;
    if size > MAX_EXECUTABLE_BYTES {
        return untrusted;
    }
    let filesystem = rustix::fs::fstatfs(fd).map_err(|_| BrokerRefusal::ReadFailed)?;
    let magic = word(filesystem.f_type) & 0xffff_ffff;
    if UNTRUSTED_FILESYSTEMS.iter().any(|m| word(*m) == magic) {
        return untrusted;
    }
    let mut value = [0u8; 64];
    match rustix::fs::fgetxattr(fd, "security.capability", &mut value[..]) {
        Err(Errno::NODATA | Errno::OPNOTSUPP) => Ok(()),
        Ok(_) | Err(Errno::RANGE) => untrusted,
        Err(_) => Err(BrokerRefusal::ReadFailed),
    }
}

/// `pread` until `buffer` is full or the file ends.
fn pread_full(fd: &OwnedFd, buffer: &mut [u8], offset: u64) -> Result<usize, BrokerRefusal> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
        let Some(rest) = buffer.get_mut(filled..) else {
            break;
        };
        match rustix::io::pread(fd, rest, at) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(_) => return Err(BrokerRefusal::ReadFailed),
        }
    }
    Ok(filled)
}

/// The ELF magic, then the SHA-256 of exactly `st_size` bytes, with the size
/// and both times unchanged across the read: lowercase hex.
fn hash(fd: &OwnedFd, before: &Stat) -> Result<String, BrokerRefusal> {
    let mut magic = [0u8; 4];
    if pread_full(fd, &mut magic, 0)? != magic.len() || magic != ELF_MAGIC {
        return Err(BrokerRefusal::ExecutableUntrusted);
    }
    let size = u64::try_from(word(before.st_size)).map_err(|_| BrokerRefusal::ReadFailed)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let read = pread_full(fd, &mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).ok_or(BrokerRefusal::ReadFailed)?);
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if offset > size {
            return Err(BrokerRefusal::DigestMismatch);
        }
    }
    let after = rustix::fs::fstat(fd).map_err(|_| BrokerRefusal::ReadFailed)?;
    let unchanged = offset == size
        && word(after.st_size) == word(before.st_size)
        && word(after.st_mtime) == word(before.st_mtime)
        && word(after.st_mtime_nsec) == word(before.st_mtime_nsec)
        && word(after.st_ctime) == word(before.st_ctime)
        && word(after.st_ctime_nsec) == word(before.st_ctime_nsec);
    if !unchanged {
        return Err(BrokerRefusal::DigestMismatch);
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}
