//! The operations that change nothing: `fs.read` (M4b), `fs.stat` and
//! `fs.list` (M4c). `fs.search` is in `search`.
//!
//! Each works through the one descriptor the authority opened and proved,
//! after re-proving it here: the file opened for reading, the object held as
//! `O_PATH`, the directory opened for reading. None has a name to open.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, FsListAuthorisation, FsListDone, FsReadAuthorisation, FsReadDone,
    FsStatAuthorisation, FsStatDone, ModeBits, OutcomeResult, RawEntry, RawName,
};
use dwk_proto::limits::MAX_LIST_SCAN_ENTRIES;
use dwk_proto::wire::list::BoundedList;
use dwk_proto::wire::scalar::{ByteCount, EntryKind, HexContent, LinkCount, StatKind};
use rustix::fs::FileType;
use rustix::io::Errno;

use super::checks::{self, Kind, named};

/// `fs.read`: at most `max_bytes` from offset zero of the file.
pub(super) fn read(authorisation: &FsReadAuthorisation, file: &OwnedFd) -> OutcomeResult {
    let want = named(&authorisation.device, &authorisation.inode);
    if let Err(refusal) = checks::readable(file, Kind::File, want) {
        return OutcomeResult::Refused(refusal);
    }
    match read_bounded(file, authorisation.max_bytes.get()) {
        Some(done) => OutcomeResult::done(BrokerDone::read(done)),
        None => OutcomeResult::Refused(BrokerRefusal::ReadFailed),
    }
}

/// Read at most `max_bytes` from offset zero of the handed descriptor.
pub(super) fn read_bounded(file: &OwnedFd, max_bytes: u32) -> Option<FsReadDone> {
    let content = read_within(max_bytes, |window, offset| {
        rustix::io::pread(file, window, offset)
    })?;
    Some(FsReadDone {
        content: HexContent::from_bytes(&content.0)?,
        eof_observed: content.1,
    })
}

/// Read at most `max_bytes` bytes from offset zero through `read_at`, asking
/// for no byte past the bound: every window ends at `max_bytes`, and no read
/// is made once it is reached. The end of the file is reported only when a
/// read returned nothing before the bound — never discovered by reading past
/// it. The buffer is sized from the bound, which decoding has already limited,
/// so nothing is allocated before the bound is known to hold.
///
/// `read_at` is the file: `pread` in production, a counting double in tests.
/// Returns the bytes and whether the end was observed.
pub(super) fn read_within(
    max_bytes: u32,
    mut read_at: impl FnMut(&mut [u8], u64) -> Result<usize, Errno>,
) -> Option<(Vec<u8>, bool)> {
    let bound = usize::try_from(max_bytes).ok()?;
    let mut content = vec![0u8; bound];
    let mut filled = 0usize;
    let mut eof_observed = false;
    while filled < bound {
        let room = bound.checked_sub(filled)?;
        let offset = u64::try_from(filled).ok()?;
        let window = content.get_mut(filled..bound)?;
        match read_at(window, offset) {
            Ok(0) => {
                eof_observed = true;
                break;
            }
            // A read cannot return more than it was given room for; one that
            // claims to is not a read this broker trusts.
            Ok(n) if n <= room => filled = filled.checked_add(n)?,
            Err(Errno::INTR) => {}
            Ok(_) | Err(_) => return None,
        }
    }
    content.truncate(filled);
    Some((content, eof_observed))
}

/// `fs.stat`: what `fstat` says about the object the `O_PATH` descriptor
/// holds. Nothing is opened, read or followed.
pub(super) fn stat(authorisation: &FsStatAuthorisation, object: &OwnedFd) -> OutcomeResult {
    let want = named(&authorisation.device, &authorisation.inode);
    let st = match checks::path_only(object, want) {
        Ok(st) => st,
        Err(refusal) => return OutcomeResult::Refused(refusal),
    };
    let kind = match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => StatKind::RegularFile,
        FileType::Directory => StatKind::Directory,
        _ => return OutcomeResult::Refused(BrokerRefusal::DescriptorNotRegular),
    };
    let done = (|| {
        Some(FsStatDone {
            kind,
            size: ByteCount::new(u64::try_from(st.st_size).ok()?)?,
            link_count: LinkCount::new(checks::widen(st.st_nlink))?,
            mode: ModeBits::new(u16::try_from(st.st_mode & 0o7777).ok()?)?,
        })
    })();
    match done {
        Some(done) => OutcomeResult::done(BrokerDone::stat(done)),
        None => OutcomeResult::Refused(BrokerRefusal::IoError),
    }
}

/// What a directory entry's `d_type` says it is. Never followed or opened.
fn entry_kind(file_type: FileType) -> EntryKind {
    match file_type {
        FileType::RegularFile => EntryKind::RegularFile,
        FileType::Directory => EntryKind::Directory,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Fifo | FileType::Socket | FileType::CharacterDevice | FileType::BlockDevice => {
            EntryKind::Other
        }
        FileType::Unknown => EntryKind::Unknown,
    }
}

/// `fs.list`: every name in the directory, through the descriptor the
/// authority opened — never reopened by name, so the directory's own search
/// permission is not what the listing depends on — sorted by their bytes, the
/// first `max_entries` returned. Not recursive: an entry is never opened,
/// followed or stat'ed. A directory with more than [`MAX_LIST_SCAN_ENTRIES`]
/// names is refused rather than listed in part by an order the directory
/// chose.
pub(super) fn list(authorisation: &FsListAuthorisation, directory: OwnedFd) -> OutcomeResult {
    let want = named(&authorisation.device, &authorisation.inode);
    if let Err(refusal) = checks::readable(&directory, Kind::Directory, want) {
        return OutcomeResult::Refused(refusal);
    }
    let Ok(entries) = rustix::fs::Dir::new(directory) else {
        return OutcomeResult::Refused(BrokerRefusal::IoError);
    };
    let mut all: Vec<(Vec<u8>, EntryKind)> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return OutcomeResult::Refused(BrokerRefusal::IoError);
        };
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if all.len() >= MAX_LIST_SCAN_ENTRIES {
            return OutcomeResult::Refused(BrokerRefusal::DirectoryTooLarge);
        }
        all.push((name.to_vec(), entry_kind(entry.file_type())));
    }
    all.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let max = usize::from(authorisation.max_entries.get());
    let complete = all.len() <= max;
    all.truncate(max);
    let entries: Option<Vec<RawEntry>> = all
        .into_iter()
        .map(|(name, kind)| {
            Some(RawEntry {
                name: RawName::from_bytes(&name)?,
                kind,
            })
        })
        .collect();
    match entries.and_then(BoundedList::new) {
        Some(entries) => OutcomeResult::done(BrokerDone::list(FsListDone { entries, complete })),
        None => OutcomeResult::Refused(BrokerRefusal::IoError),
    }
}
