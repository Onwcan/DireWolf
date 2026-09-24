//! The broker's private staging directory, and how one left behind is judged
//! (M4c, ADR-0044 §10).
//!
//! # One per invocation, beside the name that changes
//!
//! `.dwkd-<invocation id>`, made `0700` by the broker in the directory whose
//! name changes, held by descriptor, and proved to be the broker's own (owner,
//! mode, kind) before anything is put in it. An invocation has at most one: it
//! changes one name, in one directory, and the directory's name is its id.
//! Nobody but the broker's uid (and root) can create, rename or remove anything
//! inside it.
//!
//! # A record, durable before any effect
//!
//! Before the broker changes a workspace name it writes `record` into the
//! staging directory — the invocation, the operation, the name, the object
//! authorised and (for a write) the identity of the new file it wrote — and
//! makes it durable: the record's content, the directory entry that names it,
//! and the staging directory's own entry in the workspace parent (next
//! section). **No workspace name is changed before all three are.** The record
//! is removed only after the effect, if there was one, is durable and every
//! object the operation took from the workspace is durably gone. So a staging
//! directory with no complete record holds nothing of the workspace's — at
//! most the broker's own new file — and one whose record is complete says, by
//! what else is in the directory, how far the operation got:
//!
//! | operation | in the directory | what it proves | on reclamation |
//! |---|---|---|---|
//! | any | no complete record; only `new` or nothing | nothing of the workspace's: no effect was attempted, or one finished and left nothing to keep | removed |
//! | replace | record, `new` = the new file | the exchange did not happen, or was undone | removed |
//! | replace | record, `new` = another object | the exchange happened: `new` is what it displaced | **retained** (`DISPLACED`) |
//! | replace | record, no `new` | the exchange happened and the displaced file is gone | **retained** (`EVIDENCE`) |
//! | create | record, `new` = the new file | the rename did not happen | removed |
//! | create | record, no `new` | the rename happened | **retained** (`EVIDENCE`) |
//! | delete | record only | the name was not taken, or was put back | removed |
//! | delete | `held` | the object was taken out of the workspace | **retained** (`TAKEN`) |
//! | delete | `taken`, no `held` | the object was removed | **retained** (`EVIDENCE`) |
//! | any | anything else | the broker cannot account for it | **retained** (`UNEXPECTED`) |
//!
//! The clean-up of a finished operation removes entries in the order that
//! keeps every intermediate state truthful by this table — the object first,
//! then the record, then a delete's mark — except when an operation is undone,
//! where the record goes first, because what remains is then only the
//! broker's own. Each removal is durable before the next is made, so a power
//! cut cannot keep a later removal and lose an earlier one.
//!
//! # Every change durable before the next
//!
//! A file's `fsync` makes its content durable, not the directory entry that
//! names it; a directory's `fsync` makes its entries durable. So after every
//! system call that creates, removes, renames or exchanges a name, the broker
//! `fsync`s **every directory whose entries it changed** before it makes its
//! next namespace change and before it answers — and a file it wrote before
//! the directory that names it:
//!
//! | step | changes the entries of | then, before anything else |
//! |---|---|---|
//! | make `.dwkd-<invocation>` | the workspace parent | `fsync` the staging directory (its mode), then the parent |
//! | write `new` | the staging directory | `fsync` `new`, then the staging directory |
//! | write `record` | the staging directory | `fsync` `record`, then the staging directory |
//! | the exchange or rename that is the effect | the parent and the staging directory (a move: both workspace directories) | once the check after it passes: `fsync` both |
//! | an undo | the same two | `fsync` both |
//! | a delete's `taken` mark; its removal of what it took | the staging directory | `fsync` it |
//! | any other removal inside the staging directory (clean-up, reclamation) | the staging directory | `fsync` it |
//! | removing the staging directory | the workspace parent | `fsync` it |
//!
//! One exception, on purpose: the check that follows an effect comes before
//! its `fsync`, and an undo follows the change it undoes directly — a change
//! that reached an object nobody authorised is never made durable first. A
//! directory that cannot be made durable after an effect is `indeterminate`;
//! anywhere else the operation stops where it is and leaves the staging
//! directory to be reclaimed.
//!
//! This is the order of system calls durability depends on, and the unit
//! tests trace it on every operation they run. It is not a power-cut test:
//! whether the device under the filesystem honours `fsync` is outside what the
//! broker can prove.
//!
//! Only the broker's own uncommitted data is ever removed automatically. An
//! object that was in the workspace, and the evidence that an effect happened,
//! are kept for the operator and for M9's reconciliation: the authority records
//! them against the invocation, whose outcome stays `UNKNOWN`.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, FsReclaimAuthorisation, FsReclaimDone, Indeterminate, KernelNumber,
    OutcomeResult, ReclaimState, StagingHolds, StagingOperation,
};
use dwk_proto::wire::id::InvocationId;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::checks::{self, Kind, identity, named};

/// The new content, inside the staging directory.
pub(super) const NEW: &str = "new";
/// An object taken out of the workspace, inside the staging directory.
pub(super) const HELD: &str = "held";
/// The operation's record.
pub(super) const RECORD: &str = "record";
/// A delete's mark that the object it took was proved and is being removed.
pub(super) const TAKEN: &str = "taken";

/// The most entries a staging directory can legitimately hold.
const MAX_ENTRIES: usize = 4;
/// The largest record: every field bounded.
const MAX_RECORD_BYTES: usize = 1024;

/// Why an operation stopped: nothing changed, or something may have.
pub(super) enum Stop {
    Refused(BrokerRefusal),
    Indeterminate(Indeterminate),
}

impl From<BrokerRefusal> for Stop {
    fn from(refusal: BrokerRefusal) -> Self {
        Self::Refused(refusal)
    }
}

/// The class of a namespace call's failure that proves nothing changed.
pub(super) const fn denied_or(errno: Errno, otherwise: BrokerRefusal) -> BrokerRefusal {
    match errno {
        Errno::ACCESS | Errno::PERM | Errno::ROFS => BrokerRefusal::WriteDenied,
        _ => otherwise,
    }
}

/// The name's current object, not followed.
pub(super) fn at(dir: &OwnedFd, name: &str) -> Result<Stat, Errno> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
}

/// Whether `name` in `dir` binds `want` now.
pub(super) fn binds(dir: &OwnedFd, name: &str, want: (u64, u64)) -> bool {
    at(dir, name).is_ok_and(|st| identity(&st) == want)
}

/// Whether `name` in `dir` is vacant now.
pub(super) fn vacant(dir: &OwnedFd, name: &str) -> bool {
    matches!(at(dir, name), Err(Errno::NOENT))
}

/// A held directory's identity, for the unit tests' trace.
#[cfg(test)]
fn traced(dir: &OwnedFd) -> (u64, u64) {
    rustix::fs::fstat(dir).map_or((0, 0), |st| identity(&st))
}

/// One system call changed the entries of `dirs`: a step of the unit tests'
/// trace, and nothing otherwise.
#[cfg_attr(not(test), allow(clippy::missing_const_for_fn))]
pub(super) fn changed(what: &'static str, dirs: &[&OwnedFd]) {
    #[cfg(test)]
    crate::crash::step(crate::crash::Step::Changed(
        what,
        dirs.iter().copied().map(traced).collect(),
    ));
    #[cfg(not(test))]
    let _ = (what, dirs);
}

/// One system call undid the change just made, before it was made durable:
/// a step of the unit tests' trace, and nothing otherwise.
#[cfg_attr(not(test), allow(clippy::missing_const_for_fn))]
pub(super) fn undone(what: &'static str, dirs: &[&OwnedFd]) {
    #[cfg(test)]
    crate::crash::step(crate::crash::Step::Undone(
        what,
        dirs.iter().copied().map(traced).collect(),
    ));
    #[cfg(not(test))]
    let _ = (what, dirs);
}

/// Make a directory's entries durable.
pub(super) fn synced(dir: &OwnedFd) -> Result<(), Errno> {
    rustix::fs::fsync(dir)?;
    #[cfg(test)]
    crate::crash::step(crate::crash::Step::Synced(traced(dir)));
    Ok(())
}

/// Make a changed directory durable.
pub(super) fn sync_dir(dir: &OwnedFd) -> Result<(), Stop> {
    synced(dir).map_err(|_| Stop::Indeterminate(Indeterminate::DurabilityUnconfirmed))
}

/// Make a file the broker wrote durable: its content and its attributes. Not
/// the entry that names it — that is its directory's `fsync`.
pub(super) fn sync_file(file: &OwnedFd, what: &'static str) -> Result<(), Errno> {
    rustix::fs::fsync(file)?;
    #[cfg(test)]
    crate::crash::step(crate::crash::Step::FileSynced(what));
    #[cfg(not(test))]
    let _ = what;
    Ok(())
}

/// How the unit tests' trace names the removal of `entry`.
fn removal(entry: &str) -> &'static str {
    match entry {
        NEW => "unlink new",
        RECORD => "unlink record",
        TAKEN => "unlink taken",
        HELD => "unlink held",
        _ => "unlink",
    }
}

/// Write all of `bytes` to `file`.
pub(super) fn write_all(file: &OwnedFd, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        match rustix::io::write(file, bytes) {
            Ok(0) => return Err(Errno::IO),
            Ok(n) => bytes = bytes.get(n..).ok_or(Errno::IO)?,
            Err(Errno::INTR) => {}
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

/// The directory whose names change must not be writable by every user: the
/// permission model (ADR-0044 §8) keeps any writer outside the trusted set away
/// from it, and a directory that says otherwise is refused, unchanged.
pub(super) fn exclusive(parent: &Stat) -> Result<(), BrokerRefusal> {
    if parent.st_mode & 0o002 == 0 {
        Ok(())
    } else {
        Err(BrokerRefusal::SharedDirectory)
    }
}

/// A staging directory's name.
pub(super) fn name_for(invocation: &InvocationId) -> String {
    format!(".dwkd-{}", invocation.as_str())
}

/// What an operation writes into its staging directory before any effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) invocation: String,
    pub(super) operation: StagingOperation,
    pub(super) leaf: String,
    pub(super) target: Option<(u64, u64)>,
    pub(super) new: Option<(u64, u64)>,
}

/// A record as found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Found {
    /// No record, or one the broker never finished writing — and so never made
    /// durable, and so never acted after.
    Incomplete,
    /// A complete record.
    Complete(Record),
    /// Complete, but not a record this broker writes.
    Malformed,
}

fn spell(identity: Option<(u64, u64)>) -> String {
    identity.map_or_else(|| "-".to_owned(), |(d, i)| format!("{d}:{i}"))
}

/// A spelling that is neither `-` nor `<device>:<inode>`.
struct Unspellable;

fn unspell(text: &str) -> Result<Option<(u64, u64)>, Unspellable> {
    if text == "-" {
        return Ok(None);
    }
    let (device, inode) = text.split_once(':').ok_or(Unspellable)?;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
            .ok_or(Unspellable)
    };
    Ok(Some((number(device)?, number(inode)?)))
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

impl Record {
    /// The record's one spelling. Ends with `end`: a record without it was
    /// never finished.
    pub(super) fn text(&self) -> String {
        format!(
            "direwolf-staging 1\ninvocation {}\noperation {}\nleaf {}\ntarget {}\nnew {}\nend\n",
            self.invocation,
            self.operation.as_str(),
            hex(self.leaf.as_bytes()),
            spell(self.target),
            spell(self.new),
        )
    }

    fn parse(bytes: &[u8]) -> Found {
        if !bytes.ends_with(b"end\n") {
            return Found::Incomplete;
        }
        let Ok(text) = core::str::from_utf8(bytes) else {
            return Found::Malformed;
        };
        let lines: Vec<&str> = text.lines().collect();
        let field = |i: usize, key: &str| {
            lines
                .get(i)
                .and_then(|line| line.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix(' '))
        };
        let parsed = (|| {
            if lines.len() != 7 || lines.first() != Some(&"direwolf-staging 1") {
                return None;
            }
            if lines.get(6) != Some(&"end") {
                return None;
            }
            let operation = StagingOperation::ALL
                .iter()
                .copied()
                .find(|op| Some(op.as_str()) == field(2, "operation"))?;
            let leaf_hex = field(3, "leaf")?;
            let leaf_bytes = (0..leaf_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(leaf_hex.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            Some(Record {
                invocation: field(1, "invocation")?.to_owned(),
                operation,
                leaf: String::from_utf8(leaf_bytes).ok()?,
                target: unspell(field(4, "target")?).ok()?,
                new: unspell(field(5, "new")?).ok()?,
            })
        })();
        parsed.map_or(Found::Malformed, |record| {
            if hex(record.leaf.as_bytes()).len() == record.leaf.len() * 2 && record.text() == text {
                Found::Complete(record)
            } else {
                Found::Malformed
            }
        })
    }
}

/// The broker's private working directory for one invocation, beside the
/// name that changes.
pub(super) struct Staging {
    name: String,
    pub(super) dir: OwnedFd,
    identity: (u64, u64),
}

impl Staging {
    /// Make it, open it without following anything, prove it is the broker's
    /// own — a directory, owned by `own_uid`, mode exactly `0700` — and make
    /// that durable: its mode, and its name in the parent. A power cut from
    /// here on leaves a directory the reclamation recognises as the broker's.
    pub(super) fn make(
        parent: &OwnedFd,
        invocation: &InvocationId,
        own_uid: u32,
    ) -> Result<Self, BrokerRefusal> {
        let name = name_for(invocation);
        rustix::fs::mkdirat(parent, name.as_str(), Mode::RWXU)
            .map_err(|errno| denied_or(errno, BrokerRefusal::IoError))?;
        changed("mkdir staging", &[parent]);
        let dir = rustix::fs::openat(
            parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BrokerRefusal::IoError)?;
        let st = rustix::fs::fstat(&dir).map_err(|_| BrokerRefusal::IoError)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory || st.st_uid != own_uid {
            // Not the directory this broker made: someone swapped the name.
            // Nothing is put in it and nothing is removed.
            return Err(BrokerRefusal::IoError);
        }
        // Exactly 0700, whatever the umask or an inherited setgid bit.
        rustix::fs::fchmod(&dir, Mode::RWXU).map_err(|_| BrokerRefusal::IoError)?;
        let st = rustix::fs::fstat(&dir).map_err(|_| BrokerRefusal::IoError)?;
        if st.st_mode & 0o7777 != 0o700 {
            return Err(BrokerRefusal::IoError);
        }
        let staging = Self {
            name,
            identity: identity(&st),
            dir,
        };
        // Durable before anything is put in it: the mode, then the name.
        if synced(&staging.dir).and_then(|()| synced(parent)).is_err() {
            staging.remove(parent);
            return Err(BrokerRefusal::IoError);
        }
        Ok(staging)
    }

    /// Write the record, and make it durable: its content, then its entry in
    /// the staging directory (whose own entry [`Staging::make`] made durable).
    /// **The last step before any workspace name may change.** On failure
    /// nothing has changed, and whatever of the record was written is removed.
    pub(super) fn record(&self, record: &Record) -> Result<(), BrokerRefusal> {
        let file = rustix::fs::openat(
            &self.dir,
            RECORD,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| BrokerRefusal::IoError)?;
        changed("create record", &[&self.dir]);
        let durable = write_all(&file, record.text().as_bytes())
            .and_then(|()| sync_file(&file, RECORD))
            .and_then(|()| synced(&self.dir));
        if durable.is_err() {
            self.unlink(RECORD);
            return Err(BrokerRefusal::IoError);
        }
        Ok(())
    }

    /// Mark, durably, that a delete proved what it took and is removing it.
    pub(super) fn mark_taken(&self) -> Result<(), Errno> {
        let file = rustix::fs::openat(
            &self.dir,
            TAKEN,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        changed("create taken", &[&self.dir]);
        drop(file);
        synced(&self.dir)
    }

    /// Remove one of the broker's own entries, and make the removal durable
    /// before anything else happens. Returns whether it is gone, durably.
    pub(super) fn unlink(&self, entry: &str) -> bool {
        match rustix::fs::unlinkat(&self.dir, entry, AtFlags::empty()) {
            Ok(()) => {
                changed(removal(entry), &[&self.dir]);
                synced(&self.dir).is_ok()
            }
            Err(Errno::NOENT) => true,
            Err(_) => false,
        }
    }

    /// Remove the directory, by name, if the name still binds it — the kernel
    /// removes it only if it is empty — and make the removal durable in the
    /// parent. Returns whether it may have been left behind.
    pub(super) fn remove(self, parent: &OwnedFd) -> bool {
        let Self {
            name,
            dir,
            identity,
        } = self;
        drop(dir);
        if !binds(parent, &name, identity) {
            return true;
        }
        if rustix::fs::unlinkat(parent, name.as_str(), AtFlags::REMOVEDIR).is_err() {
            return true;
        }
        changed("rmdir staging", &[parent]);
        synced(parent).is_err()
    }

    /// Undo a preparation that changed no workspace name: the record first —
    /// so that what remains is provably the broker's own — then the new file,
    /// then the directory. Returns whether anything was left behind.
    pub(super) fn discard(self, parent: &OwnedFd) -> bool {
        let record_gone = self.unlink(RECORD);
        let new_gone = record_gone && self.unlink(NEW);
        !(record_gone && new_gone) | self.remove(parent)
    }
}

/// One entry of a staging directory, as found.
struct Entry {
    name: String,
    stat: Stat,
}

/// Every entry of the staging directory, or `None` if it holds more than it
/// ever legitimately can, or a name it never writes.
fn entries(dir: &OwnedFd) -> Result<Option<Vec<Entry>>, Errno> {
    let listing = rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut found = Vec::new();
    for entry in rustix::fs::Dir::new(listing)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let Ok(name) = core::str::from_utf8(bytes) else {
            return Ok(None);
        };
        if ![NEW, HELD, RECORD, TAKEN].contains(&name) || found.len() == MAX_ENTRIES {
            return Ok(None);
        }
        found.push(Entry {
            name: name.to_owned(),
            stat: at(dir, name)?,
        });
    }
    Ok(Some(found))
}

/// Read the record, if there is one: at most [`MAX_RECORD_BYTES`], from a
/// regular file the broker owns.
fn read_record(dir: &OwnedFd, record: &Entry, own_uid: u32) -> Found {
    if FileType::from_raw_mode(record.stat.st_mode) != FileType::RegularFile
        || record.stat.st_uid != own_uid
    {
        return Found::Malformed;
    }
    let Ok(file) = rustix::fs::openat(
        dir,
        RECORD,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return Found::Malformed;
    };
    let mut buffer = vec![0u8; MAX_RECORD_BYTES + 1];
    let mut filled = 0usize;
    loop {
        let Some(window) = buffer.get_mut(filled..) else {
            return Found::Malformed;
        };
        match rustix::io::read(&file, window) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(_) => return Found::Malformed,
        }
        if filled > MAX_RECORD_BYTES {
            return Found::Malformed;
        }
    }
    Record::parse(buffer.get(..filled).unwrap_or_default())
}

/// What a staging directory is, by the table in this module's documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Provably only the broker's own uncommitted data.
    Disposable,
    /// Kept: why, and the object it holds, if one.
    Retained(StagingHolds, Option<(u64, u64)>),
}

fn judge(expected: &Record, found: &Found, entries: &[Entry]) -> Verdict {
    let get = |name: &str| entries.iter().find(|e| e.name == name);
    let unexpected = |entry: Option<&Entry>| {
        Verdict::Retained(StagingHolds::Unexpected, entry.map(|e| identity(&e.stat)))
    };
    let record = match found {
        Found::Complete(record) => {
            let matches = record.invocation == expected.invocation
                && record.operation == expected.operation
                && record.leaf == expected.leaf
                && record.target == expected.target
                && (record.operation == StagingOperation::Delete) == record.new.is_none();
            if !matches {
                return unexpected(None);
            }
            Some(record)
        }
        Found::Malformed => return unexpected(None),
        Found::Incomplete => None,
    };
    let (new, held, taken) = (get(NEW), get(HELD), get(TAKEN));
    match expected.operation {
        StagingOperation::Replace | StagingOperation::Create => {
            if held.is_some() || taken.is_some() {
                return unexpected(held.or(taken));
            }
            match (record, new) {
                // No durable record: no exchange or rename was ever issued, so
                // `new`, if there, is the file the broker wrote.
                (None, _) => Verdict::Disposable,
                (Some(record), Some(new)) if record.new == Some(identity(&new.stat)) => {
                    Verdict::Disposable
                }
                (Some(_), Some(new)) if expected.operation == StagingOperation::Replace => {
                    Verdict::Retained(StagingHolds::Displaced, Some(identity(&new.stat)))
                }
                (Some(_), Some(new)) => unexpected(Some(new)),
                (Some(_), None) => Verdict::Retained(StagingHolds::Evidence, None),
            }
        }
        StagingOperation::Delete => {
            if new.is_some() {
                return unexpected(new);
            }
            match (held, taken) {
                (Some(held), _) => {
                    Verdict::Retained(StagingHolds::Taken, Some(identity(&held.stat)))
                }
                (None, Some(_)) => Verdict::Retained(StagingHolds::Evidence, None),
                (None, None) => Verdict::Disposable,
            }
        }
    }
}

fn reclaimed(
    state: ReclaimState,
    holds: Option<StagingHolds>,
    held: Option<(u64, u64)>,
) -> OutcomeResult {
    OutcomeResult::Done(BrokerDone::reclaim(FsReclaimDone {
        state,
        holds,
        held_device: held.map(|h| KernelNumber::from_u64(h.0)),
        held_inode: held.map(|h| KernelNumber::from_u64(h.1)),
    }))
}

/// `fs_reclaim`: judge the staging directory of an invocation whose outcome
/// the authority has recorded, remove it only if it is disposable, and say
/// what was found.
pub(super) fn reclaim(
    authorisation: &FsReclaimAuthorisation,
    parent: &OwnedFd,
    own_uid: u32,
) -> OutcomeResult {
    let want = named(&authorisation.parent_device, &authorisation.parent_inode);
    if let Err(refusal) = checks::readable(parent, Kind::Directory, want) {
        return OutcomeResult::Refused(refusal);
    }
    let name = name_for(&authorisation.invocation_id);
    let dir = match rustix::fs::openat(
        parent,
        name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(dir) => dir,
        Err(Errno::NOENT) => return reclaimed(ReclaimState::Absent, None, None),
        // A symlink or a file by that name: not the broker's.
        Err(Errno::LOOP | Errno::NOTDIR) => return reclaimed(ReclaimState::Foreign, None, None),
        Err(errno) => return OutcomeResult::Refused(denied_or(errno, BrokerRefusal::IoError)),
    };
    let Ok(st) = rustix::fs::fstat(&dir) else {
        return OutcomeResult::Refused(BrokerRefusal::IoError);
    };
    if st.st_uid != own_uid || st.st_mode & 0o7777 != 0o700 {
        // Spelled like a staging directory, but not one this broker made.
        return reclaimed(ReclaimState::Foreign, None, None);
    }
    let staging_identity = identity(&st);
    let found_entries = match entries(&dir) {
        Ok(Some(found)) => found,
        Ok(None) => {
            return reclaimed(ReclaimState::Retained, Some(StagingHolds::Unexpected), None);
        }
        Err(_) => return OutcomeResult::Refused(BrokerRefusal::IoError),
    };
    let found = found_entries
        .iter()
        .find(|e| e.name == RECORD)
        .map_or(Found::Incomplete, |entry| read_record(&dir, entry, own_uid));
    let expected = Record {
        invocation: authorisation.invocation_id.as_str().to_owned(),
        operation: authorisation.operation,
        leaf: authorisation.leaf.as_str().to_owned(),
        target: authorisation.target(),
        new: None,
    };
    match judge(&expected, &found, &found_entries) {
        Verdict::Retained(holds, held) => reclaimed(ReclaimState::Retained, Some(holds), held),
        Verdict::Disposable => {
            let staging = Staging {
                name,
                dir,
                identity: staging_identity,
            };
            // The record first: what remains is then disposable by the same
            // table, whenever this stops. Each removal is durable before the
            // next; the last, the directory's, in the parent.
            let gone = staging.unlink(RECORD) && staging.unlink(NEW) && !staging.remove(parent);
            if !gone {
                return OutcomeResult::Indeterminate(Indeterminate::EffectUnconfirmed);
            }
            reclaimed(ReclaimState::Removed, None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use dwk_proto::brokerp::StagingOperation;

    use super::{Found, Record};

    fn record(operation: StagingOperation) -> Record {
        Record {
            invocation: "inv_01M24BB8G3E0A851TRWE3M8FZF".to_owned(),
            operation,
            leaf: "a b\u{e9}.txt".to_owned(),
            target: Some((2049, 77)),
            new: Some((2049, 78)),
        }
    }

    #[test]
    fn a_record_reads_back_exactly_and_an_unfinished_one_is_incomplete() {
        let written = record(StagingOperation::Replace);
        let text = written.text();
        assert_eq!(Record::parse(text.as_bytes()), Found::Complete(written));
        // Every strict prefix is a record the broker never finished writing.
        for cut in 0..text.len() {
            assert_eq!(
                Record::parse(text.as_bytes().get(..cut).unwrap_or_default()),
                Found::Incomplete,
                "cut at {cut}"
            );
        }
        // A finished record in another spelling is not one this broker wrote.
        let other = text.replace("target 2049:77", "target 02049:77");
        assert_eq!(Record::parse(other.as_bytes()), Found::Malformed);
        assert_eq!(Record::parse(b"anything\nend\n"), Found::Malformed);
    }
}
