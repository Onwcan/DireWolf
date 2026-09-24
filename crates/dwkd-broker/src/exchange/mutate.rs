//! The operations that change names: `fs.write`, `fs.patch`, `fs.move` and
//! `fs.delete` (M4c, ADR-0044 §§5–8).
//!
//! # The name changed is the name the authority checked — as far as Linux lets that be proved
//!
//! Every operation acts on **one validated name in a directory the authority
//! opened and proved** — never a path — and checks, by `(st_dev, st_ino)`, that
//! the name binds the object that was authorised **immediately before** the
//! system call that changes it, and again **after** it:
//!
//! | operation | checked immediately before | the change | checked after, and undone if wrong |
//! |---|---|---|---|
//! | write, existing | the name binds the target: a regular file, singly linked, no special bit, the permission bits and group the new file was given | `renameat2(RENAME_EXCHANGE)` of the new file with the name | the displaced object is the target, still singly linked: else exchanged back |
//! | write, vacant | the name is vacant | `renameat2(RENAME_NOREPLACE)` | — the kernel refuses an occupied name atomically |
//! | patch | as write, existing, **and** the target (through the authority's readable descriptor) holds the base revision | as write, existing | as write, existing, and the displaced file still holds the base: else exchanged back, `CONFLICT` |
//! | move | the source name binds the source; the destination is vacant | one `renameat2(RENAME_NOREPLACE)` | the object at the destination is the source: else renamed back (`NOREPLACE`) |
//! | delete | the name binds the target (an empty directory: empty) | `renameat2(RENAME_NOREPLACE)` into the staging directory | what was taken is the target: else put back (`NOREPLACE`); only then removed |
//!
//! # What Linux can and cannot guarantee here
//!
//! `RENAME_NOREPLACE` is an atomic compare on the **destination**: the kernel
//! renames only if the destination name is absent, in one step. Nothing in
//! Linux compares the **source** or an exchanged name with an expected inode
//! in the same step: there is no inode compare-and-swap on a directory entry.
//! So between the check immediately before the change and the change itself
//! there is a window — microseconds, no system call of the broker's in it —
//! in which another process with write permission on the directory could
//! substitute the object. If one does:
//!
//! * the change reaches the substitute: exchanged into the staging directory,
//!   renamed to the destination, or taken for deletion;
//! * the check after the change sees it and undoes the change — exchanged back,
//!   renamed back, put back — and proves the undo, and the answer is
//!   `refused`: **no persistent change**. For that moment, though, the
//!   namespace **was** changed, and a process looking then could see it;
//! * if the undo cannot be proved, the answer is `indeterminate` and the
//!   authority records the invocation `UNKNOWN` — never an ordinary failure.
//!
//! Nothing is ever *removed* that was not proved, after it was taken, to be the
//! target: a delete removes only what it holds in its own staging directory.
//!
//! That window is why ADR-0044 §8 excludes an **untrusted** concurrent writer
//! by the permission model instead of claiming a kernel guarantee: in a
//! write-enabled workspace only the operator and the broker may change names,
//! and the runtime's uid may not. The checks after the change are robustness
//! against a trusted concurrent change, not proof that no transient effect can
//! occur. A directory writable by every user is refused outright
//! (`SHARED_DIRECTORY`).
//!
//! # Atomic, and durable before `done`
//!
//! A replacement is never written in place: the file under the name is at
//! every instant either the whole old content or the whole new content. The
//! new file is `fsync`ed — and its entry in the staging directory — before it
//! is exchanged in. An exchange or rename changes the entries of **two**
//! directories (the workspace parent and the staging directory, or a move's
//! two parents), and both are `fsync`ed before the operation goes on and
//! before the outcome says `done`; so is every directory an undo changes
//! before it says `refused` (the order in full: [`super::staging`]). A
//! directory that cannot be made durable after its name changed is
//! `indeterminate`, never `done` and never `refused`. There is no
//! copy-and-delete: a move across filesystems is `UNSUPPORTED`, and so is a
//! filesystem without `RENAME_EXCHANGE`.
//!
//! # The staging directory
//!
//! See [`super::staging`]: one per invocation, beside the name that changes,
//! with a record made durable before any workspace name changes, so that one
//! left behind by a crash is judged — removed or retained — by what it holds.
//!
//! # What the broker's own identity needs
//!
//! Directory write and search permission on the directory whose names change
//! (ADR-0044 §3): a held directory descriptor confers no right to change its
//! names. Where the broker's uid lacks it, the first namespace call fails with
//! `EACCES`/`EPERM` and the operation is `WRITE_DENIED`, having changed
//! nothing.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, CREATED_FILE_MODE, ContentRevision, FsDeleteAuthorisation,
    FsDeleteDone, FsMoveAuthorisation, FsPatchAuthorisation, FsPatchDone, FsWriteAuthorisation,
    FsWriteDone, Indeterminate, OutcomeResult, PatchEdits, StagingOperation,
};
use dwk_proto::limits::MAX_PATCH_FILE_BYTES;
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::{PatchOutcome, StatKind};
use rustix::fs::{AtFlags, FileType, Gid, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest as _, Sha256};

use super::checks::{self, Kind, identity, named};
use super::staging::{
    self, HELD, NEW, RECORD, Record, Staging, Stop, TAKEN, at, binds, denied_or, sync_dir, vacant,
    write_all,
};
use crate::crash;

fn outcome(result: Result<BrokerDone, Stop>) -> OutcomeResult {
    match result {
        Ok(done) => OutcomeResult::Done(done),
        Err(Stop::Refused(why)) => OutcomeResult::Refused(why),
        Err(Stop::Indeterminate(why)) => OutcomeResult::Indeterminate(why),
    }
}

/// Rename or exchange `old` in `from` with `new` in `to`: a change to the
/// entries of both directories, which the caller makes durable (ADR-0044
/// §10).
fn rename(
    from: &OwnedFd,
    old: &str,
    to: &OwnedFd,
    new: &str,
    (flags, what): (RenameFlags, &'static str),
) -> Result<(), Errno> {
    rustix::fs::renameat_with(from, old, to, new, flags)?;
    staging::changed(what, &[from, to]);
    Ok(())
}

/// Undo the change just made — before it was made durable, which a change
/// that reached an object nobody authorised never is.
fn undo(
    from: &OwnedFd,
    old: &str,
    to: &OwnedFd,
    new: &str,
    (flags, what): (RenameFlags, &'static str),
) -> Result<(), Errno> {
    rustix::fs::renameat_with(from, old, to, new, flags)?;
    staging::undone(what, &[from, to]);
    Ok(())
}

/// The permission bits and group a new file must have.
struct Attributes {
    mode: u32,
    group: Option<u32>,
}

/// Write `content` to a new file in the staging directory, give it
/// `attributes`, and make it durable — its content and attributes, then its
/// entry in the staging directory. Returns its identity.
fn write_new(
    staging: &Staging,
    content: &[u8],
    attributes: &Attributes,
) -> Result<(u64, u64), BrokerRefusal> {
    let file = rustix::fs::openat(
        &staging.dir,
        NEW,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| BrokerRefusal::IoError)?;
    staging::changed("create new", &[&staging.dir]);
    let prepared = (|| {
        write_all(&file, content).map_err(|_| BrokerRefusal::IoError)?;
        rustix::fs::fchmod(&file, Mode::from_raw_mode(attributes.mode))
            .map_err(|_| BrokerRefusal::IoError)?;
        let st = rustix::fs::fstat(&file).map_err(|_| BrokerRefusal::IoError)?;
        if let Some(group) = attributes.group
            && st.st_gid != group
        {
            rustix::fs::fchown(&file, None, Some(Gid::from_raw(group)))
                .map_err(|_| BrokerRefusal::AttributesNotPreserved)?;
        }
        staging::sync_file(&file, NEW).map_err(|_| BrokerRefusal::IoError)?;
        let st = rustix::fs::fstat(&file).map_err(|_| BrokerRefusal::IoError)?;
        if st.st_mode & 0o7777 != attributes.mode
            || attributes.group.is_some_and(|group| st.st_gid != group)
        {
            return Err(BrokerRefusal::AttributesNotPreserved);
        }
        staging::synced(&staging.dir).map_err(|_| BrokerRefusal::IoError)?;
        Ok(identity(&st))
    })();
    if prepared.is_err() {
        staging.unlink(NEW);
    }
    prepared
}

/// The regular file `leaf` names in `parent` must be `target`, singly linked
/// and without a setuid, setgid or sticky bit. Returns its stat.
fn replaceable(parent: &OwnedFd, leaf: &str, target: (u64, u64)) -> Result<Stat, BrokerRefusal> {
    let st = match at(parent, leaf) {
        Ok(st) => st,
        Err(errno) => return Err(denied_or(errno, BrokerRefusal::ObjectChanged)),
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || identity(&st) != target
        || checks::widen(st.st_nlink) != 1
    {
        return Err(BrokerRefusal::ObjectChanged);
    }
    if st.st_mode & 0o7000 != 0 {
        return Err(BrokerRefusal::Unsupported);
    }
    Ok(st)
}

/// What a replacement is checked against, immediately before and after the
/// exchange.
struct Expected<'a> {
    /// The authorised file.
    target: (u64, u64),
    /// Whether it still holds the content it was decided on. Always true for a
    /// write; for a patch, the base revision, through the authority's
    /// descriptor.
    unchanged: &'a dyn Fn() -> bool,
}

/// The check made immediately before the exchange: the name still binds the
/// target, with the permission bits and group the new file was given, and the
/// target's content is still what the change was decided on. There is no
/// system call of the broker's between this and the exchange.
fn still_replaceable(
    parent: &OwnedFd,
    leaf: &str,
    expected: &Expected<'_>,
    attributes: &Attributes,
) -> Result<(), BrokerRefusal> {
    let st = replaceable(parent, leaf, expected.target)?;
    if st.st_mode & 0o777 != attributes.mode || attributes.group != Some(st.st_gid) {
        return Err(BrokerRefusal::ObjectChanged);
    }
    if !(expected.unchanged)() {
        return Err(BrokerRefusal::Conflict);
    }
    Ok(())
}

/// Replace the regular file `expected.target`, named `leaf` in `parent`, with
/// a new file holding `content` and the target's permission bits and group —
/// atomically, by exchange. Returns whether the staging directory was left
/// behind.
fn replace(
    parent: &OwnedFd,
    leaf: &str,
    expected: &Expected<'_>,
    content: &[u8],
    invocation: &InvocationId,
    own_uid: u32,
) -> Result<bool, Stop> {
    let st = replaceable(parent, leaf, expected.target)?;
    let staging = Staging::make(parent, invocation, own_uid)?;
    let attributes = Attributes {
        mode: st.st_mode & 0o777,
        group: Some(st.st_gid),
    };
    let new = match write_new(&staging, content, &attributes) {
        Ok(new) => new,
        Err(refusal) => {
            staging.discard(parent);
            return Err(refusal.into());
        }
    };
    crash::point("replace.before_record");
    let record = Record {
        invocation: invocation.as_str().to_owned(),
        operation: StagingOperation::Replace,
        leaf: leaf.to_owned(),
        target: Some(expected.target),
        new: Some(new),
    };
    if let Err(refusal) = staging.record(&record) {
        staging.discard(parent);
        return Err(refusal.into());
    }
    crash::point("replace.before_check");
    if let Err(refusal) = still_replaceable(parent, leaf, expected, &attributes) {
        staging.discard(parent);
        return Err(refusal.into());
    }
    crash::point("replace.before_exchange");
    if let Err(errno) = rename(
        &staging.dir,
        NEW,
        parent,
        leaf,
        (RenameFlags::EXCHANGE, "exchange"),
    ) {
        let refusal = match errno {
            Errno::NOENT => BrokerRefusal::ObjectChanged,
            Errno::INVAL | Errno::NOSYS | Errno::XDEV => BrokerRefusal::Unsupported,
            other => denied_or(other, BrokerRefusal::IoError),
        };
        // `rename(2)` is all or nothing; the new file still in the staging
        // directory is the proof that nothing moved.
        if !binds(&staging.dir, NEW, new) {
            return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed));
        }
        staging.discard(parent);
        return Err(refusal.into());
    }
    crash::point("replace.after_exchange");
    let displaced = at(&staging.dir, NEW);
    let proved = displaced.as_ref().is_ok_and(|d| {
        identity(d) == expected.target
            && FileType::from_raw_mode(d.st_mode) == FileType::RegularFile
            && checks::widen(d.st_nlink) == 1
    });
    let intact = proved && (expected.unchanged)();
    if !intact {
        // Not the target, linked again, or changed since it was checked: the
        // exchange reached something else. Put back exactly what was there,
        // and prove it; a restore that cannot be proved is indeterminate.
        let Ok(displaced) = displaced else {
            return Err(Stop::Indeterminate(Indeterminate::RestoreFailed));
        };
        crash::point("replace.before_restore");
        let back = undo(
            &staging.dir,
            NEW,
            parent,
            leaf,
            (RenameFlags::EXCHANGE, "exchange back"),
        )
        .is_ok()
            && binds(parent, leaf, identity(&displaced))
            && binds(&staging.dir, NEW, new);
        if !back {
            return Err(Stop::Indeterminate(Indeterminate::RestoreFailed));
        }
        // The undo is durable in both directories before the record goes.
        sync_dir(parent)?;
        sync_dir(&staging.dir)?;
        staging.discard(parent);
        return Err(Stop::Refused(if proved {
            BrokerRefusal::Conflict
        } else {
            BrokerRefusal::ObjectChanged
        }));
    }
    // The exchange changed both directories; both are made durable before
    // anything else — and before `done`.
    sync_dir(parent)?;
    sync_dir(&staging.dir)?;
    crash::point("replace.after_sync");
    // The displaced file is the target, proved: the one object removed. Then
    // the record, which until now is the evidence of the exchange.
    let file_gone = staging.unlink(NEW);
    let record_gone = file_gone && staging.unlink(RECORD);
    let directory_left = staging.remove(parent);
    Ok(!record_gone || directory_left)
}

/// Create `leaf` in `parent` holding `content`, mode exactly
/// [`CREATED_FILE_MODE`] — never replacing anything. Returns whether the
/// staging directory was left behind.
fn create(
    parent: &OwnedFd,
    parent_st: &Stat,
    leaf: &str,
    content: &[u8],
    invocation: &InvocationId,
    own_uid: u32,
) -> Result<bool, Stop> {
    match at(parent, leaf) {
        Err(Errno::NOENT) => {}
        Ok(_) => return Err(BrokerRefusal::TargetOccupied.into()),
        Err(errno) => return Err(denied_or(errno, BrokerRefusal::IoError).into()),
    }
    let staging = Staging::make(parent, invocation, own_uid)?;
    // In a setgid directory a file created there takes the directory's group;
    // one created in the staging directory and renamed in must be given it.
    let attributes = Attributes {
        mode: CREATED_FILE_MODE,
        group: (parent_st.st_mode & 0o2000 != 0).then_some(parent_st.st_gid),
    };
    let new = match write_new(&staging, content, &attributes) {
        Ok(new) => new,
        Err(refusal) => {
            staging.discard(parent);
            return Err(refusal.into());
        }
    };
    let record = Record {
        invocation: invocation.as_str().to_owned(),
        operation: StagingOperation::Create,
        leaf: leaf.to_owned(),
        target: None,
        new: Some(new),
    };
    if let Err(refusal) = staging.record(&record) {
        staging.discard(parent);
        return Err(refusal.into());
    }
    crash::point("create.before_check");
    if !vacant(parent, leaf) {
        staging.discard(parent);
        return Err(BrokerRefusal::TargetOccupied.into());
    }
    crash::point("create.before_rename");
    // The one atomic compare Linux offers: the name is created only if it is
    // absent, in the same step.
    if let Err(errno) = rename(
        &staging.dir,
        NEW,
        parent,
        leaf,
        (RenameFlags::NOREPLACE, "rename"),
    ) {
        let refusal = match errno {
            Errno::EXIST => BrokerRefusal::TargetOccupied,
            Errno::INVAL | Errno::NOSYS | Errno::XDEV => BrokerRefusal::Unsupported,
            other => denied_or(other, BrokerRefusal::IoError),
        };
        if !binds(&staging.dir, NEW, new) {
            return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed));
        }
        staging.discard(parent);
        return Err(refusal.into());
    }
    crash::point("create.after_rename");
    sync_dir(parent)?;
    sync_dir(&staging.dir)?;
    let record_gone = staging.unlink(RECORD);
    let directory_left = staging.remove(parent);
    Ok(!record_gone || directory_left)
}

/// `fs.write`: replace or create one regular file's whole content.
pub(super) fn write(
    authorisation: &FsWriteAuthorisation,
    parent: &OwnedFd,
    own_uid: u32,
) -> OutcomeResult {
    let want = named(&authorisation.parent_device, &authorisation.parent_inode);
    let parent_st = match checks::readable(parent, Kind::Directory, want)
        .and_then(|st| staging::exclusive(&st).map(|()| st))
    {
        Ok(st) => st,
        Err(refusal) => return OutcomeResult::Refused(refusal),
    };
    let leaf = authorisation.leaf.as_str();
    let content = authorisation.content.to_bytes();
    let invocation = &authorisation.invocation_id;
    outcome(match authorisation.target() {
        Some(target) => {
            let expected = Expected {
                target,
                unchanged: &|| true,
            };
            replace(parent, leaf, &expected, &content, invocation, own_uid).map(|debris| {
                BrokerDone::write(FsWriteDone {
                    created: false,
                    debris,
                })
            })
        }
        None => create(parent, &parent_st, leaf, &content, invocation, own_uid).map(|debris| {
            BrokerDone::write(FsWriteDone {
                created: true,
                debris,
            })
        }),
    })
}

/// Read all of a file, up to `limit` bytes, through its descriptor. `None`
/// when it is longer, or a read fails.
fn read_whole(file: &OwnedFd, limit: usize) -> Option<Vec<u8>> {
    let bound = u32::try_from(limit.checked_add(1)?).ok()?;
    let (bytes, eof) = super::observe::read_within(bound, |window, offset| {
        rustix::io::pread(file, window, offset)
    })?;
    (eof && bytes.len() <= limit).then_some(bytes)
}

/// Whether `bytes` are exactly `revision`.
fn is(bytes: &[u8], revision: &ContentRevision) -> bool {
    use core::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    u64::try_from(bytes.len()).ok() == Some(u64::from(revision.length.get()))
        && hex == revision.sha256.as_str()
}

/// Apply `edits` to `base`: each, in ascending order of offset, removes
/// `delete` bytes at `offset` and puts `insert` there. `None` if they are out
/// of order, overlap, or reach past the base — the authority refused such a
/// patch already; this is the broker not trusting that.
pub(super) fn apply(base: &[u8], edits: &PatchEdits) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(base.len());
    let mut cursor = 0usize;
    for edit in edits {
        let offset = usize::try_from(edit.offset.get()).ok()?;
        let delete = usize::try_from(edit.delete.get()).ok()?;
        if offset < cursor {
            return None;
        }
        out.extend_from_slice(base.get(cursor..offset)?);
        out.extend_from_slice(&edit.insert.to_bytes());
        cursor = offset.checked_add(delete)?;
        if cursor > base.len() {
            return None;
        }
    }
    out.extend_from_slice(base.get(cursor..)?);
    Some(out)
}

/// `fs.patch`: if the file holds the base revision, replace it — atomically,
/// as `fs.write` replaces — with the base edited, which must be the post
/// revision; if it holds the post revision already, change nothing and say
/// so; otherwise refuse, `CONFLICT`.
pub(super) fn patch(
    authorisation: &FsPatchAuthorisation,
    parent: &OwnedFd,
    file: &OwnedFd,
    own_uid: u32,
) -> OutcomeResult {
    let parent_want = named(&authorisation.parent_device, &authorisation.parent_inode);
    let target = named(&authorisation.target_device, &authorisation.target_inode);
    if let Err(refusal) = checks::readable(parent, Kind::Directory, parent_want)
        .and_then(|st| staging::exclusive(&st))
        .and_then(|()| checks::readable(file, Kind::File, target))
    {
        return OutcomeResult::Refused(refusal);
    }
    let Some(current) = read_whole(file, MAX_PATCH_FILE_BYTES) else {
        return OutcomeResult::Refused(BrokerRefusal::Conflict);
    };
    if is(&current, &authorisation.post) {
        return OutcomeResult::Done(BrokerDone::patch(FsPatchDone {
            outcome: PatchOutcome::AlreadyApplied,
            debris: false,
        }));
    }
    if !is(&current, &authorisation.base) {
        return OutcomeResult::Refused(BrokerRefusal::Conflict);
    }
    let Some(result) = apply(&current, &authorisation.edits) else {
        return OutcomeResult::Refused(BrokerRefusal::Conflict);
    };
    if !is(&result, &authorisation.post) {
        return OutcomeResult::Refused(BrokerRefusal::Conflict);
    }
    // The base is proved again immediately before the exchange, and once more
    // after it: a write to the file between the reading above and the
    // exchange is not lost silently.
    let base = &authorisation.base;
    let unchanged = || read_whole(file, MAX_PATCH_FILE_BYTES).is_some_and(|now| is(&now, base));
    let expected = Expected {
        target,
        unchanged: &unchanged,
    };
    outcome(
        replace(
            parent,
            authorisation.leaf.as_str(),
            &expected,
            &result,
            &authorisation.invocation_id,
            own_uid,
        )
        .map(|debris| {
            BrokerDone::patch(FsPatchDone {
                outcome: PatchOutcome::Applied,
                debris,
            })
        }),
    )
}

/// `fs.move`: rename the regular file `source` to the vacant destination
/// name with one `renameat2(RENAME_NOREPLACE)`, and prove the object now at
/// the destination is the source.
pub(super) fn move_file(
    authorisation: &FsMoveAuthorisation,
    from: &OwnedFd,
    to: &OwnedFd,
) -> OutcomeResult {
    let from_want = named(
        &authorisation.source_parent_device,
        &authorisation.source_parent_inode,
    );
    let to_want = named(
        &authorisation.destination_parent_device,
        &authorisation.destination_parent_inode,
    );
    let source = named(&authorisation.source_device, &authorisation.source_inode);
    if let Err(refusal) = checks::readable(from, Kind::Directory, from_want)
        .and_then(|st| staging::exclusive(&st))
        .and_then(|()| checks::readable(to, Kind::Directory, to_want))
        .and_then(|st| staging::exclusive(&st))
    {
        return OutcomeResult::Refused(refusal);
    }
    let old = authorisation.source_leaf.as_str();
    let new = authorisation.destination_leaf.as_str();
    outcome((|| {
        crash::point("move.before_check");
        // Immediately before the rename: the source name binds the source, a
        // regular file, and the destination is vacant.
        match at(from, old) {
            Ok(st)
                if identity(&st) == source
                    && FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {}
            Ok(_) => return Err(BrokerRefusal::ObjectChanged.into()),
            Err(errno) => return Err(denied_or(errno, BrokerRefusal::ObjectChanged).into()),
        }
        match at(to, new) {
            Err(Errno::NOENT) => {}
            Ok(_) => return Err(BrokerRefusal::TargetOccupied.into()),
            Err(errno) => return Err(denied_or(errno, BrokerRefusal::IoError).into()),
        }
        crash::point("move.before_rename");
        if let Err(errno) = rename(from, old, to, new, (RenameFlags::NOREPLACE, "rename")) {
            let refusal = match errno {
                Errno::EXIST => BrokerRefusal::TargetOccupied,
                Errno::NOENT => BrokerRefusal::ObjectChanged,
                Errno::XDEV | Errno::INVAL | Errno::NOSYS => BrokerRefusal::Unsupported,
                other => denied_or(other, BrokerRefusal::IoError),
            };
            // `rename(2)` is all or nothing; the source not at the
            // destination is the proof that nothing moved.
            if binds(to, new, source) {
                return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed));
            }
            return Err(refusal.into());
        }
        crash::point("move.after_rename");
        match at(to, new) {
            Ok(st) if identity(&st) == source => {}
            Ok(moved) => {
                // Another object was under the source name when it was
                // renamed: put it back where it was, and prove it.
                crash::point("move.before_restore");
                let back = undo(to, new, from, old, (RenameFlags::NOREPLACE, "rename back"))
                    .is_ok()
                    && binds(from, old, identity(&moved))
                    && vacant(to, new);
                return if back {
                    sync_dir(from)?;
                    sync_dir(to)?;
                    Err(BrokerRefusal::ObjectChanged.into())
                } else {
                    Err(Stop::Indeterminate(Indeterminate::RestoreFailed))
                };
            }
            Err(_) => return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed)),
        }
        sync_dir(to)?;
        if from_want != to_want {
            sync_dir(from)?;
        }
        crash::point("move.after_sync");
        Ok(BrokerDone::moved())
    })())
}

/// Put an object taken into the staging directory back under its name —
/// never over anything — prove it, and answer `refusal`: no persistent change.
/// A put-back that cannot be proved is indeterminate.
fn put_back(
    staging: Staging,
    parent: &OwnedFd,
    leaf: &str,
    taken: (u64, u64),
    refusal: BrokerRefusal,
) -> Result<BrokerDone, Stop> {
    // The mark goes first: while the object is in the staging directory it is
    // `TAKEN`, never `EVIDENCE` of a removal that did not happen.
    if !staging.unlink(TAKEN) {
        return Err(Stop::Indeterminate(Indeterminate::RestoreFailed));
    }
    crash::point("delete.before_restore");
    let back = undo(
        &staging.dir,
        HELD,
        parent,
        leaf,
        (RenameFlags::NOREPLACE, "put back"),
    )
    .is_ok()
        && binds(parent, leaf, taken)
        && vacant(&staging.dir, HELD);
    if !back {
        return Err(Stop::Indeterminate(Indeterminate::RestoreFailed));
    }
    // Durable in both directories before the record goes.
    sync_dir(parent)?;
    sync_dir(&staging.dir)?;
    staging.discard(parent);
    Err(refusal.into())
}

/// Whether the directory `name` in `parent` has no entries.
fn empty_directory(parent: &OwnedFd, name: &str) -> Result<bool, BrokerRefusal> {
    let dir = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| denied_or(errno, BrokerRefusal::ObjectChanged))?;
    let entries = rustix::fs::Dir::new(dir).map_err(|_| BrokerRefusal::IoError)?;
    for entry in entries {
        let entry = entry.map_err(|_| BrokerRefusal::IoError)?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `fs.delete`: take the name out of the workspace into the private staging
/// directory, prove what was taken is the target, and only then remove it.
pub(super) fn delete(
    authorisation: &FsDeleteAuthorisation,
    parent: &OwnedFd,
    own_uid: u32,
) -> OutcomeResult {
    let want = named(&authorisation.parent_device, &authorisation.parent_inode);
    if let Err(refusal) =
        checks::readable(parent, Kind::Directory, want).and_then(|st| staging::exclusive(&st))
    {
        return OutcomeResult::Refused(refusal);
    }
    let leaf = authorisation.leaf.as_str();
    let target = named(&authorisation.target_device, &authorisation.target_inode);
    let directory = authorisation.target_kind == StatKind::Directory;
    let kind_ok = |st: &Stat| {
        let found = FileType::from_raw_mode(st.st_mode);
        if directory {
            found == FileType::Directory
        } else {
            found == FileType::RegularFile
        }
    };
    // The name binds the target, of its kind — and a directory is empty.
    let deletable = || -> Result<(), BrokerRefusal> {
        match at(parent, leaf) {
            Ok(st) if identity(&st) == target && kind_ok(&st) => {}
            Ok(_) => return Err(BrokerRefusal::ObjectChanged),
            Err(errno) => return Err(denied_or(errno, BrokerRefusal::ObjectChanged)),
        }
        if directory && !empty_directory(parent, leaf)? {
            return Err(BrokerRefusal::DirectoryNotEmpty);
        }
        Ok(())
    };
    outcome((|| {
        deletable()?;
        let staging = Staging::make(parent, &authorisation.invocation_id, own_uid)?;
        let record = Record {
            invocation: authorisation.invocation_id.as_str().to_owned(),
            operation: StagingOperation::Delete,
            leaf: leaf.to_owned(),
            target: Some(target),
            new: None,
        };
        if let Err(refusal) = staging.record(&record) {
            staging.discard(parent);
            return Err(refusal.into());
        }
        crash::point("delete.before_check");
        if let Err(refusal) = deletable() {
            staging.discard(parent);
            return Err(refusal.into());
        }
        crash::point("delete.before_stage");
        if let Err(errno) = rename(
            parent,
            leaf,
            &staging.dir,
            HELD,
            (RenameFlags::NOREPLACE, "stage"),
        ) {
            let refusal = match errno {
                Errno::NOENT => BrokerRefusal::ObjectChanged,
                Errno::INVAL | Errno::NOSYS | Errno::XDEV => BrokerRefusal::Unsupported,
                other => denied_or(other, BrokerRefusal::IoError),
            };
            if !vacant(&staging.dir, HELD) {
                return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed));
            }
            staging.discard(parent);
            return Err(refusal.into());
        }
        crash::point("delete.after_stage");
        let taken = match at(&staging.dir, HELD) {
            Ok(st) if identity(&st) == target && kind_ok(&st) => identity(&st),
            Ok(st) => {
                return put_back(
                    staging,
                    parent,
                    leaf,
                    identity(&st),
                    BrokerRefusal::ObjectChanged,
                );
            }
            Err(_) => return Err(Stop::Indeterminate(Indeterminate::EffectUnconfirmed)),
        };
        remove_taken(staging, parent, leaf, taken, directory)
    })())
}

/// The rest of `fs.delete`, once what it took is proved to be the target:
/// the name out of the workspace durably, in both directories; the mark,
/// durably, so that a crash from here on leaves the evidence of what
/// happened; the object removed; then the evidence.
fn remove_taken(
    staging: Staging,
    parent: &OwnedFd,
    leaf: &str,
    taken: (u64, u64),
    directory: bool,
) -> Result<BrokerDone, Stop> {
    sync_dir(parent)?;
    sync_dir(&staging.dir)?;
    if staging.mark_taken().is_err() {
        return put_back(staging, parent, leaf, taken, BrokerRefusal::IoError);
    }
    let flags = if directory {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    if let Err(errno) = rustix::fs::unlinkat(&staging.dir, HELD, flags) {
        let refusal = match errno {
            Errno::NOTEMPTY | Errno::EXIST => BrokerRefusal::DirectoryNotEmpty,
            other => denied_or(other, BrokerRefusal::IoError),
        };
        return put_back(staging, parent, leaf, taken, refusal);
    }
    staging::changed("unlink held", &[&staging.dir]);
    sync_dir(&staging.dir)?;
    crash::point("delete.after_unlink");
    // The evidence goes last: the record, then the mark, then the directory
    // — each removal durable before the next.
    let record_gone = staging.unlink(RECORD);
    let mark_gone = record_gone && staging.unlink(TAKEN);
    let directory_left = staging.remove(parent);
    Ok(BrokerDone::delete(FsDeleteDone {
        debris: !mark_gone || directory_left,
    }))
}

#[cfg(test)]
mod tests {
    use dwk_proto::brokerp::{PatchEdit, PatchEdits};
    use dwk_proto::wire::scalar::{HexContent, PatchLength};

    use super::apply;

    fn edits(list: &[(u32, u32, &[u8])]) -> PatchEdits {
        let built: Vec<PatchEdit> = list
            .iter()
            .filter_map(|(offset, delete, insert)| {
                Some(PatchEdit {
                    offset: PatchLength::new(*offset)?,
                    delete: PatchLength::new(*delete)?,
                    insert: HexContent::from_bytes(insert)?,
                })
            })
            .collect();
        let Some(edits) = PatchEdits::new(built) else {
            unreachable!("within the bound")
        };
        edits
    }

    #[test]
    fn edits_apply_against_the_base_in_order_and_nothing_else_is_accepted() {
        let base = b"hello, world";
        assert_eq!(
            apply(
                base,
                &edits(&[(0, 5, b"HELLO"), (7, 5, b"there"), (12, 0, b"!")])
            ),
            Some(b"HELLO, there!".to_vec())
        );
        assert_eq!(
            apply(base, &edits(&[(5, 2, b"")])),
            Some(b"helloworld".to_vec())
        );
        assert_eq!(
            apply(base, &edits(&[(7, 1, b""), (3, 1, b"")])),
            None,
            "out of order"
        );
        assert_eq!(
            apply(base, &edits(&[(1, 4, b""), (3, 1, b"")])),
            None,
            "overlapping"
        );
        assert_eq!(apply(base, &edits(&[(10, 5, b"")])), None, "past the end");
    }
}
