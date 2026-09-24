//! The authority's end of the private broker channel, on Linux (M4b,
//! ADR-0043; M4c, ADR-0044).
//!
//! One of the three authority modules that may name `rustix` (TX008), and the
//! only one that may send a descriptor or take one out of a handoff (TX014).
//! The exchange, and where each property comes from:
//!
//! | step | property |
//! |---|---|
//! | `connect` to the configured path | none: the path is not trusted |
//! | `SO_PEERCRED` == broker uid, else close | **only the broker is sent anything** |
//! | read `BrokerHello`, bounded | the channel this authorisation will name |
//! | `sendmsg` authorisation + the operation's fds (`SCM_RIGHTS`) | the checked objects, as descriptors |
//! | read `BrokerOutcome`, bounded, same channel and invocation | the answer is to *this* authorisation |
//! | the answer is this operation's, within its bounds | nothing more than was decided comes back |
//!
//! Everything before the `sendmsg` is **before sending**: a failure there is
//! provably without effect. Everything after it is **after sending**: unless
//! the broker says it refused, the effect may have happened, and the state
//! layer records it so (ADR-0044 §10).
//!
//! Every read and write is under one deadline for the whole exchange, so a
//! stalling peer costs at most [`super::EXCHANGE_DEADLINE`].

use std::io::{ErrorKind, IoSlice, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::{
    Authorisation, BrokerDone, BrokerHello, BrokerOutcome, Common, FsDeleteAuthorisation,
    FsListAuthorisation, FsMoveAuthorisation, FsPatchAuthorisation, FsReadAuthorisation,
    FsReclaimAuthorisation, FsReclaimDone, FsSearchAuthorisation, FsStatAuthorisation,
    FsWriteAuthorisation, LeafName, MAX_HELLO_BODY, MAX_OUTCOME_BODY, MoveSide, OutcomeResult,
    ReclaimState, StagingHolds,
};
use dwk_proto::frame::FrameDecoder;
use dwk_proto::wire::scalar::{HexContent, StatKind};
use rustix::fd::AsFd;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

use super::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, FsReadDelivery, ListDelivery,
    Operation, RawListEntry, SearchDelivery, StatDelivery, Unreachable,
};
use crate::resource::{FileIdentity, ParentHandoff, ResourceKind};

/// What was sent, kept to check the answer against.
enum Sent {
    Read {
        max_bytes: u32,
    },
    Stat,
    List {
        max_entries: u16,
    },
    Search {
        needle: usize,
        max_scan: u64,
        max_matches: u16,
    },
    Write {
        creating: bool,
    },
    Patch,
    Move,
    Delete,
    Reclaim,
}

/// Perform one operation through the broker at `socket`, which must be served
/// by `broker_uid`.
pub(super) fn perform(
    socket: &Path,
    broker_uid: u32,
    deadline: Duration,
    order: BrokerOrder,
) -> Result<BrokerDelivery, BrokerError> {
    let before = BrokerError::before_sending;
    let until = Instant::now() + deadline;
    let stream = UnixStream::connect(socket)
        .map_err(|_| before(BrokerFailure::Unreachable(Unreachable::Connect)))?;
    // Who is listening, as the kernel recorded it when the broker called
    // listen(2). Nothing has been sent yet, and nothing is sent to anyone else.
    let cred = rustix::net::sockopt::socket_peercred(&stream)
        .map_err(|_| before(BrokerFailure::Unreachable(Unreachable::PeerCredentials)))?;
    let observed_uid = cred.uid.as_raw();
    if observed_uid != broker_uid {
        return Err(before(BrokerFailure::PeerRefused { observed_uid }));
    }

    let mut decoder = FrameDecoder::new();
    let hello = read_body(&stream, &mut decoder, until, MAX_HELLO_BODY).map_err(before)?;
    let hello = BrokerHello::decode_frame_body(&hello)
        .map_err(|_| before(BrokerFailure::Protocol("the hello did not decode")))?;

    let (invocation, operation) = order.into_parts();
    let common = Common::new(hello.channel.clone(), invocation.clone());
    let (authorisation, descriptors, sent) = authorise(common, operation).map_err(before)?;
    let frame = authorisation
        .encode_frame()
        .map_err(|_| before(BrokerFailure::Protocol("the authorisation did not encode")))?;
    // From the first byte of this call on, the broker may act.
    send_with_descriptors(&stream, &frame, &descriptors, until)
        .map_err(BrokerError::after_sending)?;
    // The authority's copies close here; the broker's are the only ones left.
    drop(descriptors);

    let after = BrokerError::after_sending;
    let outcome = read_body(&stream, &mut decoder, until, MAX_OUTCOME_BODY).map_err(after)?;
    let outcome = BrokerOutcome::decode_frame_body(&outcome)
        .map_err(|_| after(BrokerFailure::Protocol("the outcome did not decode")))?;
    if outcome.channel != hello.channel {
        return Err(after(BrokerFailure::Protocol(
            "the outcome names another channel",
        )));
    }
    if outcome.invocation_id != invocation {
        return Err(after(BrokerFailure::Protocol(
            "the outcome answers another invocation",
        )));
    }
    match outcome.result() {
        OutcomeResult::Done(done) => deliver(&sent, done).map_err(after),
        OutcomeResult::Refused(why) => Err(after(BrokerFailure::Refused(why))),
        OutcomeResult::Indeterminate(why) => Err(after(BrokerFailure::Indeterminate(why))),
    }
}

fn leaf(parent: &ParentHandoff) -> Result<LeafName, BrokerFailure> {
    LeafName::new(parent.leaf_name()).ok_or(BrokerFailure::Protocol("a checked name is not a leaf"))
}

const fn pair(identity: FileIdentity) -> (u64, u64) {
    (identity.device(), identity.inode())
}

fn target_of(parent: &ParentHandoff) -> Result<(u64, u64), BrokerFailure> {
    parent
        .target()
        .map(|(identity, _)| pair(identity))
        .ok_or(BrokerFailure::Protocol("an existing object was expected"))
}

/// An authorisation, its descriptors in their fixed order, and what to check
/// the answer against.
type Prepared = (Authorisation, Vec<OwnedFd>, Sent);

/// The authorisation for `operation`, its descriptors in their fixed order,
/// and what to check the answer against.
fn authorise(common: Common, operation: Operation) -> Result<Prepared, BrokerFailure> {
    match operation {
        Operation::Read { .. }
        | Operation::Stat { .. }
        | Operation::List { .. }
        | Operation::Search { .. } => observation(common, operation),
        Operation::Write { .. }
        | Operation::Patch { .. }
        | Operation::Move { .. }
        | Operation::Delete { .. } => change(common, operation),
        Operation::Reclaim { directory, staging } => {
            let leaf = LeafName::new(staging.leaf.as_str())
                .ok_or(BrokerFailure::Protocol("a recorded name is not a leaf"))?;
            let (fd, identity) = directory.into_transfer_descriptor();
            Ok((
                Authorisation::FsReclaim(FsReclaimAuthorisation::new(
                    common,
                    pair(identity),
                    leaf,
                    staging.operation,
                    staging.target,
                )),
                vec![fd],
                Sent::Reclaim,
            ))
        }
    }
}

/// An operation that changes nothing: one descriptor, the object itself.
fn observation(common: Common, operation: Operation) -> Result<Prepared, BrokerFailure> {
    Ok(match operation {
        Operation::Read { max_bytes, file } => {
            let (fd, identity) = file.into_transfer_descriptor();
            (
                Authorisation::FsRead(FsReadAuthorisation::new(
                    common.channel,
                    common.invocation_id,
                    identity.device(),
                    identity.inode(),
                    max_bytes,
                )),
                vec![fd],
                Sent::Read {
                    max_bytes: max_bytes.get(),
                },
            )
        }
        Operation::Stat { object } => {
            let (fd, identity) = object.into_transfer_descriptor();
            (
                Authorisation::FsStat(FsStatAuthorisation::new(
                    common,
                    identity.device(),
                    identity.inode(),
                )),
                vec![fd],
                Sent::Stat,
            )
        }
        Operation::List {
            max_entries,
            directory,
        } => {
            let (fd, identity) = directory.into_transfer_descriptor();
            (
                Authorisation::FsList(FsListAuthorisation::new(
                    common,
                    identity.device(),
                    identity.inode(),
                    max_entries,
                )),
                vec![fd],
                Sent::List {
                    max_entries: max_entries.get(),
                },
            )
        }
        Operation::Search {
            needle,
            max_scan_bytes,
            max_matches,
            file,
        } => {
            let length = needle.to_bytes().len();
            let (fd, identity) = file.into_transfer_descriptor();
            (
                Authorisation::FsSearch(FsSearchAuthorisation::new(
                    common,
                    pair(identity),
                    needle,
                    max_scan_bytes,
                    max_matches,
                )),
                vec![fd],
                Sent::Search {
                    needle: length,
                    max_scan: u64::from(max_scan_bytes.get()),
                    max_matches: max_matches.get(),
                },
            )
        }
        Operation::Write { .. }
        | Operation::Patch { .. }
        | Operation::Move { .. }
        | Operation::Delete { .. }
        | Operation::Reclaim { .. } => {
            // Never reached: `authorise` routes by kind. Refused rather than
            // asserted, before anything is sent.
            return Err(BrokerFailure::Protocol("a change is not an observation"));
        }
    })
}

/// An operation that changes names: the parent directories, and for a patch
/// the file.
fn change(common: Common, operation: Operation) -> Result<Prepared, BrokerFailure> {
    Ok(match operation {
        Operation::Write { parent, content } => {
            let name = leaf(&parent)?;
            let target = parent.target().map(|(identity, _)| pair(identity));
            let content = HexContent::from_bytes(&content)
                .ok_or(BrokerFailure::Protocol("the content exceeds its bound"))?;
            let creating = target.is_none();
            let (fd, directory) = parent.into_transfer_descriptor();
            (
                Authorisation::FsWrite(FsWriteAuthorisation::new(
                    common,
                    pair(directory),
                    name,
                    target,
                    content,
                )),
                vec![fd],
                Sent::Write { creating },
            )
        }
        Operation::Patch {
            parent,
            file,
            base,
            post,
            edits,
        } => {
            let name = leaf(&parent)?;
            let target = target_of(&parent)?;
            let (directory_fd, directory) = parent.into_transfer_descriptor();
            let (file_fd, _) = file.into_transfer_descriptor();
            (
                Authorisation::FsPatch(FsPatchAuthorisation::new(
                    common,
                    pair(directory),
                    name,
                    target,
                    (base, post, edits),
                )),
                vec![directory_fd, file_fd],
                Sent::Patch,
            )
        }
        Operation::Move {
            source,
            destination,
        } => {
            let source_leaf = leaf(&source)?;
            let source_identity = target_of(&source)?;
            let destination_leaf = leaf(&destination)?;
            let (source_fd, source_directory) = source.into_transfer_descriptor();
            let (destination_fd, destination_directory) = destination.into_transfer_descriptor();
            (
                Authorisation::FsMove(FsMoveAuthorisation::new(
                    common,
                    MoveSide {
                        parent: pair(source_directory),
                        leaf: source_leaf,
                    },
                    source_identity,
                    MoveSide {
                        parent: pair(destination_directory),
                        leaf: destination_leaf,
                    },
                )),
                vec![source_fd, destination_fd],
                Sent::Move,
            )
        }
        Operation::Delete { parent } => {
            let name = leaf(&parent)?;
            let (target, kind) = parent
                .target()
                .ok_or(BrokerFailure::Protocol("an existing object was expected"))?;
            let kind = match kind {
                ResourceKind::RegularFile => StatKind::RegularFile,
                ResourceKind::Directory => StatKind::Directory,
            };
            let (fd, directory) = parent.into_transfer_descriptor();
            (
                Authorisation::FsDelete(FsDeleteAuthorisation::new(
                    common,
                    pair(directory),
                    name,
                    pair(target),
                    kind,
                )),
                vec![fd],
                Sent::Delete,
            )
        }
        Operation::Read { .. }
        | Operation::Stat { .. }
        | Operation::List { .. }
        | Operation::Search { .. }
        | Operation::Reclaim { .. } => {
            return Err(BrokerFailure::Protocol("an observation is not a change"));
        }
    })
}

/// The answer, if it is this operation's and within every bound it was
/// decided on.
fn deliver(sent: &Sent, done: BrokerDone) -> Result<BrokerDelivery, BrokerFailure> {
    let wrong = BrokerFailure::Protocol("the outcome answers another operation");
    Ok(match sent {
        Sent::Read { max_bytes } => {
            let read = done.fs_read.ok_or(wrong)?;
            let content = read.content.to_bytes();
            if content.len() > usize::try_from(*max_bytes).unwrap_or(usize::MAX) {
                return Err(BrokerFailure::Protocol(
                    "the broker returned more than was authorised",
                ));
            }
            BrokerDelivery::Read(FsReadDelivery {
                content,
                eof_observed: read.eof_observed,
            })
        }
        Sent::Stat => {
            let stat = done.fs_stat.ok_or(wrong)?;
            BrokerDelivery::Stat(StatDelivery {
                kind: stat.kind,
                size: stat.size.get(),
                link_count: stat.link_count.get(),
                mode: stat.mode.get(),
            })
        }
        Sent::List { max_entries } => {
            let list = done.fs_list.ok_or(wrong)?;
            if list.entries.len() > usize::from(*max_entries) {
                return Err(BrokerFailure::Protocol(
                    "the broker listed more entries than were authorised",
                ));
            }
            BrokerDelivery::List(ListDelivery {
                entries: list
                    .entries
                    .into_iter()
                    .map(|entry| RawListEntry {
                        name: entry.name.to_bytes(),
                        kind: entry.kind,
                    })
                    .collect(),
                complete: list.complete,
            })
        }
        Sent::Search {
            needle,
            max_scan,
            max_matches,
        } => search(
            done.fs_search.ok_or(wrong)?,
            *needle,
            *max_scan,
            *max_matches,
        )?,
        Sent::Write { creating } => {
            let write = done.fs_write.ok_or(wrong)?;
            if write.created != *creating {
                return Err(BrokerFailure::Protocol(
                    "the broker created where it was to replace, or the reverse",
                ));
            }
            BrokerDelivery::Write {
                created: write.created,
                debris: write.debris,
            }
        }
        Sent::Patch => {
            let patch = done.fs_patch.ok_or(wrong)?;
            BrokerDelivery::Patch {
                outcome: patch.outcome,
                debris: patch.debris,
            }
        }
        Sent::Move => {
            done.fs_move.ok_or(wrong)?;
            BrokerDelivery::Move
        }
        Sent::Delete => {
            let delete = done.fs_delete.ok_or(wrong)?;
            BrokerDelivery::Delete {
                debris: delete.debris,
            }
        }
        Sent::Reclaim => reclamation(&done.fs_reclaim.ok_or(wrong)?)?,
    })
}

/// A reclamation's answer, if its parts agree: a reason exactly when the
/// directory was retained, and an object's identity exactly when what it holds
/// is an object.
fn reclamation(done: &FsReclaimDone) -> Result<BrokerDelivery, BrokerFailure> {
    let held = match (&done.held_device, &done.held_inode) {
        (Some(device), Some(inode)) => Some((device.value(), inode.value())),
        (None, None) => None,
        _ => return Err(BrokerFailure::Protocol("a held object is half named")),
    };
    let consistent = match (done.state, done.holds) {
        (ReclaimState::Retained, Some(StagingHolds::Displaced | StagingHolds::Taken)) => {
            held.is_some()
        }
        (ReclaimState::Retained, Some(StagingHolds::Evidence)) => held.is_none(),
        (ReclaimState::Retained, Some(StagingHolds::Unexpected)) => true,
        (ReclaimState::Absent | ReclaimState::Removed | ReclaimState::Foreign, None) => {
            held.is_none()
        }
        _ => false,
    };
    if !consistent {
        return Err(BrokerFailure::Protocol(
            "a reclamation's answer does not agree with itself",
        ));
    }
    Ok(BrokerDelivery::Reclaim {
        state: done.state,
        holds: done.holds,
        held,
    })
}

/// A search's answer, if every offset is a whole occurrence within what was
/// scanned, in ascending order, and no more than were allowed.
fn search(
    done: dwk_proto::brokerp::FsSearchDone,
    needle: usize,
    max_scan: u64,
    max_matches: u16,
) -> Result<BrokerDelivery, BrokerFailure> {
    let scanned = done.scanned.get();
    let offsets: Vec<u64> = done
        .offsets
        .into_iter()
        .map(dwk_proto::wire::scalar::ByteCount::get)
        .collect();
    let length = u64::try_from(needle).unwrap_or(u64::MAX);
    let ordered = offsets.windows(2).all(|pair| match pair {
        [a, b] => a < b,
        _ => true,
    });
    let within = offsets
        .iter()
        .all(|offset| offset.checked_add(length).is_some_and(|end| end <= scanned));
    if scanned > max_scan || offsets.len() > usize::from(max_matches) || !ordered || !within {
        return Err(BrokerFailure::Protocol(
            "the broker reported matches outside what it was allowed to scan",
        ));
    }
    Ok(BrokerDelivery::Search(SearchDelivery {
        offsets,
        scanned,
        eof_observed: done.eof_observed,
        matches_truncated: done.matches_truncated,
    }))
}

/// The time left before `until`, or a timeout failure.
fn remaining(until: Instant) -> Result<Duration, BrokerFailure> {
    let now = Instant::now();
    if now >= until {
        return Err(BrokerFailure::Unreachable(Unreachable::Timeout));
    }
    Ok(until - now)
}

fn io_failure(error: &std::io::Error) -> BrokerFailure {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
            BrokerFailure::Unreachable(Unreachable::Timeout)
        }
        _ => BrokerFailure::Unreachable(Unreachable::Io),
    }
}

/// Read one frame body of at most `max` bytes before `until`.
fn read_body(
    mut stream: &UnixStream,
    decoder: &mut FrameDecoder,
    until: Instant,
    max: usize,
) -> Result<Vec<u8>, BrokerFailure> {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if !pending.is_empty() {
            let (consumed, frame) = decoder
                .feed(&pending)
                .map_err(|_| BrokerFailure::Protocol("the broker sent a malformed frame"))?;
            pending.drain(..consumed);
            if let Some(frame) = frame {
                if frame.body.len() > max {
                    return Err(BrokerFailure::Protocol(
                        "the broker sent an oversized message",
                    ));
                }
                if !pending.is_empty() {
                    return Err(BrokerFailure::Protocol(
                        "the broker sent more than one message",
                    ));
                }
                return Ok(frame.body);
            }
        }
        stream
            .set_read_timeout(Some(remaining(until)?))
            .map_err(|e| io_failure(&e))?;
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(BrokerFailure::Protocol(
                    "the broker closed the channel early",
                ));
            }
            Ok(n) => pending.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_failure(&e)),
        }
    }
}

/// Send `frame` with `descriptors`, in order, attached to its first byte.
fn send_with_descriptors(
    mut stream: &UnixStream,
    frame: &[u8],
    descriptors: &[OwnedFd],
    until: Instant,
) -> Result<(), BrokerFailure> {
    stream
        .set_write_timeout(Some(remaining(until)?))
        .map_err(|e| io_failure(&e))?;
    let fds: Vec<_> = descriptors.iter().map(AsFd::as_fd).collect();
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(BrokerFailure::Protocol(
            "the descriptors did not fit their control message",
        ));
    }
    let sent = rustix::net::sendmsg(
        stream,
        &[IoSlice::new(frame)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(|errno| io_failure(&std::io::Error::from(errno)))?;
    // The descriptors travelled with the first byte. Whatever did not fit in
    // that call follows as ordinary bytes.
    let rest = frame.get(sent..).unwrap_or_default();
    stream.write_all(rest).map_err(|e| io_failure(&e))
}
