//! One exchange on one connection from the authority (M4b, ADR-0043; the M4c
//! operations, ADR-0044).
//!
//! | step | refusal, before anything is read or changed |
//! |---|---|
//! | send `BrokerHello{channel}` | — |
//! | receive one frame (at most one DWKP frame) and every descriptor with it | malformed: close, no reply |
//! | decode strictly as one authorisation, by its `kind`, with the kind's descriptor count | malformed: close, no reply |
//! | channel is this connection's | `CHANNEL_MISMATCH` |
//! | exactly the kind's descriptors arrived, control data not truncated | `DESCRIPTOR_COUNT` |
//! | each descriptor is its role's open mode and kind, and the object named | `DESCRIPTOR_NOT_*`, `IDENTITY_MISMATCH` |
//! | the operation's own checks | see `observe`, `search`, `mutate`, `staging` |
//!
//! **Exactly the kind's descriptors, or none is used.** Too few, too many —
//! or truncated control data — is `DESCRIPTOR_COUNT`: every descriptor that
//! arrived is closed and nothing is done through any of them. At most two are
//! ever held while the count is judged; any beyond that is closed the moment
//! it arrives.
//!
//! Then one `BrokerOutcome` — `done`, `refused` (no persistent change) or
//! `indeterminate` (something may have been, and the broker cannot prove
//! what) — and the connection closes: a second authorisation on the same
//! connection is never read.
//!
//! The broker has no path to open: it acts on the objects the authority
//! checked, through the descriptors the authority opened, on at most the one
//! validated name the authorisation carries, after proving each descriptor is
//! the object named. It does not canonicalise, resolve, evaluate policy or
//! record anything; the authority does all of that, before and after.

pub(crate) mod checks;
mod mutate;
mod observe;
mod search;
mod staging;

use std::io::{IoSliceMut, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::{
    self, Authorisation, BrokerHello, BrokerOutcome, BrokerRefusal, ChannelNonce,
    MAX_AUTHORISATION_BODY, OutcomeResult,
};
use dwk_proto::frame::{ContentType, HEADER_LEN};
use rustix::io::Errno;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};

/// How long one exchange may take, end to end. The authority's own deadline
/// is the same, so neither waits on the other for longer.
pub(crate) const DEADLINE: Duration = Duration::from_secs(10);

/// The largest authorisation frame, header included.
const MAX_AUTHORISATION_FRAME: usize = HEADER_LEN + MAX_AUTHORISATION_BODY;

/// The most descriptors any authorisation carries.
const MAX_DESCRIPTORS: usize = 2;

/// Serve one connection the kernel says the authority made. `own_uid` is the
/// broker's effective uid, which its staging directories must be owned by;
/// `processes` is this broker instance's process table.
pub(crate) fn serve_one(
    stream: &UnixStream,
    channel: Option<ChannelNonce>,
    own_uid: u32,
    processes: &crate::process::Processes,
) {
    let Some(channel) = channel else {
        crate::event("channels_exhausted");
        return;
    };
    let until = Instant::now() + DEADLINE;
    let hello = BrokerHello::new(channel.clone());
    let sent =
        brokerp::encode_frame(&hello).is_ok_and(|frame| write_all(stream, &frame, until).is_ok());
    if !sent {
        crate::event("hello_failed");
        return;
    }

    let received = match receive(stream, until) {
        Ok(received) => received,
        Err(why) => {
            crate::event(&format!("malformed reason={why}"));
            return;
        }
    };
    let Ok(authorisation) = Authorisation::decode_frame_body(&received.body) else {
        crate::event("malformed reason=authorisation");
        return;
    };
    let invocation = authorisation.invocation_id().clone();
    let operation = authorisation.kind().as_str();
    let result = execute(
        &channel,
        &authorisation,
        received.descriptors,
        own_uid,
        processes,
    );
    match &result {
        OutcomeResult::Done(done) => {
            let detail = done.fs_read.as_ref().map_or_else(String::new, |read| {
                format!(
                    " bytes={} eof_observed={}",
                    read.content.byte_len(),
                    read.eof_observed
                )
            });
            crate::event(&format!(
                "executed invocation={}{detail} op={operation}",
                invocation.as_str()
            ));
        }
        OutcomeResult::Refused(why) => crate::event(&format!(
            "refused invocation={} reason={} op={operation}",
            invocation.as_str(),
            why.as_str()
        )),
        OutcomeResult::Indeterminate(why) => crate::event(&format!(
            "indeterminate invocation={} reason={} op={operation}",
            invocation.as_str(),
            why.as_str()
        )),
    }
    let outcome = BrokerOutcome::new(channel, invocation, result);
    let delivered =
        brokerp::encode_frame(&outcome).is_ok_and(|frame| write_all(stream, &frame, until).is_ok());
    if !delivered {
        crate::event("outcome_failed");
    }
}

/// What arrived: one frame body, and the descriptors that came with it.
struct Received {
    body: Vec<u8>,
    descriptors: Descriptors,
}

/// Every descriptor that arrived with the authorisation, counted.
///
/// At most [`MAX_DESCRIPTORS`] are held, and only until the count is judged:
/// any later one is closed the moment it arrives, because a message that
/// carries more than its kind's count is refused whatever the first ones are
/// — so a peer cannot make the broker hold descriptors by sending many, and
/// nothing is ever done through a descriptor before the count is known to be
/// exactly right.
#[derive(Default)]
struct Descriptors {
    held: Vec<OwnedFd>,
    count: usize,
    truncated: bool,
}

impl Descriptors {
    fn receive(&mut self, fd: OwnedFd) {
        self.count = self.count.saturating_add(1);
        if self.held.len() < MAX_DESCRIPTORS {
            self.held.push(fd);
        } else {
            // Beyond any kind's count: closed here, unused.
            drop(fd);
        }
    }

    /// The descriptors — when exactly `expected` arrived, intact, and the
    /// authorisation declared exactly that many. Otherwise every descriptor
    /// that arrived is closed here, unused, and the answer is a refusal.
    fn exactly(self, declared: u8, expected: u8) -> Result<Vec<OwnedFd>, BrokerRefusal> {
        let Self {
            held,
            count,
            truncated,
        } = self;
        let expected = usize::from(expected);
        let exact = !truncated
            && count == expected
            && usize::from(declared) == expected
            && held.len() == expected;
        if exact {
            Ok(held)
        } else {
            drop(held);
            Err(BrokerRefusal::DescriptorCount)
        }
    }
}

fn remaining(until: Instant) -> Option<Duration> {
    let now = Instant::now();
    (now < until).then(|| until - now)
}

fn write_all(mut stream: &UnixStream, bytes: &[u8], until: Instant) -> Result<(), ()> {
    let left = remaining(until).ok_or(())?;
    stream.set_write_timeout(Some(left)).map_err(|_| ())?;
    stream.write_all(bytes).map_err(|_| ())
}

/// Receive exactly one frame of at most [`MAX_AUTHORISATION_FRAME`] bytes,
/// collecting every descriptor attached to any of its bytes. Nothing past the
/// frame is read.
fn receive(stream: &UnixStream, until: Instant) -> Result<Received, &'static str> {
    let mut buffer = vec![0u8; MAX_AUTHORISATION_FRAME];
    let mut filled = 0usize;
    let mut want = HEADER_LEN;
    let mut descriptors = Descriptors::default();
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    loop {
        if filled == want {
            if want == HEADER_LEN {
                let header = buffer.get(..HEADER_LEN).ok_or("header")?;
                let [a, b, c, d, content] =
                    <[u8; HEADER_LEN]>::try_from(header).map_err(|_| "header")?;
                if ContentType::from_byte(content) != Some(ContentType::Json) {
                    return Err("content_type");
                }
                let length =
                    usize::try_from(u32::from_be_bytes([a, b, c, d])).map_err(|_| "length")?;
                if length == 0 || length > MAX_AUTHORISATION_BODY {
                    return Err("length");
                }
                want = HEADER_LEN.saturating_add(length);
                continue;
            }
            let body = buffer.get(HEADER_LEN..want).ok_or("body")?.to_vec();
            return Ok(Received { body, descriptors });
        }
        let left = remaining(until).ok_or("timeout")?;
        stream.set_read_timeout(Some(left)).map_err(|_| "timeout")?;
        let window = buffer.get_mut(filled..want).ok_or("window")?;
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = match rustix::net::recvmsg(
            stream.as_fd(),
            &mut [IoSliceMut::new(window)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(received) => received,
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => return Err("timeout"),
            Err(_) => return Err("io"),
        };
        if received.flags.contains(ReturnFlags::CTRUNC) {
            descriptors.truncated = true;
        }
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                for fd in fds {
                    descriptors.receive(fd);
                }
            }
        }
        // Anything the buffer did not drain is closed when it drops here.
        drop(control);
        if received.bytes == 0 {
            return Err(if filled == 0 {
                "closed"
            } else {
                "closed_mid_frame"
            });
        }
        filled = filled.saturating_add(received.bytes);
    }
}

/// Check the authorisation's channel and descriptor count, then perform it.
fn execute(
    channel: &ChannelNonce,
    authorisation: &Authorisation,
    descriptors: Descriptors,
    own_uid: u32,
    processes: &crate::process::Processes,
) -> OutcomeResult {
    if authorisation.channel() != channel {
        return OutcomeResult::Refused(BrokerRefusal::ChannelMismatch);
    }
    let Some(expected) = authorisation.kind().descriptors() else {
        return OutcomeResult::Refused(BrokerRefusal::DescriptorCount);
    };
    let fds = match descriptors.exactly(authorisation.declared_descriptors(), expected) {
        Ok(fds) => fds,
        Err(refusal) => return OutcomeResult::Refused(refusal),
    };
    let mut fds = fds.into_iter();
    // The process operations (M4d): a launch carries exactly the executable
    // and the working directory, in that order; a status or a kill carries
    // none, and `exactly` has already closed any that arrived.
    match authorisation {
        Authorisation::ProcessStart(start) => {
            return match (fds.next(), fds.next(), fds.next()) {
                (Some(executable), Some(cwd), None) => processes.start(start, executable, cwd),
                _ => OutcomeResult::Refused(BrokerRefusal::DescriptorCount),
            };
        }
        Authorisation::ProcessStatus(status) => return processes.status(status),
        Authorisation::ProcessKill(kill) => return processes.kill(kill),
        _ => {}
    }
    let (Some(first), second) = (fds.next(), fds.next()) else {
        return OutcomeResult::Refused(BrokerRefusal::DescriptorCount);
    };
    match (authorisation, second) {
        (Authorisation::FsRead(read), None) => observe::read(read, &first),
        (Authorisation::FsStat(stat), None) => observe::stat(stat, &first),
        (Authorisation::FsList(list), None) => observe::list(list, first),
        (Authorisation::FsSearch(found), None) => search::search(found, &first),
        (Authorisation::FsWrite(write), None) => mutate::write(write, &first, own_uid),
        (Authorisation::FsPatch(patch), Some(file)) => mutate::patch(patch, &first, &file, own_uid),
        (Authorisation::FsMove(moved), Some(destination)) => {
            mutate::move_file(moved, &first, &destination)
        }
        (Authorisation::FsDelete(delete), None) => mutate::delete(delete, &first, own_uid),
        (Authorisation::FsReclaim(reclaim), None) => staging::reclaim(reclaim, &first, own_uid),
        _ => OutcomeResult::Refused(BrokerRefusal::DescriptorCount),
    }
}

#[cfg(test)]
mod tests;
