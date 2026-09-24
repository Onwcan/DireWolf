//! One exchange on one connection from the authority (M4b, ADR-0043).
//!
//! | step | refusal, before any byte of the file is read |
//! |---|---|
//! | send `BrokerHello{channel}` | — |
//! | receive one frame (at most 16 KiB) and every descriptor with it | malformed: close, no reply |
//! | decode strictly as `FsReadAuthorisation` | malformed: close, no reply |
//! | channel is this connection's | `CHANNEL_MISMATCH` |
//! | exactly the declared one descriptor, control data not truncated | `DESCRIPTOR_COUNT` |
//! | open for reading only, not `O_PATH` | `DESCRIPTOR_NOT_READABLE` |
//! | a regular file | `DESCRIPTOR_NOT_REGULAR` |
//! | `(st_dev, st_ino)` is the authorised object's | `IDENTITY_MISMATCH` |
//! | `pread` from offset 0, at most `max_bytes` | `READ_FAILED` |
//!
//! **Never a byte past the bound.** Every read's window ends at `max_bytes`,
//! and no read is made once the bound is reached, so the end of the file is
//! reported only when it was *observed* — a read returned nothing before the
//! bound (`eof_observed`). Exactly `max_bytes` read leaves the end unproven: to
//! prove it would take reading byte `max_bytes + 1`, which the authority did not
//! authorise.
//!
//! **Exactly one descriptor, or none is used.** No descriptor, two, three —
//! or truncated control data — is `DESCRIPTOR_COUNT`: every descriptor that
//! arrived is closed and nothing is read from any of them. The first is not
//! "the one" with the rest discarded.
//!
//! Then one `FsReadOutcome` and the connection closes: a second authorisation
//! on the same connection is never read.
//!
//! The broker has no path to open: it reads the one object the authority
//! checked, through the descriptor the authority opened, after proving the
//! descriptor is that object. It does not canonicalise, resolve, evaluate
//! policy or record anything; the authority does all of that, before and
//! after.

use std::io::{IoSliceMut, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::{
    self, BrokerHello, BrokerRefusal, ChannelNonce, FS_READ_DESCRIPTORS, FsReadAuthorisation,
    FsReadDone, FsReadOutcome, MAX_AUTHORISATION_BODY, OutcomeResult,
};
use dwk_proto::frame::{ContentType, HEADER_LEN};
use dwk_proto::wire::scalar::HexContent;
use rustix::fs::{FileType, OFlags};
use rustix::io::Errno;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};

/// How long one exchange may take, end to end. The authority's own deadline
/// is the same, so neither waits on the other for longer.
pub(crate) const DEADLINE: Duration = Duration::from_secs(10);

/// The largest authorisation frame, header included.
const MAX_AUTHORISATION_FRAME: usize = HEADER_LEN + MAX_AUTHORISATION_BODY;

/// Serve one connection the kernel says the authority made.
pub(crate) fn serve_one(stream: &UnixStream, channel: Option<ChannelNonce>) {
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
    let Ok(authorisation) = FsReadAuthorisation::decode_frame_body(&received.body) else {
        crate::event("malformed reason=authorisation");
        return;
    };
    let invocation = authorisation.invocation_id.clone();
    let result = execute(&channel, &authorisation, received.descriptors);
    match &result {
        OutcomeResult::Done(done) => crate::event(&format!(
            "executed invocation={} bytes={} eof_observed={}",
            invocation.as_str(),
            done.content.byte_len(),
            done.eof_observed
        )),
        OutcomeResult::Refused(why) => crate::event(&format!(
            "refused invocation={} reason={}",
            invocation.as_str(),
            why.as_str()
        )),
    }
    let outcome = FsReadOutcome::new(channel, invocation, result);
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
/// Only the first is held, and only until the count is judged: every later
/// one is closed the moment it arrives, because a message that carries more
/// than one is refused whatever the first one is — so a peer cannot make the
/// broker hold descriptors by sending many, and nothing is ever read from a
/// descriptor before the count is known to be exactly one.
#[derive(Default)]
struct Descriptors {
    first: Option<OwnedFd>,
    count: usize,
    truncated: bool,
}

impl Descriptors {
    fn receive(&mut self, fd: OwnedFd) {
        self.count = self.count.saturating_add(1);
        if self.count == 1 {
            self.first = Some(fd);
        } else {
            // Not the first: closed here, unread.
            drop(fd);
        }
    }

    /// The one descriptor — when exactly one arrived, intact, and the
    /// authorisation declared exactly one. Otherwise every descriptor that
    /// arrived is closed here, unread, and the answer is a refusal.
    fn exactly_one(self, declared: u8) -> Result<OwnedFd, BrokerRefusal> {
        let Self {
            first,
            count,
            truncated,
        } = self;
        let exact = !truncated && count == 1 && declared == FS_READ_DESCRIPTORS;
        match first {
            Some(fd) if exact => Ok(fd),
            other => {
                drop(other);
                Err(BrokerRefusal::DescriptorCount)
            }
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

/// Check the authorisation and its descriptor, then read.
fn execute(
    channel: &ChannelNonce,
    authorisation: &FsReadAuthorisation,
    descriptors: Descriptors,
) -> OutcomeResult {
    if &authorisation.channel != channel {
        return OutcomeResult::Refused(BrokerRefusal::ChannelMismatch);
    }
    let file = match descriptors.exactly_one(authorisation.descriptors.get()) {
        Ok(file) => file,
        Err(refusal) => return OutcomeResult::Refused(refusal),
    };
    let Ok(flags) = rustix::fs::fcntl_getfl(&file) else {
        return OutcomeResult::Refused(BrokerRefusal::DescriptorNotReadable);
    };
    if flags.contains(OFlags::PATH) || flags & OFlags::RWMODE != OFlags::RDONLY {
        return OutcomeResult::Refused(BrokerRefusal::DescriptorNotReadable);
    }
    let Ok(st) = rustix::fs::fstat(&file) else {
        return OutcomeResult::Refused(BrokerRefusal::ReadFailed);
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return OutcomeResult::Refused(BrokerRefusal::DescriptorNotRegular);
    }
    let identity = (widen(st.st_dev), widen(st.st_ino));
    if identity != (authorisation.device.value(), authorisation.inode.value()) {
        return OutcomeResult::Refused(BrokerRefusal::IdentityMismatch);
    }
    match read_bounded(&file, authorisation.max_bytes.get()) {
        Some(done) => OutcomeResult::Done(done),
        None => OutcomeResult::Refused(BrokerRefusal::ReadFailed),
    }
}

/// Widen a kernel integer without a lossy cast.
fn widen<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

/// Read at most `max_bytes` from offset zero of the handed descriptor.
fn read_bounded(file: &OwnedFd, max_bytes: u32) -> Option<FsReadDone> {
    read_within(max_bytes, |window, offset| {
        rustix::io::pread(file, window, offset)
    })
}

/// Read at most `max_bytes` bytes from offset zero through `read_at`, asking
/// for no byte past the bound: every window ends at `max_bytes`, and no read
/// is made once it is reached. The end of the file is reported only when a
/// read returned nothing before the bound — never discovered by reading past
/// it. The buffer is sized from the bound, which decoding has already limited
/// to 256 KiB, so nothing is allocated before the bound is known to hold.
///
/// `read_at` is the file: `pread` in production, a counting double in tests.
fn read_within(
    max_bytes: u32,
    mut read_at: impl FnMut(&mut [u8], u64) -> Result<usize, Errno>,
) -> Option<FsReadDone> {
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
    Some(FsReadDone {
        content: HexContent::from_bytes(&content)?,
        eof_observed,
    })
}

#[cfg(test)]
mod tests;
