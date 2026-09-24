//! The authority's end of the private broker channel, on Linux (M4b,
//! ADR-0043).
//!
//! One of the three authority modules that may name `rustix` (TX008), and the
//! only one that may send a descriptor or take one out of a [`ReadHandoff`]
//! (TX014). The exchange, and where each property comes from:
//!
//! | step | property |
//! |---|---|
//! | `connect` to the configured path | none: the path is not trusted |
//! | `SO_PEERCRED` == broker uid, else close | **only the broker is sent anything** |
//! | read `BrokerHello`, bounded | the channel this authorisation will name |
//! | `sendmsg` authorisation + one fd (`SCM_RIGHTS`) | the checked file, as a descriptor |
//! | read `FsReadOutcome`, bounded, same channel and invocation | the answer is to *this* authorisation |
//!
//! Every read and write is under one deadline for the whole exchange, so a
//! stalling peer costs at most [`super::EXCHANGE_DEADLINE`].
//!
//! [`ReadHandoff`]: crate::resource::ReadHandoff

use std::io::{ErrorKind, IoSlice, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::{
    self, BrokerHello, FsReadAuthorisation, FsReadOutcome, MAX_HELLO_BODY, MAX_OUTCOME_BODY,
    OutcomeResult,
};
use dwk_proto::frame::FrameDecoder;
use rustix::fd::AsFd as _;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

use super::{BrokerFailure, FsReadDelivery, FsReadOrder, Unreachable};

/// Perform one `fs.read` through the broker at `socket`, which must be served
/// by `broker_uid`.
pub(super) fn fs_read(
    socket: &Path,
    broker_uid: u32,
    deadline: Duration,
    order: FsReadOrder,
) -> Result<FsReadDelivery, BrokerFailure> {
    let until = Instant::now() + deadline;
    let stream = UnixStream::connect(socket)
        .map_err(|_| BrokerFailure::Unreachable(Unreachable::Connect))?;
    // Who is listening, as the kernel recorded it when the broker called
    // listen(2). Nothing has been sent yet, and nothing is sent to anyone else.
    let cred = rustix::net::sockopt::socket_peercred(&stream)
        .map_err(|_| BrokerFailure::Unreachable(Unreachable::PeerCredentials))?;
    let observed_uid = cred.uid.as_raw();
    if observed_uid != broker_uid {
        return Err(BrokerFailure::PeerRefused { observed_uid });
    }

    let mut decoder = FrameDecoder::new();
    let hello = read_body(&stream, &mut decoder, until, MAX_HELLO_BODY)?;
    let hello = BrokerHello::decode_frame_body(&hello)
        .map_err(|_| BrokerFailure::Protocol("the hello did not decode"))?;

    let FsReadOrder {
        invocation,
        max_bytes,
        file,
    } = order;
    let (descriptor, identity) = file.into_transfer_descriptor();
    let authorisation = FsReadAuthorisation::new(
        hello.channel.clone(),
        invocation.clone(),
        identity.device(),
        identity.inode(),
        max_bytes,
    );
    let frame = brokerp::encode_frame(&authorisation)
        .map_err(|_| BrokerFailure::Protocol("the authorisation did not encode"))?;
    send_with_descriptor(&stream, &frame, &descriptor, until)?;
    // The authority's copy of the descriptor closes here; the broker's copy is
    // the only one left.
    drop(descriptor);

    let outcome = read_body(&stream, &mut decoder, until, MAX_OUTCOME_BODY)?;
    let outcome = FsReadOutcome::decode_frame_body(&outcome)
        .map_err(|_| BrokerFailure::Protocol("the outcome did not decode"))?;
    if outcome.channel != hello.channel {
        return Err(BrokerFailure::Protocol("the outcome names another channel"));
    }
    if outcome.invocation_id != invocation {
        return Err(BrokerFailure::Protocol(
            "the outcome answers another invocation",
        ));
    }
    match outcome
        .result()
        .map_err(|_| BrokerFailure::Protocol("the outcome has no single result"))?
    {
        OutcomeResult::Done(done) => {
            let content = done.content.to_bytes();
            let bound = usize::try_from(max_bytes.get()).unwrap_or(usize::MAX);
            if content.len() > bound {
                return Err(BrokerFailure::Protocol(
                    "the broker returned more than was authorised",
                ));
            }
            Ok(FsReadDelivery {
                content,
                eof_observed: done.eof_observed,
            })
        }
        OutcomeResult::Refused(why) => Err(BrokerFailure::Refused(why)),
    }
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

/// Send `frame` with exactly one descriptor attached to its first byte.
fn send_with_descriptor(
    mut stream: &UnixStream,
    frame: &[u8],
    descriptor: &std::os::fd::OwnedFd,
    until: Instant,
) -> Result<(), BrokerFailure> {
    stream
        .set_write_timeout(Some(remaining(until)?))
        .map_err(|e| io_failure(&e))?;
    let fds = [descriptor.as_fd()];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(BrokerFailure::Protocol(
            "the descriptor did not fit its control message",
        ));
    }
    let sent = rustix::net::sendmsg(
        stream,
        &[IoSlice::new(frame)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(|errno| io_failure(&std::io::Error::from(errno)))?;
    // The descriptor travelled with the first byte. Whatever did not fit in
    // that call follows as ordinary bytes.
    let rest = frame.get(sent..).unwrap_or_default();
    stream.write_all(rest).map_err(|e| io_failure(&e))
}
