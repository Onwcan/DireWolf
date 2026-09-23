//! One accepted, authenticated connection: frames in, decoded requests to
//! the worker, answers out — one at a time.
//!
//! By the time a connection reaches this module the kernel has reported its
//! peer's uid and the operator's peer policy has admitted it. Everything here
//! runs with one [`CallerContext`], minted by the authority for this
//! connection alone; it lives on this thread's stack, is never stored
//! anywhere another connection could reach it, and dies when the connection
//! does.
//!
//! # One request at a time
//!
//! A frame is read whole, decoded by `dwk-proto`'s production decoder,
//! answered, and only then is the next one read. There is no pipelining, no
//! multiplexing and no stream id: within a connection, answers come in the
//! order requests were sent, and a client that sends several at once simply
//! has them answered in turn.
//!
//! # Close or continue
//!
//! | what arrives | answer | then |
//! |---|---|---|
//! | a request the authority answers (including `authority.refused`) | the response | **continue** |
//! | a framing error: empty, oversized, reserved content type | `direwolf.protocol.error` | close — a length-prefixed stream has no trustworthy next boundary (ADR-0032) |
//! | end of stream inside a frame | `PROTOCOL_FRAME_TRUNCATED` if the peer still reads | close; the partial request never reaches the authority |
//! | a complete frame that does not decode | `direwolf.protocol.error` | close — DWKP's peers ship together, so malformed input is a bug or an attack, and "a single bad frame closes the connection" (ADR-0032) |
//! | a handshake with no common version | `PROTOCOL_VERSION_UNSUPPORTED` naming the supported range | close |
//! | a request before the handshake, a second handshake, a response or an event | nothing | close — no wire code says "out of order" truthfully |
//! | a request in another envelope version than the negotiated one | `PROTOCOL_VERSION_UNSUPPORTED` | close |
//! | an authority that cannot answer truthfully | nothing | close; the server stops if the store is poisoned |
//! | end of stream between frames | nothing | close: a normal disconnect |
//! | a deadline passes | nothing | close |
//!
//! Every close for a protocol violation is recorded in `audit.log`. A timeout
//! is an availability control, not a verdict, and is not.
//!
//! # Deadlines
//!
//! A connection must complete its handshake within [`Limits::handshake`] of
//! being accepted. Once a frame has begun, all of it must arrive within
//! [`Limits::frame`] — so a peer trickling one byte at a time holds a worker
//! slot for a bounded time, not for ever. Between frames a connection may be
//! silent for [`Limits::idle`], which is a lease lifetime plus a grace period:
//! a connection quieter than that cannot be keeping a lease alive. Writes time
//! out after [`Limits::write`], so a peer that stops reading loses its
//! connection instead of blocking anything else.
//!
//! Disconnecting ends nothing in the state machine. The holder can no longer
//! be presented, and the lease it held stays exactly as the state layer's
//! release, expiry and restart rules leave it (ADR-0041).

use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use dwk_proto::dwkp::messages::HandshakeAccepted;
use dwk_proto::dwkp::{self, DwkpBody};
use dwk_proto::error::ProtocolError;
use dwk_proto::frame::{Frame, FrameDecoder};
use dwk_proto::version::HANDSHAKE_ENVELOPE_VERSION;
use dwk_proto::wire::scalar::Version;

use super::envelope::Responder;
use super::peer::PeerCredentials;
use super::protocol::{self, Phase, Step};
use super::worker::WorkerHandle;
use crate::state::{AuthenticatedSubject, CallerContext, TransportEvent, Violation};

/// How long a connection may take over each part of its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// From accept to a complete handshake.
    pub(crate) handshake: Duration,
    /// From a frame's first byte to its last.
    pub(crate) frame: Duration,
    /// Silence allowed between frames, once established.
    pub(crate) idle: Duration,
    /// For one response to be written.
    pub(crate) write: Duration,
}

impl Limits {
    /// The limits for a server whose leases live `lease_ttl_ms`.
    pub(crate) fn for_lease_ttl(lease_ttl_ms: u64) -> Self {
        Self {
            handshake: Duration::from_secs(5),
            frame: Duration::from_secs(5),
            idle: Duration::from_millis(lease_ttl_ms).saturating_add(Duration::from_secs(5)),
            write: Duration::from_secs(5),
        }
    }
}

/// The most bytes read from the socket at once. With the decoder's own bound,
/// a connection holds at most one frame body (1 MiB) plus this.
const READ_CHUNK: usize = 16 * 1024;

/// Why a frame could not be read.
#[derive(Debug)]
enum ReadError {
    /// A deadline passed.
    TimedOut,
    /// The stream ended inside a frame.
    Truncated(ProtocolError),
    /// The bytes are not a frame.
    Framing(ProtocolError),
    /// The socket failed.
    Io,
}

/// Frames from a stream, never buffering more than one frame plus a chunk.
struct FrameReader {
    decoder: FrameDecoder,
    pending: Vec<u8>,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
        }
    }

    /// The next frame, `None` at a clean end of stream between frames.
    ///
    /// `idle_until` bounds the wait for a frame to begin; once one has begun,
    /// it must end within `frame_budget`.
    fn next(
        &mut self,
        stream: &mut UnixStream,
        idle_until: Instant,
        frame_budget: Duration,
    ) -> Result<Option<Frame>, ReadError> {
        let mut frame_deadline = (!self.pending.is_empty() || !self.decoder.is_idle())
            .then(|| Instant::now() + frame_budget);
        loop {
            while !self.pending.is_empty() {
                let (consumed, frame) = self
                    .decoder
                    .feed(&self.pending)
                    .map_err(ReadError::Framing)?;
                self.pending.drain(..consumed.min(self.pending.len()));
                if let Some(frame) = frame {
                    return Ok(Some(frame));
                }
                if consumed == 0 {
                    break;
                }
            }
            let deadline = frame_deadline.unwrap_or(idle_until);
            let now = Instant::now();
            if now >= deadline {
                return Err(ReadError::TimedOut);
            }
            stream
                .set_read_timeout(Some(deadline - now))
                .map_err(|_| ReadError::Io)?;
            let mut chunk = [0u8; READ_CHUNK];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return match self.decoder.finish() {
                        Ok(()) => Ok(None),
                        Err(error) => Err(ReadError::Truncated(error)),
                    };
                }
                Ok(read) => {
                    if frame_deadline.is_none() {
                        frame_deadline = Some(Instant::now() + frame_budget);
                    }
                    self.pending
                        .extend_from_slice(chunk.get(..read).unwrap_or_default());
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Err(ReadError::TimedOut);
                }
                Err(_) => return Err(ReadError::Io),
            }
        }
    }
}

/// Serve one connection until it closes.
pub(crate) fn serve(
    mut stream: UnixStream,
    peer: PeerCredentials,
    worker: &WorkerHandle,
    responder: &Responder,
    limits: Limits,
) {
    // One holder for this connection, minted here and nowhere else.
    let Some(caller) = worker.connect(AuthenticatedSubject::unix_uid(peer.uid)) else {
        return;
    };
    let _ = stream.set_write_timeout(Some(limits.write));
    let connection = Connection {
        peer,
        caller,
        worker,
        responder,
    };
    connection.run(&mut stream, limits);
    // Dropping the stream closes it; nothing else holds this descriptor.
}

struct Connection<'a> {
    peer: PeerCredentials,
    caller: CallerContext,
    worker: &'a WorkerHandle,
    responder: &'a Responder,
}

impl Connection<'_> {
    fn run(&self, stream: &mut UnixStream, limits: Limits) {
        let accepted = Instant::now();
        let mut phase = Phase::AwaitingHandshake;
        let mut reader = FrameReader::new();
        loop {
            let (idle_until, version) = match phase {
                Phase::AwaitingHandshake => {
                    (accepted + limits.handshake, HANDSHAKE_ENVELOPE_VERSION)
                }
                Phase::Established(version) => (Instant::now() + limits.idle, version),
            };
            let frame = match reader.next(stream, idle_until, limits.frame) {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(ReadError::TimedOut | ReadError::Io) => return,
                Err(ReadError::Truncated(error)) => {
                    self.answer_error(stream, version, None, &error);
                    self.violation(Violation::Truncated);
                    return;
                }
                Err(ReadError::Framing(error)) => {
                    self.answer_error(stream, version, None, &error);
                    self.violation(Violation::Framing(error.code));
                    return;
                }
            };
            // The production decoder: the same one the protocol tests, the
            // shared vectors and the fuzz targets exercise.
            let message = match dwkp::decode_frame(&frame) {
                Ok(message) => message,
                Err(error) => {
                    self.answer_error(stream, version, None, &error);
                    self.violation(Violation::Malformed(error.code));
                    return;
                }
            };
            match protocol::step(phase, protocol::classify(&message)) {
                Step::Accept(negotiated) => {
                    let Some(accepted_version) = Version::new(negotiated) else {
                        return;
                    };
                    let body = DwkpBody::HandshakeAccepted(HandshakeAccepted {
                        version: accepted_version,
                    });
                    if !self.answer(stream, HANDSHAKE_ENVELOPE_VERSION, &message.header, body) {
                        return;
                    }
                    phase = Phase::Established(negotiated);
                }
                Step::Reject(error, violation) => {
                    self.answer_error(stream, version, Some(&message.header), &error);
                    self.violation(violation);
                    return;
                }
                Step::Close(violation) => {
                    self.violation(violation);
                    return;
                }
                Step::Dispatch => {
                    let header = message.header.clone();
                    let Ok(body) = self.worker.dispatch(self.caller, message) else {
                        return;
                    };
                    if !self.answer(stream, version, &header, body) {
                        return;
                    }
                }
            }
        }
    }

    /// Write one response. `false` if it could not be built or written, in
    /// which case the connection closes.
    fn answer(
        &self,
        stream: &mut UnixStream,
        version: u16,
        request: &dwk_proto::envelope::Header,
        body: DwkpBody,
    ) -> bool {
        match self.responder.frame(version, Some(request), body) {
            Ok(frame) => stream
                .write_all(&frame)
                .and_then(|()| stream.flush())
                .is_ok(),
            Err(error) => {
                super::log(&format!("a response could not be encoded: {}", error.0));
                false
            }
        }
    }

    /// Best effort: the peer may already be gone.
    fn answer_error(
        &self,
        stream: &mut UnixStream,
        version: u16,
        request: Option<&dwk_proto::envelope::Header>,
        error: &ProtocolError,
    ) {
        if let Ok(frame) = self.responder.protocol_error(version, request, error) {
            let _ = stream.write_all(&frame).and_then(|()| stream.flush());
        }
    }

    fn violation(&self, violation: Violation) {
        self.worker.audit(TransportEvent::ProtocolViolation {
            uid: self.peer.uid,
            holder: self.caller.holder(),
            violation,
        });
    }
}
