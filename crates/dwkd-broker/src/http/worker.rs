//! The exchange worker: `dwkd-broker http-worker` (D11, ADR-0050 §9). One
//! hop, then it exits -- and every byte of the hop's plaintext, in every
//! allocation of every library that touched it, goes with its address space.
//!
//! **Why a process.** `rustls` copies each decrypted record into a buffer of
//! its own, and the `http` crate's header map copies each response header
//! value; both are freed without being zeroed, and neither can be scrubbed by
//! safe code. In the long-lived broker an origin that echoed the credential
//! left it there until the allocator reused the block. Here the long-lived
//! broker never holds the credential's header, the request or a byte of the
//! response: the worker that does is gone before the broker answers.
//!
//! **What the broker keeps, and what the worker gets.** The broker judges the
//! hop again and dials (`super::Client::prepare`, `super::connect`): the
//! worker is handed a TCP connection **already made to a pinned address**, so
//! it chooses no destination and resolves no name, and the credential's value
//! in a fresh pipe the broker filled once (`super::render::hand_on`). It
//! cannot reach the authority, the store or the CONNECT proxy: it holds no
//! descriptor for them.
//!
//! | step | the worker | the broker |
//! |---|---|---|
//! | 1 | its stderr is the control channel (a socket pair); its peer must be its parent broker: same uid, pid = parent pid | spawns it: empty environment, stdin and stdout `/dev/null`, its own process group |
//! | 2 | `RLIMIT_CORE` 0, not dumpable, the parent-death signal (`SIGKILL`), `no_new_privs`; no inheritable descriptor | sends the hand-over and the descriptors, then closes its copies |
//! | 3 | receives the hand-over: the trust, the hop's time left, the authorisation frame; and one or two descriptors | -- |
//! | 4 | `super::converse`: credential, request, TLS, response, redaction; `S` on the channel before the first request byte | reads the channel to end of file, under the hop's deadline and a grace |
//! | 5 | `A`, the answer's length, the outcome frame; exits | reaps it, decodes the outcome strictly, checks it answers this hop |
//!
//! **What the broker concludes** when no answer comes: a worker that never
//! wrote `S` sent nothing (`HTTP_WORKER_FAILED`); one that did may have been
//! heard by the origin (`EXCHANGE_UNCONFIRMED`, which the authority records
//! as `UNKNOWN` and never repeats). A worker that overruns is killed.
//!
//! Run by anyone else, its stderr is not a socket whose peer is its parent
//! broker, and it exits having done nothing. It reads no environment, no file
//! and no flag: the trust it uses is the one its broker was started with.

use std::io::{IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::http::HttpExchangeAuthorisation;
use dwk_proto::brokerp::{
    Authorisation, BrokerOutcome, BrokerRefusal, Indeterminate, MAX_AUTHORISATION_BODY,
    MAX_OUTCOME_BODY, OutcomeResult,
};
use dwk_proto::frame::{ContentType, HEADER_LEN, decode_all};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use super::tls::{ANCHOR_MAX_BYTES, Trust};
use super::{Deadlines, Prepared, converse, outcome};

/// The hand-over's magic and version.
const MAGIC: &[u8; 5] = b"DWHW1";

/// What the worker writes, once, immediately before the first byte of the
/// request.
pub(crate) const SENDING: &[u8; 1] = b"S";

/// What precedes the worker's answer.
const ANSWER: u8 = b'A';

/// How long past the hop's own deadline the broker waits for an answer: the
/// worker's start, and the outcome's encoding.
const GRACE: Duration = Duration::from_secs(5);

/// How long the hand-over may take to send.
const HAND_OVER: Duration = Duration::from_secs(5);

/// The largest hand-over: its fixed fields, an evidence anchor and one
/// authorisation frame.
const MAX_HAND_OVER: usize = 64 + ANCHOR_MAX_BYTES + HEADER_LEN + MAX_AUTHORISATION_BODY;

/// The most the broker reads from a worker: the marker, the answer's tag and
/// length, and one outcome frame.
const MAX_ANSWER: usize = 1 + 1 + 4 + HEADER_LEN + MAX_OUTCOME_BODY;

/// The trust as it travels: `0` for Mozilla's roots, `1` and its PEM text
/// for the evidence anchor.
fn put_trust(out: &mut Vec<u8>, trust: &Trust) {
    match trust {
        Trust::Production => out.push(0),
        Trust::Evidence(pem) => {
            out.push(1);
            out.extend_from_slice(&u32::try_from(pem.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(pem);
        }
    }
}

/// The hand-over: its length, then `DWHW1`, the hop's time left in
/// milliseconds, the trust, and the authorisation's frame.
fn encode(trust: &Trust, left: Duration, frame: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(frame.len().saturating_add(64));
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(
        &u64::try_from(left.as_millis())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    put_trust(&mut body, trust);
    body.extend_from_slice(frame);
    let mut out = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&body);
    out
}

/// A hand-over, decoded.
#[derive(Debug, PartialEq, Eq)]
struct HandOver {
    trust: Trust,
    left: Duration,
    exchange: HttpExchangeAuthorisation,
}

/// Take `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = rest.split_at_checked(n)?;
    *rest = tail;
    Some(head)
}

/// Decode a hand-over body (after its length): strictly, the authorisation
/// by the private protocol's own decoder, and nothing else.
fn decode(body: &[u8]) -> Option<HandOver> {
    let mut rest = body;
    if take(&mut rest, MAGIC.len())? != MAGIC {
        return None;
    }
    let left = Duration::from_millis(u64::from_be_bytes(take(&mut rest, 8)?.try_into().ok()?));
    let trust = match take(&mut rest, 1)? {
        [0] => Trust::Production,
        [1] => {
            let length =
                usize::try_from(u32::from_be_bytes(take(&mut rest, 4)?.try_into().ok()?)).ok()?;
            if length > ANCHOR_MAX_BYTES {
                return None;
            }
            Trust::Evidence(take(&mut rest, length)?.to_vec())
        }
        _ => return None,
    };
    let [frame] = decode_all(rest).ok()?.try_into().ok()?;
    if frame.content_type != ContentType::Json {
        return None;
    }
    let Authorisation::HttpExchange(exchange) =
        Authorisation::decode_frame_body(&frame.body).ok()?
    else {
        return None;
    };
    Some(HandOver {
        trust,
        left,
        exchange,
    })
}

// ---- the broker's side --------------------------------------------------------

/// Stop and reap a worker.
fn abandon(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Send `payload` with `descriptors`, attached to its first byte.
fn send(stream: &UnixStream, payload: &[u8], descriptors: &[&OwnedFd]) -> std::io::Result<()> {
    stream.set_write_timeout(Some(HAND_OVER))?;
    let fds: Vec<_> = descriptors.iter().map(|fd| fd.as_fd()).collect();
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(std::io::Error::other("the descriptors did not fit"));
    }
    let sent = rustix::net::sendmsg(
        stream,
        &[IoSlice::new(payload)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(std::io::Error::from)?;
    let mut writer = stream;
    writer.write_all(payload.get(sent..).unwrap_or_default())
}

/// Read what the worker writes, to end of file or `until`: at most
/// [`MAX_ANSWER`] bytes, and whether end of file was reached.
fn read_answer(stream: &UnixStream, until: Instant) -> (Vec<u8>, bool) {
    let mut read = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut reader = stream;
    loop {
        let now = Instant::now();
        if now >= until || read.len() > MAX_ANSWER {
            return (read, false);
        }
        if stream.set_read_timeout(Some(until - now)).is_err() {
            return (read, false);
        }
        match reader.read(&mut chunk) {
            Ok(0) => return (read, true),
            Ok(n) => read.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (read, false),
        }
    }
}

/// What the worker's channel said: whether it began sending, and the outcome
/// it answered with, if any and if it answers `exchange`.
fn parse_answer(
    bytes: &[u8],
    exchange: &HttpExchangeAuthorisation,
) -> (bool, Option<OutcomeResult>) {
    match bytes.split_first() {
        Some((b'S', rest)) => (true, answer_of(rest, exchange)),
        _ => (false, answer_of(bytes, exchange)),
    }
}

/// `A`, a length, and exactly that many bytes of one outcome frame -- decoded
/// strictly, and only if it answers `exchange`.
fn answer_of(bytes: &[u8], exchange: &HttpExchangeAuthorisation) -> Option<OutcomeResult> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != ANSWER {
        return None;
    }
    let (length, frame) = rest.split_at_checked(4)?;
    let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    if frame.len() != length {
        return None;
    }
    let [frame] = decode_all(frame).ok()?.try_into().ok()?;
    if frame.content_type != ContentType::Json {
        return None;
    }
    let outcome = BrokerOutcome::decode_frame_body(&frame.body).ok()?;
    (outcome.channel == exchange.channel && outcome.invocation_id == exchange.invocation_id)
        .then(|| outcome.result())
}

/// Run one hop's exchange in a worker of `binary`: hand it `prepared` -- the
/// connection and the credential's pipe -- and the hop, and return its
/// answer. The broker's copies of both descriptors are closed once sent.
pub(super) fn exchange(
    binary: &Path,
    trust: &Trust,
    authorisation: &HttpExchangeAuthorisation,
    prepared: Prepared,
    hop_until: Instant,
) -> OutcomeResult {
    let failed = OutcomeResult::Refused(BrokerRefusal::HttpWorkerFailed);
    let Ok(frame) = Authorisation::HttpExchange(authorisation.clone()).encode_frame() else {
        return OutcomeResult::Refused(BrokerRefusal::HttpRequestInvalid);
    };
    let left = hop_until.saturating_duration_since(Instant::now());
    let payload = encode(trust, left, &frame);
    let Ok((ours, theirs)) = UnixStream::pair() else {
        return failed;
    };
    let mut command = Command::new(binary);
    command
        .arg("http-worker")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(OwnedFd::from(theirs)))
        .process_group(0);
    let spawned = {
        let _fork = crate::process::fork_guard();
        command.spawn()
    };
    let Ok(mut child) = spawned else {
        return failed;
    };
    // The parent's copy of the worker's end closes here: end of file on ours
    // means the worker's side closed.
    drop(command);
    let Prepared { socket, credential } = prepared;
    let socket = OwnedFd::from(socket);
    let mut descriptors = vec![&socket];
    if let Some(fd) = &credential {
        descriptors.push(fd);
    }
    let sent = send(&ours, &payload, &descriptors);
    // The worker holds the only copies now.
    drop(socket);
    drop(credential);
    if sent.is_err() {
        abandon(&mut child);
        return failed;
    }
    let (bytes, ended) = read_answer(&ours, hop_until + GRACE);
    if ended {
        let _ = child.wait();
    } else {
        abandon(&mut child);
    }
    match parse_answer(&bytes, authorisation) {
        (_, Some(result)) if ended => result,
        (true, _) => OutcomeResult::Indeterminate(Indeterminate::ExchangeUnconfirmed),
        (false, _) => failed,
    }
}

// ---- the worker's side ---------------------------------------------------------

/// Receive the hand-over and its one or two descriptors: the connection, and
/// the credential's pipe exactly when the hop carries one.
fn receive(control: &UnixStream) -> Option<(HandOver, Prepared)> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let mut first = vec![0u8; MAX_HAND_OVER.saturating_add(4)];
    let received = rustix::net::recvmsg(
        control,
        &mut [IoSliceMut::new(&mut first)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .ok()?;
    if received.flags.contains(ReturnFlags::CTRUNC) || received.bytes < 4 {
        return None;
    }
    let mut fds: Vec<OwnedFd> = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    let mut data = first.get(..received.bytes)?.to_vec();
    drop(first);
    let length = usize::try_from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    if length > MAX_HAND_OVER {
        return None;
    }
    let want = length.checked_add(4)?;
    let mut reader = control;
    while data.len() < want {
        let mut chunk = vec![0u8; want - data.len()];
        let n = reader.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(chunk.get(..n)?);
    }
    if data.len() != want {
        return None;
    }
    let hand_over = decode(data.get(4..)?)?;
    let credential = if fds.len() == 2 { fds.pop() } else { None };
    let [socket]: [OwnedFd; 1] = fds.try_into().ok()?;
    if hand_over.exchange.credential.is_some() != credential.is_some() {
        return None;
    }
    let prepared = Prepared::handed(socket, credential);
    Some((hand_over, prepared))
}

/// The worker's own hardening, before it reads anything: no core, not
/// dumpable, dies with its broker, gains no privilege (`hardening::worker`),
/// and inherited nothing beyond its standard streams.
fn harden(parent: Option<rustix::process::Pid>) -> bool {
    crate::hardening::worker(parent)
        && crate::process::inheritable_descriptors().is_ok_and(|found| found.is_empty())
}

/// The worker's whole life: one hop, answered, or nothing at all.
pub(crate) fn serve() -> ExitCode {
    // 1. The control channel: stderr, as the broker spawned it, and its peer
    // the parent broker.
    let Ok(control) = std::io::stderr().as_fd().try_clone_to_owned() else {
        return ExitCode::from(2);
    };
    let mut control = UnixStream::from(control);
    let parent = rustix::process::getppid();
    let parent_pid = parent.and_then(|p| u32::try_from(p.as_raw_nonzero().get()).ok());
    let authentic = crate::peer::of(&control).is_ok_and(|peer| {
        crate::peer::is_parent(peer, parent_pid, rustix::process::geteuid().as_raw())
    });
    if !authentic {
        // Not started by a broker: nothing is read, nothing is done.
        return ExitCode::from(2);
    }
    // 2. Hardened before anything is received.
    if !harden(parent) {
        return ExitCode::from(3);
    }
    // 3. The hop.
    let Some((hand_over, prepared)) = receive(&control) else {
        return ExitCode::from(4);
    };
    let hop_until = Instant::now() + hand_over.left;
    let marker = control.try_clone().ok();
    let result = match hand_over.trust.config() {
        Ok(config) => outcome(converse(
            &config,
            Deadlines::PRODUCTION,
            &hand_over.exchange,
            prepared,
            hop_until,
            marker,
        )),
        Err(_) => OutcomeResult::Refused(BrokerRefusal::HttpRequestInvalid),
    };
    // 4. The answer, and the end.
    let exchange = hand_over.exchange;
    let answer = BrokerOutcome::new(exchange.channel, exchange.invocation_id, result);
    let Ok(frame) = dwk_proto::brokerp::encode_frame(&answer) else {
        return ExitCode::from(5);
    };
    let mut message = Vec::with_capacity(frame.len().saturating_add(5));
    message.push(ANSWER);
    message.extend_from_slice(&u32::try_from(frame.len()).unwrap_or(u32::MAX).to_be_bytes());
    message.extend_from_slice(&frame);
    if control.write_all(&message).is_err() {
        return ExitCode::from(6);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dwk_proto::brokerp::http::{
        ExchangeDisposition, HeaderCount, HttpExchangeDone, HttpStatus, ResponseHeaders,
    };
    use dwk_proto::brokerp::{BrokerDone, BrokerOutcome, BrokerRefusal, OutcomeResult};
    use dwk_proto::wire::scalar::{ByteCount, HexContent};

    use super::{ANSWER, HandOver, Trust, decode, encode, parse_answer};

    fn exchange() -> dwk_proto::brokerp::http::HttpExchangeAuthorisation {
        super::super::tests::authorisation_for_worker_tests()
    }

    #[test]
    fn a_hand_over_round_trips_and_nothing_else_decodes() {
        let exchange = exchange();
        let frame = dwk_proto::brokerp::Authorisation::HttpExchange(exchange.clone())
            .encode_frame()
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        for trust in [Trust::Production, Trust::Evidence(b"-----BEGIN".to_vec())] {
            let bytes = encode(&trust, Duration::from_millis(1500), &frame);
            let body = bytes.get(4..).unwrap_or_default();
            assert_eq!(
                decode(body),
                Some(HandOver {
                    trust: trust.clone(),
                    left: Duration::from_millis(1500),
                    exchange: exchange.clone(),
                })
            );
            // Any byte cut, any magic changed, any trailing byte: refused.
            for cut in 0..body.len() {
                assert_eq!(
                    decode(body.get(..cut).unwrap_or_default()),
                    None,
                    "cut {cut}"
                );
            }
            let mut wrong = body.to_vec();
            if let Some(first) = wrong.first_mut() {
                *first = b'X';
            }
            assert_eq!(decode(&wrong), None);
            let mut longer = body.to_vec();
            longer.push(0);
            assert_eq!(decode(&longer), None);
        }
    }

    #[test]
    fn an_answer_is_believed_only_whole_and_for_its_own_hop() {
        let exchange = exchange();
        let done = HttpExchangeDone {
            disposition: ExchangeDisposition::Completed,
            status: HttpStatus::new(204),
            headers: ResponseHeaders::new(Vec::new()).unwrap_or_else(|| unreachable!()),
            location: None,
            body: HexContent::from_bytes(b"").unwrap_or_else(|| unreachable!()),
            truncated: false,
            headers_dropped: HeaderCount::new(0).unwrap_or_else(|| unreachable!()),
            cookies_dropped: HeaderCount::new(0).unwrap_or_else(|| unreachable!()),
            credential_echoes: HeaderCount::new(0).unwrap_or_else(|| unreachable!()),
            bytes_sent: ByteCount::new(10).unwrap_or_else(|| unreachable!()),
            bytes_received: ByteCount::new(10).unwrap_or_else(|| unreachable!()),
        };
        let result = OutcomeResult::done(BrokerDone::http_exchange(done));
        let framed = |outcome: &BrokerOutcome| {
            let frame =
                dwk_proto::brokerp::encode_frame(outcome).unwrap_or_else(|e| unreachable!("{e:?}"));
            let mut out = vec![b'S', ANSWER];
            out.extend_from_slice(&u32::try_from(frame.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&frame);
            out
        };
        let ours = framed(&BrokerOutcome::new(
            exchange.channel.clone(),
            exchange.invocation_id.clone(),
            result.clone(),
        ));
        assert_eq!(parse_answer(&ours, &exchange), (true, Some(result.clone())));
        // Cut anywhere: sent, but no answer.
        for cut in 1..ours.len() {
            assert_eq!(
                parse_answer(ours.get(..cut).unwrap_or_default(), &exchange),
                (true, None)
            );
        }
        // Nothing at all: nothing was sent.
        assert_eq!(parse_answer(b"", &exchange), (false, None));
        // A refusal before sending.
        let refused = BrokerOutcome::new(
            exchange.channel.clone(),
            exchange.invocation_id.clone(),
            OutcomeResult::Refused(BrokerRefusal::HttpTlsFailed),
        );
        let bytes = framed(&refused);
        assert_eq!(
            parse_answer(bytes.get(1..).unwrap_or_default(), &exchange),
            (
                false,
                Some(OutcomeResult::Refused(BrokerRefusal::HttpTlsFailed))
            )
        );
        // Another hop's answer is no answer.
        let other = BrokerOutcome::new(
            exchange.channel.clone(),
            dwk_proto::wire::id::InvocationId::parse("inv_01M24BB8G4E87TVJX9GX248ADE")
                .unwrap_or_else(|| unreachable!()),
            result,
        );
        assert_eq!(parse_answer(&framed(&other), &exchange), (true, None));
    }
}
