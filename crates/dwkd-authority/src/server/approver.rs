//! The approver endpoint (F-18 Phase 3.4, [ADR-0067], accepted; its
//! operations M6.3, [ADR-0081], Proposed): a door of its own, apart from the
//! runtime's DWKP socket, for the people who approve.
//!
//! ```text
//!   a process on this host
//!        │  the approver socket (its own path, its own checked place)
//!        ▼
//!   accept ──▶ kernel peer credentials (SO_PEERCRED)            peer.rs
//!        ──▶ is that uid one of the operator's approvers?       this module
//!                 no   → closed before a byte is read; approver.peer_refused
//!                 full → closed before a byte is read; approver.peer_authenticated
//!                        {outcome: closed, reason: connection_limit}
//!                 yes  → approver.peer_authenticated {outcome: admitted}
//!        ──▶ one frame, its length checked from its header      this module
//!        ──▶ approverp::Request, strictly decoded                dwk-proto
//!        ──▶ the worker: Authority::serve_approver              worker.rs → state
//!        ◀── one approverp::Response; the connection is closed
//! ```
//!
//! # Who is an approver
//!
//! A uid the operator listed with `--approver-uid`, and only such a uid: no
//! wildcard, no group, no user name, no exception for root. The list is
//! disjoint from every `--allow-uid` (a runtime's), the broker's uid and the
//! authority's own, with no override for any of them: a runtime that is also
//! an approver could approve its own requests. The parser refuses the first
//! two, the start the third. The set the endpoint admits is the set the
//! registry was attached at start ([`ApproverPolicy::from_set`]): one value,
//! so what is admitted here and what a decision or a spend recognises never
//! diverge. A uid is an operating-system identity, not a person: two people
//! who share one are one approver, and every process of that uid is that
//! approver (ADR-0063 OD-1, ADR-0077 §2).
//!
//! # The kernel decides who, before a byte is read
//!
//! The decision is the kernel's report, never a byte the peer sends, and is
//! made before one is read: a peer that is not an approver is closed with
//! whatever it sent unread. Only an authenticated connection gets a thread,
//! an [`ApproverContext`] -- made here and nowhere else -- and a read: one
//! frame, at most [`approverp::MAX_REQUEST_BODY`] bytes by its header, within
//! [`REQUEST_DEADLINE`] of its acceptance. Then one answer, written within
//! [`WRITE_DEADLINE`], and the connection is closed. There is no second
//! request, no handshake, no session and no idle connection: a person reads
//! and decides between connections, so nothing here waits for one, and no
//! authority gate or transaction is held while they do.
//!
//! # What a connection can reach
//!
//! The three approver operations, through the worker, and nothing else: no
//! DWKP dispatch, no subject, no lease holder, no run, no tool, no broker, no
//! policy, no ownership, no grant. The approver's identity reaches the
//! registry as an [`ApproverPrincipal`] made from the kernel's uid -- no
//! field of a request names one, or a level, which the registry sets (A1).
//! A descriptor a peer attaches is never received: nothing here receives
//! ancillary data (TX061 covers this module as it covers the DWKP endpoint),
//! so the kernel discards it with the bytes that carried it; the endpoint
//! detects nothing and trusts nothing it could not have read.
//!
//! The socket's place is checked as the DWKP socket's is (`socket.rs`):
//! absolute, its final name never followed, in an authority-owned directory no
//! one else can write, under ancestors only root or the authority own, a stale
//! socket removed only if it is this authority's own dead one, one lock per
//! name. An operator who wants a runtime unable even to connect gives the
//! approver socket a directory of its own, `0710` with the approvers' group;
//! that narrows who can reach it, and proves nobody's identity.
//!
//! [ADR-0067]: ../../../../../docs/adr/0067-f18-approver-endpoint-identity-boundary.md
//! [ADR-0081]: ../../../../../docs/adr/0081-the-approver-endpoints-operations-and-the-trusted-approver-client.md

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dwk_proto::approverp::{self, ApproverKind, RefusalCode, Request, Response};
use dwk_proto::frame::{FrameDecoder, HEADER_LEN};

use super::peer::{self, PeerCredentials};
use super::worker::{Shutdown, WorkerHandle};
use crate::state::{ApproverPrincipal, ApproverSet, TransportEvent};

/// Most approver connections served at once. An approver over the limit is
/// closed unread and recorded; nothing waits.
pub(crate) const MAX_APPROVER_CONNECTIONS: usize = 4;

/// From a connection's acceptance to its one request's last byte.
pub(crate) const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// For the one answer to be written.
pub(crate) const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// The most bytes read at once: one request and its header, so a read never
/// holds more than one bounded request.
const READ_CHUNK: usize = approverp::MAX_REQUEST_BODY + HEADER_LEN;

/// The operator's approvers: a closed set of kernel-reported uids, made from
/// the set the registry was attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApproverPolicy {
    uids: BTreeSet<u32>,
}

impl ApproverPolicy {
    /// The endpoint's policy for the registry's attached set.
    pub(crate) fn from_set(set: &ApproverSet) -> Self {
        Self {
            uids: set.uids().iter().copied().collect(),
        }
    }

    /// Whether the kernel reported one of the operator's approvers.
    pub(crate) fn admits(&self, uid: u32) -> bool {
        self.uids.contains(&uid)
    }

    /// The approvers, in order.
    pub(crate) fn uids(&self) -> Vec<u32> {
        self.uids.iter().copied().collect()
    }
}

/// An approver this endpoint authenticated: the uid and pid the kernel
/// reported for one connection, found in the operator's set before a byte of
/// it was read. Made only by [`authenticate`]; it holds no subject, no lease
/// holder and no level, and dies with its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApproverContext {
    uid: u32,
    pid: Option<u32>,
}

impl ApproverContext {
    /// The approver as the registry checks and records them.
    fn principal(self) -> ApproverPrincipal {
        ApproverPrincipal::kernel_reported(self.uid)
    }
}

/// Who a connection is, from the kernel's report alone: an approver, or a
/// refusal to record.
fn authenticate(
    policy: &ApproverPolicy,
    credentials: PeerCredentials,
) -> Result<ApproverContext, TransportEvent> {
    if policy.admits(credentials.uid) {
        Ok(ApproverContext {
            uid: credentials.uid,
            pid: credentials.pid,
        })
    } else {
        Err(TransportEvent::ApproverRefused {
            uid: credentials.uid,
            pid: credentials.pid,
        })
    }
}

/// What an approver connection reaches: the worker's rate-limited transport
/// audit, and the registry's three operations. The worker in production; a
/// test's own in this module's tests.
pub(crate) trait Approvals: Clone + Send + 'static {
    /// Record a transport event, rate-limited.
    fn record(&self, event: TransportEvent);
    /// Answer one request for `approver`; `None` when the authority cannot
    /// answer truthfully.
    fn answer(&self, approver: ApproverPrincipal, request: Request) -> Option<Response>;
}

impl Approvals for WorkerHandle {
    fn record(&self, event: TransportEvent) {
        self.audit(event);
    }

    fn answer(&self, approver: ApproverPrincipal, request: Request) -> Option<Response> {
        self.approver(approver, request)
    }
}

/// Releases a connection slot when its thread ends, however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections on the approver socket until the server stops. Each is
/// judged by its kernel-reported uid before a byte is read: refused and
/// closed, closed at the connection limit, or admitted to its one request on
/// a thread of its own. Every judgement is recorded through `approvals`.
pub(crate) fn accept(
    listener: &UnixListener,
    policy: &ApproverPolicy,
    approvals: &impl Approvals,
    shutdown: &Shutdown,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        if shutdown.stopping() {
            return;
        }
        let Ok(stream) = incoming else {
            // Out of descriptors, an aborted connection: nothing was read
            // and nothing is owed. Pause so a persistent condition does not
            // spin.
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        let Ok(credentials) = peer::peer_credentials(&stream) else {
            super::log(
                "an approver-endpoint connection whose peer the kernel could not identify was \
                 closed",
            );
            continue;
        };
        let context = match authenticate(policy, credentials) {
            Ok(context) => context,
            Err(refused) => {
                approvals.record(refused);
                drop(stream);
                continue;
            }
        };
        if active.load(Ordering::SeqCst) >= MAX_APPROVER_CONNECTIONS {
            approvals.record(TransportEvent::ApproverAuthenticated {
                uid: context.uid,
                pid: context.pid,
                admitted: false,
            });
            drop(stream);
            continue;
        }
        approvals.record(TransportEvent::ApproverAuthenticated {
            uid: context.uid,
            pid: context.pid,
            admitted: true,
        });
        active.fetch_add(1, Ordering::SeqCst);
        let slot = Slot(Arc::clone(&active));
        let approvals = approvals.clone();
        // A thread that cannot start takes its slot and its connection with
        // it: the closure that owned both is dropped, unread.
        let _ = std::thread::Builder::new()
            .name("dwkp-approver-connection".to_owned())
            .spawn(move || {
                let _slot = slot;
                serve(stream, context, &approvals);
            });
    }
}

/// Why no request was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unread {
    /// Not one well-formed frame within its bound: an oversized or empty
    /// declaration, a reserved content type, bytes past the one request, or
    /// a stream that ended inside it. Answered `MALFORMED_REQUEST`.
    Framing,
    /// The deadline passed, the socket failed, or the peer left before a
    /// byte: nothing is owed.
    Gone,
}

/// The one request on an authenticated connection: a whole frame of at most
/// [`approverp::MAX_REQUEST_BODY`] bytes by its header, nothing after it,
/// before `deadline`.
fn read_request(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, Unread> {
    let mut decoder = FrameDecoder::bounded(approverp::MAX_REQUEST_BODY);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Unread::Gone);
        }
        stream
            .set_read_timeout(Some(deadline - now))
            .map_err(|_| Unread::Gone)?;
        let read = match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(if decoder.is_idle() {
                    Unread::Gone
                } else {
                    Unread::Framing
                });
            }
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Unread::Gone),
        };
        let mut rest = chunk.get(..read).unwrap_or_default();
        while !rest.is_empty() {
            let (consumed, frame) = decoder.feed(rest).map_err(|_| Unread::Framing)?;
            rest = rest.get(consumed..).unwrap_or_default();
            if let Some(frame) = frame {
                if !rest.is_empty() {
                    // A second request, or bytes past the first: one request
                    // per connection, and nothing is guessed.
                    return Err(Unread::Framing);
                }
                return Ok(frame.body);
            }
            if consumed == 0 {
                break;
            }
        }
    }
}

/// Which operation a decoded request is.
const fn operation(request: &Request) -> ApproverKind {
    match request {
        Request::List => ApproverKind::List,
        Request::Show(_) => ApproverKind::Show,
        Request::Decide { .. } => ApproverKind::Decide,
    }
}

/// The request id a decoded request names, as bytes.
fn named(request: &Request) -> Option<[u8; 32]> {
    let id = match request {
        Request::List => return None,
        Request::Show(id) | Request::Decide { request_id: id, .. } => id.as_str(),
    };
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(id.as_bytes().chunks(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

/// Write the one answer. Best effort: the approver may already be gone, and a
/// decision recorded is recorded whether or not its answer arrives -- the
/// client reads it back with `approver.show`.
fn reply(stream: &mut UnixStream, response: &Response) {
    match response.encode_frame() {
        Ok(frame) => {
            let _ = stream.write_all(&frame).and_then(|()| stream.flush());
        }
        Err(error) => super::log(&format!(
            "an approver-endpoint answer could not be encoded: {}",
            error.detail
        )),
    }
}

/// Serve one authenticated connection: read its one request, have the
/// registry answer it, write the answer, close.
fn serve(mut stream: UnixStream, context: ApproverContext, approvals: &impl Approvals) {
    let _ = stream.set_write_timeout(Some(WRITE_DEADLINE));
    let refuse = |stream: &mut UnixStream, code: RefusalCode| {
        approvals.record(TransportEvent::ApproverRequestRefused {
            uid: context.uid,
            operation: None,
            code,
            request: None,
        });
        reply(stream, &Response::Refused(code));
    };
    let body = match read_request(&mut stream, Instant::now() + REQUEST_DEADLINE) {
        Ok(body) => body,
        Err(Unread::Framing) => {
            refuse(&mut stream, RefusalCode::MalformedRequest);
            return;
        }
        Err(Unread::Gone) => return,
    };
    let request = match Request::decode_frame_body(&body) {
        Ok(request) => request,
        Err(malformed) => {
            refuse(&mut stream, malformed.code());
            return;
        }
    };
    let (kind, id) = (operation(&request), named(&request));
    // The authority could not answer truthfully: nothing was decided, and
    // the connection closes unanswered.
    let Some(response) = approvals.answer(context.principal(), request) else {
        return;
    };
    if let Response::Refused(code) = &response {
        approvals.record(TransportEvent::ApproverRequestRefused {
            uid: context.uid,
            operation: Some(kind),
            code: *code,
            request: id,
        });
    }
    reply(&mut stream, &response);
}

// Linux, as the server is: the kernel's peer credentials and its reset on
// unread bytes are what these tests observe.
#[cfg(all(test, target_os = "linux"))]
#[path = "approver_tests.rs"]
mod tests;
