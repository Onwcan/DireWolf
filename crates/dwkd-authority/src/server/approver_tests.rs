//! The approver endpoint's own tests (M6.3, ADR-0081): the kernel's
//! judgement before a byte is read, one bounded request per connection, the
//! connection limit and the deadline -- against a recording registry, so that
//! what reaches the authority is exactly what is asserted. The real registry
//! behind the real worker is `state/approver_route_tests.rs`'s.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::approverp::{self, ApproverKind, RefusalCode, Request, Response};

use super::{
    Approvals, ApproverPolicy, MAX_APPROVER_CONNECTIONS, PeerCredentials, REQUEST_DEADLINE, accept,
    authenticate,
};
use crate::server::worker::Shutdown;
use crate::state::{ApproverPrincipal, ApproverSet, TransportEvent};

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn policy(uids: &[u32]) -> ApproverPolicy {
    ApproverPolicy::from_set(&ApproverSet::new(uids, u32::MAX).unwrap())
}

fn peer(uid: u32) -> PeerCredentials {
    PeerCredentials { uid, pid: Some(77) }
}

#[test]
fn only_a_uid_the_operator_named_is_an_approver() {
    let approvers = policy(&[2001, 2002]);
    assert!(authenticate(&approvers, peer(2001)).is_ok());
    assert!(approvers.admits(2002));
    // A runtime's uid, root, the uid next door: refused, by the uid the
    // kernel reported.
    for uid in [1001, 0, 2000, 2003, u32::MAX] {
        assert_eq!(
            authenticate(&approvers, peer(uid)),
            Err(TransportEvent::ApproverRefused { uid, pid: Some(77) }),
            "{uid}"
        );
    }
    assert_eq!(approvers.uids(), [2001, 2002]);
}

#[test]
fn the_endpoints_set_is_the_registrys_set_and_never_a_default() {
    // The policy is made only from the set the registry was attached: no
    // empty set, no repeat, never the authority's own uid, at most the
    // parser's bound.
    assert!(ApproverSet::new(&[], 0).is_err(), "no default approver");
    assert!(ApproverSet::new(&[2001, 2001], 0).is_err(), "a repeat");
    assert!(
        ApproverSet::new(&[2001, 1000], 1000).is_err(),
        "the authority"
    );
    let bound = u32::try_from(crate::server::MAX_APPROVER_UIDS).unwrap();
    let full: Vec<u32> = (2000..2000 + bound).collect();
    assert!(ApproverSet::new(&full, 0).is_ok(), "the parser's bound");
    let over: Vec<u32> = (2000..=2000 + bound).collect();
    assert!(ApproverSet::new(&over, 0).is_err(), "one past it");
    let set = ApproverSet::new(&[2002, 2001], 1000).unwrap();
    assert_eq!(set.uids(), [2001, 2002]);
    assert_eq!(ApproverPolicy::from_set(&set).uids(), set.uids());
}

/// A test's registry: what it was asked, what it recorded, and one answer
/// for everything; held at a barrier when asked to.
#[derive(Clone, Default)]
struct Recorder {
    records: Arc<Mutex<Vec<TransportEvent>>>,
    asked: Arc<Mutex<Vec<(ApproverPrincipal, Request)>>>,
    answer: Option<Response>,
    hold: Option<Arc<Barrier>>,
}

impl Approvals for Recorder {
    fn record(&self, event: TransportEvent) {
        self.records.lock().unwrap().push(event);
    }

    fn answer(&self, approver: ApproverPrincipal, request: Request) -> Option<Response> {
        self.asked.lock().unwrap().push((approver, request));
        if let Some(hold) = &self.hold {
            hold.wait();
            hold.wait();
        }
        self.answer.clone()
    }
}

impl Recorder {
    fn records(&self) -> Vec<TransportEvent> {
        self.records.lock().unwrap().clone()
    }

    fn asked(&self) -> Vec<(ApproverPrincipal, Request)> {
        self.asked.lock().unwrap().clone()
    }
}

/// A listening approver socket in a directory of its own.
struct Door {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
    listener: Option<UnixListener>,
}

type Running = (Arc<Shutdown>, std::thread::JoinHandle<()>);

impl Door {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "dw-approver-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("approver.sock");
        let listener = UnixListener::bind(&path).unwrap();
        Self {
            dir,
            path,
            listener: Some(listener),
        }
    }

    fn own_uid(&self) -> u32 {
        std::fs::metadata(&self.dir).unwrap().uid()
    }

    fn client(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        stream
    }

    /// The accept loop on its own thread for `approvals`, admitting `uids`.
    fn serve(&mut self, uids: &[u32], approvals: &Recorder) -> Running {
        let listener = self.listener.take().unwrap();
        let policy = policy(uids);
        let shutdown = Arc::new(Shutdown::default());
        let stopping = Arc::clone(&shutdown);
        let approvals = approvals.clone();
        let thread = std::thread::spawn(move || {
            accept(&listener, &policy, &approvals, &stopping);
        });
        (shutdown, thread)
    }

    fn stop(&self, running: Running) {
        running.0.request_stop();
        let _ = UnixStream::connect(&self.path);
        running.1.join().unwrap();
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What a client read before the end, and whether the end was a reset --
/// the kernel's word that the server closed with bytes of ours unread.
fn read_all(stream: &mut UnixStream) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return (out, false),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return (out, true);
            }
            Err(error) => panic!("reading the answer: {error}"),
        }
    }
}

fn answer_of(bytes: &[u8]) -> Response {
    Response::decode_frame_body(&bytes[dwk_proto::frame::HEADER_LEN..]).unwrap()
}

fn eventually(mut test: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !test() {
        assert!(Instant::now() < deadline, "never happened");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_peer_that_is_not_an_approver_is_closed_before_a_byte_is_read() {
    // The client writes a whole, valid request before the endpoint even
    // accepts. The endpoint judges it by the kernel's uid alone and closes it
    // with that request unread: the kernel reports the reset only unread
    // bytes cause, nothing was answered, the registry was asked nothing, and
    // the record is a refusal.
    let mut door = Door::new("refused");
    let me = door.own_uid();
    let mut client = door.client();
    client
        .write_all(&Request::List.encode_frame().unwrap())
        .unwrap();
    let recorder = Recorder::default();
    let running = door.serve(&[me.wrapping_add(1).max(1)], &recorder);
    let (bytes, reset) = read_all(&mut client);
    assert!(bytes.is_empty(), "nothing answered");
    assert!(reset, "closed with the request unread");
    eventually(|| !recorder.records().is_empty());
    assert_eq!(
        recorder.records()[0],
        TransportEvent::ApproverRefused {
            uid: me,
            pid: Some(std::process::id())
        }
    );
    assert!(
        recorder.asked().is_empty(),
        "the registry was asked nothing"
    );
    door.stop(running);
}

fn id_bytes() -> [u8; 32] {
    let mut id = [0u8; 32];
    for (slot, i) in id.iter_mut().zip((0..64).step_by(2)) {
        *slot = u8::from_str_radix(&ID[i..i + 2], 16).unwrap();
    }
    id
}

#[test]
fn an_approver_has_one_request_read_and_answered_as_the_kernel_reported_them() {
    let mut door = Door::new("served");
    let me = door.own_uid();
    let recorder = Recorder {
        answer: Some(Response::Refused(RefusalCode::NotPending)),
        ..Recorder::default()
    };
    let running = door.serve(&[me], &recorder);
    let mut client = door.client();
    let request = Request::Show(approverp::RequestId::new(ID).unwrap());
    client.write_all(&request.encode_frame().unwrap()).unwrap();
    let (bytes, reset) = read_all(&mut client);
    assert!(!reset);
    assert_eq!(
        answer_of(&bytes),
        Response::Refused(RefusalCode::NotPending)
    );
    // The registry was asked once, for the approver the kernel reported,
    // with the request as decoded.
    assert_eq!(
        recorder.asked(),
        [(ApproverPrincipal::kernel_reported(me), request)]
    );
    eventually(|| recorder.records().len() >= 2);
    let records = recorder.records();
    assert_eq!(
        records[0],
        TransportEvent::ApproverAuthenticated {
            uid: me,
            pid: Some(std::process::id()),
            admitted: true
        }
    );
    assert_eq!(
        records[1],
        TransportEvent::ApproverRequestRefused {
            uid: me,
            operation: Some(ApproverKind::Show),
            code: RefusalCode::NotPending,
            request: Some(id_bytes()),
        }
    );
    door.stop(running);
}

/// One authenticated connection that sends `bytes` and waits for the end:
/// what it was answered, and what reached the registry. A frame never
/// completed is closed at the endpoint's deadline.
fn exchange(bytes: &[u8]) -> (Option<Response>, Vec<(ApproverPrincipal, Request)>) {
    let mut door = Door::new("frame");
    let me = door.own_uid();
    let recorder = Recorder {
        answer: Some(Response::Refused(RefusalCode::UnknownRequest)),
        ..Recorder::default()
    };
    let running = door.serve(&[me], &recorder);
    let mut client = door.client();
    let _ = client.write_all(bytes);
    let (answer, _) = read_all(&mut client);
    let answer = (!answer.is_empty()).then(|| answer_of(&answer));
    let asked = recorder.asked();
    door.stop(running);
    (answer, asked)
}

fn declared(n: u32) -> Vec<u8> {
    let mut frame = n.to_be_bytes().to_vec();
    frame.push(0x01);
    frame
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut frame = declared(u32::try_from(body.len()).unwrap());
    frame.extend_from_slice(body);
    frame
}

#[test]
fn every_malformed_frame_is_refused_and_reaches_nothing() {
    let list = Request::List.encode_frame().unwrap();
    let mut oversized = declared(u32::try_from(approverp::MAX_REQUEST_BODY + 1).unwrap());
    oversized.extend_from_slice(&[b' '; 64]);
    let mut wrong_type = list.clone();
    wrong_type[4] = 0x02;
    let mut two = list.clone();
    two.extend_from_slice(&list);
    let mut trailing = list.clone();
    trailing.push(b'x');
    let truncated = list[..list.len() - 3].to_vec();
    let cases: [(&str, Vec<u8>); 9] = [
        ("declared too large", oversized),
        ("empty", declared(0)),
        ("reserved content type", wrong_type),
        ("two requests", two),
        ("trailing byte", trailing),
        ("not JSON", framed(b"hello")),
        (
            "an unknown operation",
            framed(br#"{"kind":"approver.revoke","protocol":1}"#),
        ),
        (
            "a claimed level",
            framed(br#"{"assurance":"A2","kind":"approver.list","protocol":1}"#),
        ),
        (
            "a DWKP handshake",
            framed(br#"{"envelope":1,"type":"direwolf.handshake"}"#),
        ),
    ];
    for (name, bytes) in cases {
        let (answer, asked) = exchange(&bytes);
        assert_eq!(
            answer,
            Some(Response::Refused(RefusalCode::MalformedRequest)),
            "{name}"
        );
        assert!(asked.is_empty(), "{name} reached the registry");
    }
    let (answer, asked) = exchange(&framed(br#"{"kind":"approver.list","protocol":2}"#));
    assert_eq!(
        answer,
        Some(Response::Refused(RefusalCode::UnsupportedProtocol))
    );
    assert!(asked.is_empty());
    // A frame that never ends, and nothing at all: closed unanswered at the
    // deadline, nothing reached.
    for (name, bytes) in [
        ("ended inside the frame", truncated),
        ("nothing", Vec::new()),
    ] {
        let (answer, asked) = exchange(&bytes);
        assert_eq!(answer, None, "{name}");
        assert!(asked.is_empty(), "{name}");
    }
}

#[test]
fn an_oversized_declaration_is_refused_from_its_header_alone() {
    // A header declaring one byte past the bound, and nothing after it: the
    // endpoint answers at once -- it never waits for, or keeps, a body.
    let mut door = Door::new("header");
    let me = door.own_uid();
    let recorder = Recorder::default();
    let running = door.serve(&[me], &recorder);
    let mut client = door.client();
    client
        .write_all(&declared(
            u32::try_from(approverp::MAX_REQUEST_BODY + 1).unwrap(),
        ))
        .unwrap();
    let started = Instant::now();
    let (bytes, _) = read_all(&mut client);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "it waited for a body"
    );
    assert_eq!(
        answer_of(&bytes),
        Response::Refused(RefusalCode::MalformedRequest)
    );
    assert!(recorder.asked().is_empty());
    door.stop(running);
}

#[test]
fn a_slow_approver_holds_its_connection_for_a_bounded_time_and_reaches_nothing() {
    // Half a request, then silence: the connection is closed at its deadline,
    // unanswered, and the registry is asked nothing.
    let mut door = Door::new("slow");
    let me = door.own_uid();
    let recorder = Recorder::default();
    let running = door.serve(&[me], &recorder);
    let mut client = door.client();
    let frame = Request::List.encode_frame().unwrap();
    client.write_all(&frame[..7]).unwrap();
    let started = Instant::now();
    let (bytes, _) = read_all(&mut client);
    let waited = started.elapsed();
    assert!(
        bytes.is_empty(),
        "a request never completed is never answered"
    );
    assert!(
        waited >= REQUEST_DEADLINE.saturating_sub(Duration::from_millis(500)),
        "{waited:?}"
    );
    assert!(
        waited < REQUEST_DEADLINE + Duration::from_secs(5),
        "{waited:?}"
    );
    assert!(recorder.asked().is_empty());
    door.stop(running);
}

#[test]
fn past_the_connection_limit_an_approver_is_closed_unread() {
    // Four connections held in the registry; a fifth is closed with its
    // request unread and recorded as not admitted.
    let mut door = Door::new("limit");
    let me = door.own_uid();
    let hold = Arc::new(Barrier::new(MAX_APPROVER_CONNECTIONS + 1));
    let recorder = Recorder {
        answer: Some(Response::Refused(RefusalCode::UnknownRequest)),
        hold: Some(Arc::clone(&hold)),
        ..Recorder::default()
    };
    let running = door.serve(&[me], &recorder);
    let mut clients = Vec::new();
    for _ in 0..MAX_APPROVER_CONNECTIONS {
        let mut client = door.client();
        client
            .write_all(&Request::List.encode_frame().unwrap())
            .unwrap();
        clients.push(client);
    }
    hold.wait();
    // The endpoint may close it before its request lands (a broken pipe) or
    // after, with the request unread (a reset): either way nothing is read
    // or answered.
    let mut fifth = door.client();
    let wrote = fifth.write_all(&Request::List.encode_frame().unwrap());
    let (bytes, reset) = read_all(&mut fifth);
    assert!(bytes.is_empty(), "nothing answered");
    assert!(wrote.is_err() || reset, "closed with the request unread");
    eventually(|| {
        recorder
            .records()
            .contains(&TransportEvent::ApproverAuthenticated {
                uid: me,
                pid: Some(std::process::id()),
                admitted: false,
            })
    });
    hold.wait();
    for mut client in clients {
        let (bytes, _) = read_all(&mut client);
        assert_eq!(
            answer_of(&bytes),
            Response::Refused(RefusalCode::UnknownRequest)
        );
    }
    assert_eq!(recorder.asked().len(), MAX_APPROVER_CONNECTIONS);
    door.stop(running);
}

/// The endpoint module's code, without its comments or its tests.
fn production() -> String {
    let source = include_str!("approver.rs");
    let end = source
        .find(&["#[cfg(", "test)]"].concat())
        .unwrap_or(source.len());
    source
        .get(..end)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_endpoint_reaches_only_the_approver_protocol() {
    // TX065's successor, checked where a mutation review can see it: the
    // endpoint makes no subject, holder or caller context, reaches no DWKP
    // decoder or dispatch, no decision or revocation seam directly, no
    // approver attachment, and receives no descriptor; its one way into the
    // authority is the worker's approver job, with the principal made from
    // the kernel's uid.
    let code = production();
    assert!(code.contains("fn accept("), "the scan sees the module");
    let forbidden = [
        ["dis", "patch"].concat(),
        ["unix_", "uid"].concat(),
        ["Authenticated", "Subject"].concat(),
        ["Caller", "Context"].concat(),
        ["Lease", "Holder"].concat(),
        ["connection", "::"].concat(),
        ["dw", "kp::"].concat(),
        [".", "connect("].concat(),
        ["decide_", "approval"].concat(),
        ["revoke_", "approval"].concat(),
        ["attach_", "approver"].concat(),
        ["re", "cvmsg"].concat(),
        ["SCM_", "RIGHTS"].concat(),
        ["Recv", "Ancillary"].concat(),
        ["Owned", "Fd"].concat(),
        ["from_raw", "_fd"].concat(),
        ["Assurance", "::"].concat(),
    ];
    for token in &forbidden {
        assert!(
            !code.contains(token.as_str()),
            "the approver endpoint spells `{token}`"
        );
    }
    assert!(code.contains("ApproverPrincipal::kernel_reported(self.uid)"));
    // The kernel's judgement comes before the connection is served.
    let judged = code.find("authenticate(policy, credentials)").unwrap();
    let served = code.find("serve(stream, context").unwrap();
    assert!(judged < served, "a connection served before its judgement");
}
