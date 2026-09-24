//! Real-process fixtures for the M3e transport evidence.
//!
//! Everything here crosses the real boundary: the **released** `dwkd-authority`
//! binary (`CARGO_BIN_EXE_dwkd-authority`, the same `serve` code path an
//! operator runs — there is no test server), a real Unix-domain socket, the
//! kernel's peer credentials, `dwk-proto`'s real framing and decoder on both
//! sides, and the real `kernel.db` and `audit.log`. The test process is the
//! client, so the client is always a different process from the authority.
//!
//! Trusted setup — installing agent profiles and skills — happens **before**
//! the server starts, through the authority's in-process operator API, exactly
//! as an operator's own tooling would. No wire operation does it.
//!
//! Audit assertions read `audit.log` through `read_audit_log`, which verifies
//! the whole chain before it returns a record.

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::frame::{ContentType, FrameDecoder, encode};
use dwkd_authority::state::{AuditRecord, read_audit_log};

use super::state_support::{TempDir, balanced, ceiling, decode, id, install_fixtures, start};

/// The binary under test: the one `cargo build` produces and an operator runs.
pub(crate) const BIN: &str = env!("CARGO_BIN_EXE_dwkd-authority");

/// How long a test waits for anything that should be prompt.
pub(crate) const PROMPT: Duration = Duration::from_secs(10);

/// This process's effective uid, as the kernel will report it to the server.
pub(crate) fn own_uid() -> u32 {
    std::fs::metadata("/proc/self").expect("procfs").uid()
}

/// A state directory with the fixture profiles installed, and a socket path.
pub(crate) struct Fixture {
    pub(crate) dir: TempDir,
}

impl Fixture {
    /// A fresh directory; the authority state is prepared by trusted,
    /// in-process operator setup before any server runs.
    pub(crate) fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let clock = Arc::new(dwkd_authority::state::ManualClock::new(
            super::state_support::START_MS,
        ));
        let (mut authority, _) =
            start(&dir.state(), &balanced(), &clock, None).expect("the fixture store starts");
        install_fixtures(&mut authority);
        drop(authority);
        Self { dir }
    }

    pub(crate) fn state(&self) -> PathBuf {
        self.dir.state()
    }

    /// The IPC directory is created by the server, beside the state.
    pub(crate) fn socket(&self) -> PathBuf {
        self.dir.path().join("ipc").join("kernel.sock")
    }

    /// `serve` arguments admitting `uids`, plus `extra`.
    pub(crate) fn args_for(&self, uids: &[u32], extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "serve".to_owned(),
            "--state-dir".to_owned(),
            self.state().display().to_string(),
            "--socket".to_owned(),
            self.socket().display().to_string(),
            "--policy-shipped".to_owned(),
            "balanced".to_owned(),
            "--mode".to_owned(),
            "balanced".to_owned(),
        ];
        for uid in uids {
            args.push("--allow-uid".to_owned());
            args.push(uid.to_string());
        }
        for capability in ceiling() {
            args.push("--ceiling".to_owned());
            args.push(capability);
        }
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args
    }

    /// The development configuration: this process's own uid may connect.
    pub(crate) fn args(&self, extra: &[&str]) -> Vec<String> {
        let mut extra: Vec<&str> = extra.to_vec();
        extra.push("--allow-authority-uid");
        self.args_for(&[own_uid()], &extra)
    }

    /// Every verified record in the fixture's `audit.log`.
    pub(crate) fn audit(&self) -> Vec<AuditRecord> {
        read_audit_log(&self.state().join("audit.log")).expect("the audit chain verifies")
    }

    pub(crate) fn events(&self, event: &str) -> Vec<AuditRecord> {
        self.audit()
            .into_iter()
            .filter(|record| record.event() == event)
            .collect()
    }
}

/// A running `dwkd-authority serve`, killed when dropped.
pub(crate) struct Server {
    child: Child,
    pub(crate) pid: u32,
    stderr: Arc<Mutex<String>>,
    ready_line: String,
}

impl Server {
    /// Start the real binary and wait until it says it is serving.
    pub(crate) fn start(args: &[String]) -> Self {
        match Self::try_start(args) {
            Ok(server) => server,
            Err((status, stderr)) => panic!("the server did not start ({status:?}):\n{stderr}"),
        }
    }

    /// Start the binary through `wrapper` (a shell that sets limits and
    /// `exec`s it). Test harness only; the authority never runs a shell.
    pub(crate) fn start_wrapped(wrapper: &[&str], args: &[String]) -> Self {
        let mut command = Command::new(wrapper[0]);
        command.args(&wrapper[1..]).arg(BIN).args(args);
        match Self::spawn(command) {
            Ok(server) => server,
            Err((status, stderr)) => panic!("the server did not start ({status:?}):\n{stderr}"),
        }
    }

    /// Start, or report how it refused.
    pub(crate) fn try_start(args: &[String]) -> Result<Self, (Option<ExitStatus>, String)> {
        let mut command = Command::new(BIN);
        command.args(args);
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Result<Self, (Option<ExitStatus>, String)> {
        let mut child = super::state_support::spawn(
            command
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .expect("the binary spawns");
        let pid = child.id();
        let stdout = child.stdout.take().expect("stdout");
        let stderr_pipe = child.stderr.take().expect("stderr");
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
                let mut text = sink.lock().unwrap();
                text.push_str(&line);
                text.push('\n');
            }
        });
        let (lines, ready): (mpsc::Sender<String>, Receiver<String>) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = lines.send(line);
            }
        });
        let deadline = Instant::now() + PROMPT;
        loop {
            match ready.recv_timeout(Duration::from_millis(50)) {
                Ok(line) if line.contains("serving DWKP at") => {
                    return Ok(Self {
                        child,
                        pid,
                        stderr,
                        ready_line: line,
                    });
                }
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {}
            }
            if let Ok(Some(status)) = child.try_wait() {
                // Give the stderr reader a moment to drain.
                std::thread::sleep(Duration::from_millis(100));
                let text = stderr.lock().unwrap().clone();
                return Err((Some(status), text));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                let text = stderr.lock().unwrap().clone();
                return Err((None, format!("timed out waiting to serve\n{text}")));
            }
        }
    }

    pub(crate) fn ready_line(&self) -> &str {
        &self.ready_line
    }

    pub(crate) fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// `SIGKILL`: no destructor runs, and the socket file stays behind.
    pub(crate) fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Wait for the server to exit on its own.
    pub(crate) fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

/// What a read produced.
#[derive(Debug)]
pub(crate) enum Received {
    /// A complete message the real decoder accepted.
    Message(Box<DwkpMessage>),
    /// The server closed the connection, having sent nothing more.
    Closed,
    /// Nothing arrived in time.
    TimedOut,
}

impl Received {
    pub(crate) fn message(self) -> DwkpMessage {
        match self {
            Self::Message(message) => *message,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// One client connection: a process other than the authority.
pub(crate) struct Client {
    stream: UnixStream,
    decoder: FrameDecoder,
    pending: Vec<u8>,
}

impl Client {
    pub(crate) fn connect(path: &Path) -> Self {
        let stream = UnixStream::connect(path).expect("the socket accepts a connection");
        Self {
            stream,
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
        }
    }

    pub(crate) fn try_connect(path: &Path) -> std::io::Result<Self> {
        UnixStream::connect(path).map(|stream| Self {
            stream,
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
        })
    }

    pub(crate) fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Raw bytes, exactly as given.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes)
    }

    /// A frame around arbitrary body bytes.
    pub(crate) fn body(&mut self, body: &[u8]) -> std::io::Result<()> {
        self.raw(&encode(ContentType::Json, body).expect("a frame"))
    }

    /// A well-formed message, encoded by the real encoder.
    pub(crate) fn send(&mut self, message: &DwkpMessage) {
        let frame = message.to_frame().expect("the message encodes");
        self.raw(&frame).expect("the server reads the frame");
    }

    /// Read one response.
    pub(crate) fn recv(&mut self, timeout: Duration) -> Received {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.pending.is_empty() {
                let (consumed, frame) = self.decoder.feed(&self.pending).expect("a frame");
                self.pending.drain(..consumed);
                if let Some(frame) = frame {
                    return Received::Message(Box::new(
                        dwkp::decode_frame(&frame).expect("the server's response decodes"),
                    ));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Received::TimedOut;
            }
            self.stream.set_read_timeout(Some(deadline - now)).unwrap();
            let mut chunk = [0u8; 16 * 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    assert!(self.decoder.is_idle(), "the server closed mid-frame");
                    return Received::Closed;
                }
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::ConnectionReset => return Received::Closed,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Received::TimedOut;
                }
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    /// Send and read the answer.
    pub(crate) fn call(&mut self, message: &DwkpMessage) -> DwkpMessage {
        self.send(message);
        self.recv(PROMPT).message()
    }

    /// Complete the handshake, asserting it was accepted at version 1.
    pub(crate) fn handshake(&mut self) -> DwkpMessage {
        let request = handshake(1, 1, 1);
        let answer = self.call(&request);
        match &answer.body {
            DwkpBody::HandshakeAccepted(accepted) => assert_eq!(accepted.version.get(), 1),
            other => panic!("handshake not accepted: {other:?}"),
        }
        answer
    }
}

/// A handshake offering `min..=max`, message number `n`.
pub(crate) fn handshake(min: u16, max: u16, n: u64) -> DwkpMessage {
    decode(&handshake_json(min, max, n))
}

pub(crate) fn handshake_json(min: u16, max: u16, n: u64) -> String {
    format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.handshake","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","correlation_id":"{corr}","payload":{{"min_version":{min},"max_version":{max}}}}}"#,
        id = id("msg", 50_000 + n),
        corr = id("cor", 50_000 + n),
    )
}

/// One line of structured evidence for the M3 evaluations: which case ran,
/// where it was contained, and whether `audit.log` recorded it.
pub(crate) fn evidence(suite: &str, case: &str, layer: &str, contained: bool, audited: bool) {
    println!(
        "DWKP-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"layer\":\"{layer}\",\
         \"contained\":{contained},\"audited\":{audited},\"server\":\"{BIN}\"}}"
    );
}
