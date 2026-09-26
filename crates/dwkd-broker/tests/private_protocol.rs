//! The broker binary against a hostile authority-side peer (M4b, ADR-0043).
//!
//! This test process plays the authority: it connects to the released
//! `dwkd-broker`, reads its hello and sends authorisations with descriptors
//! over `SCM_RIGHTS` — honest ones, replayed ones, altered ones, ones with the
//! wrong descriptors or none, and frames that are not authorisations at all.
//! Locally the test and the broker share one uid, which the broker is told
//! with `--allow-shared-authority-uid`; the peer check itself is exercised by
//! naming an authority uid this process does not have.
//!
//! What the broker must do, whatever arrives: read nothing from a peer that
//! is not the authority, execute at most one authorisation per connection,
//! refuse before reading on any mismatch, and never hold a descriptor longer
//! than one exchange.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
#[cfg(target_os = "linux")]
use nix as _;
// Linux-only, like the operations that digest with it.
#[cfg(target_os = "linux")]
use sha2 as _;

#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_the_broker_does_not_serve() {
    // A path that is absolute on this platform, so the refusal is the
    // platform's and not the command line's.
    let socket = std::env::temp_dir().join("dw-broker.sock");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dwkd-broker"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .args(["--authority-uid", "1"])
        .output()
        .expect("runs");
    assert!(!socket.exists(), "nothing was created");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only on Linux"));
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::{
        self, Authorisation, BrokerHello, BrokerOutcome, BrokerRefusal, ChannelNonce, Common,
        ContentRevision, FsDeleteAuthorisation, FsMoveAuthorisation, FsPatchAuthorisation,
        FsReadAuthorisation, FsReclaimAuthorisation, FsStatAuthorisation, FsWriteAuthorisation,
        LeafName, MoveSide, OutcomeResult, PatchEdit, PatchEdits, StagingOperation,
    };
    use dwk_proto::frame::{ContentType, FrameDecoder};
    use dwk_proto::wire::id::InvocationId;
    use dwk_proto::wire::scalar::{ContentDigest, HexContent, PatchLength, ReadLimit, StatKind};
    use rustix::fs::{Mode, OFlags};
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);

    /// How long a peer waits for the broker: longer than the broker's own
    /// exchange deadline, so a test can wait out a stalled exchange.
    const PEER_WAIT: Duration = Duration::from_secs(20);

    /// Builds one malformed frame for a connection's channel.
    type Make = Box<dyn Fn(&ChannelNonce) -> Vec<u8>>;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn own_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    const SUITE: &str = "private-protocol";

    fn evidence(case: &str, outcome: &str) {
        println!(
            "BROKER-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\
             \"outcome\":\"{outcome}\",\"broker\":\"{BIN}\"}}"
        );
    }

    /// A private scratch directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("dwb-{tag}-{}-{nanos}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("ipc").join("broker.sock")
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The released broker, killed when dropped.
    struct Broker {
        child: Child,
        pid: u32,
        stderr: Arc<Mutex<String>>,
    }

    impl Broker {
        fn start(socket: &Path, authority_uid: u32, extra: &[&str]) -> Self {
            Self::try_start(socket, authority_uid, extra)
                .unwrap_or_else(|text| panic!("the broker did not start:\n{text}"))
        }

        fn shared(socket: &Path) -> Self {
            Self::start(socket, own_uid(), &["--allow-shared-authority-uid"])
        }

        fn try_start(socket: &Path, authority_uid: u32, extra: &[&str]) -> Result<Self, String> {
            Self::try_start_with(socket, authority_uid, extra, None, &[])
        }

        /// A shared-uid broker that aborts at crash point `point` (debug
        /// builds: `DWKD_BROKER_CRASH_AT`).
        fn crashing_at(socket: &Path, point: &str) -> Self {
            Self::try_start_with(
                socket,
                own_uid(),
                &["--allow-shared-authority-uid"],
                Some(point),
                &[],
            )
            .unwrap_or_else(|text| panic!("the broker did not start:\n{text}"))
        }

        /// A shared-uid broker whose own environment holds `variables`.
        fn with_environment(socket: &Path, variables: &[(&str, &str)]) -> Self {
            Self::try_start_with(
                socket,
                own_uid(),
                &["--allow-shared-authority-uid"],
                None,
                variables,
            )
            .unwrap_or_else(|text| panic!("the broker did not start:\n{text}"))
        }

        fn try_start_with(
            socket: &Path,
            authority_uid: u32,
            extra: &[&str],
            crash: Option<&str>,
            variables: &[(&str, &str)],
        ) -> Result<Self, String> {
            let mut command = Command::new(BIN);
            command.env_clear();
            if let Some(point) = crash {
                command.env("DWKD_BROKER_CRASH_AT", point);
            }
            for (name, value) in variables {
                command.env(name, value);
            }
            let mut child = command
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(authority_uid.to_string())
                .args(extra)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let stderr = Arc::new(Mutex::new(String::new()));
            let sink = Arc::clone(&stderr);
            let pipe = child.stderr.take().unwrap();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let mut text = sink.lock().unwrap();
                    text.push_str(&line);
                    text.push('\n');
                }
            });
            let stdout = child.stdout.take().unwrap();
            let (lines, ready) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    let _ = lines.send(line);
                }
            });
            let deadline = Instant::now() + PROMPT;
            loop {
                if let Ok(line) = ready.recv_timeout(Duration::from_millis(50))
                    && line.contains("serving the private broker channel at")
                {
                    return Ok(Self { child, pid, stderr });
                }
                if let Ok(Some(status)) = child.try_wait() {
                    std::thread::sleep(Duration::from_millis(100));
                    return Err(format!("{status:?}\n{}", stderr.lock().unwrap()));
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    return Err(format!("timed out\n{}", stderr.lock().unwrap()));
                }
            }
        }

        fn stderr(&self) -> String {
            self.stderr.lock().unwrap().clone()
        }

        fn count(&self, kind: &str) -> usize {
            self.stderr()
                .lines()
                .filter(|l| {
                    l.split_once("event=")
                        .is_some_and(|(_, e)| e.starts_with(kind))
                })
                .count()
        }

        fn wait_for(&self, kind: &str, n: usize) {
            let deadline = Instant::now() + PROMPT;
            while self.count(kind) < n {
                assert!(Instant::now() < deadline, "{n} {kind}:\n{}", self.stderr());
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn open_fds(&self) -> usize {
            std::fs::read_dir(format!("/proc/{}/fd", self.pid))
                .unwrap()
                .count()
        }

        /// Bytes the broker has read through `read`/`pread` since it started
        /// (`/proc/<pid>/io`, `rchar`). Its authorisation arrives by
        /// `recvmsg`, which this does not count, and it reads no other file
        /// while serving -- so across one exchange the change is exactly the
        /// content it read from the handed descriptor.
        fn rchar(&self) -> u64 {
            let io = std::fs::read_to_string(format!("/proc/{}/io", self.pid)).unwrap();
            io.lines()
                .find_map(|l| l.strip_prefix("rchar:"))
                .map(|v| v.trim().parse().unwrap())
                .expect("an rchar line")
        }

        /// Whether any of the broker's descriptors refers to `path`.
        fn holds(&self, path: &Path) -> bool {
            std::fs::read_dir(format!("/proc/{}/fd", self.pid))
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| std::fs::read_link(entry.path()).is_ok_and(|to| to == path))
        }

        /// Wait until the broker holds exactly `n` descriptors again.
        fn settle_fds(&self, n: usize) {
            let deadline = Instant::now() + PROMPT;
            while self.open_fds() != n {
                assert!(
                    Instant::now() < deadline,
                    "the broker holds {} descriptors, not {n}",
                    self.open_fds()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn kill(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for Broker {
        fn drop(&mut self) {
            self.kill();
        }
    }

    /// The authority's end of one connection, as this test plays it.
    struct Peer {
        stream: UnixStream,
        decoder: FrameDecoder,
        pending: Vec<u8>,
    }

    impl Peer {
        fn connect(socket: &Path) -> Self {
            let stream = UnixStream::connect(socket).unwrap();
            stream.set_read_timeout(Some(PEER_WAIT)).unwrap();
            Self {
                stream,
                decoder: FrameDecoder::new(),
                pending: Vec::new(),
            }
        }

        /// One frame body, or `None` when the broker closed.
        fn frame(&mut self) -> Option<Vec<u8>> {
            loop {
                if !self.pending.is_empty() {
                    let (used, frame) = self.decoder.feed(&self.pending).unwrap();
                    self.pending.drain(..used);
                    if let Some(frame) = frame {
                        return Some(frame.body);
                    }
                }
                let mut chunk = [0u8; 64 * 1024];
                match self.stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                }
            }
        }

        fn hello(&mut self) -> BrokerHello {
            BrokerHello::decode_frame_body(&self.frame().expect("a hello")).unwrap()
        }

        /// `bytes` with `fds` attached to the first byte.
        fn try_send(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<()> {
            let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(32))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if !fds.is_empty() {
                assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
            }
            let sent = rustix::net::sendmsg(
                &self.stream,
                &[IoSlice::new(bytes)],
                &mut control,
                SendFlags::NOSIGNAL,
            )?;
            self.stream.write_all(&bytes[sent..])
        }

        fn send(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
            self.try_send(bytes, fds).unwrap();
        }

        fn outcome(&mut self) -> Option<BrokerOutcome> {
            self.frame()
                .map(|body| BrokerOutcome::decode_frame_body(&body).unwrap())
        }

        /// Whether the broker closed without another frame.
        fn closed(&mut self) -> bool {
            self.frame().is_none()
        }
    }

    fn invocation(n: u8) -> InvocationId {
        InvocationId::parse(&format!("inv_01M24BB8G3E0A851TRWE3M8F{:02}", n % 90 + 10)).unwrap()
    }

    fn open(path: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(path).unwrap())
    }

    fn identity(path: &Path) -> (u64, u64) {
        let meta = std::fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    fn authorisation(
        channel: &ChannelNonce,
        n: u8,
        (device, inode): (u64, u64),
        max: u32,
    ) -> Vec<u8> {
        let a = FsReadAuthorisation::new(
            channel.clone(),
            invocation(n),
            device,
            inode,
            ReadLimit::new(max).unwrap(),
        );
        brokerp::encode_frame(&a).unwrap()
    }

    /// An `fs.write` authorisation's body text: `leaf` in the scratch
    /// directory's parent identity, replacing `target` or creating.
    fn write(channel: &ChannelNonce, leaf: &str, target: Option<(u64, u64)>) -> String {
        let a = FsWriteAuthorisation::new(
            Common::new(channel.clone(), invocation(1)),
            (1, 2),
            LeafName::new(leaf).unwrap(),
            target,
            HexContent::from_bytes(b"x").unwrap(),
        );
        String::from_utf8(brokerp::encode_frame(&a).unwrap()[5..].to_vec()).unwrap()
    }

    fn refused(outcome: Option<BrokerOutcome>) -> BrokerRefusal {
        match outcome.expect("an outcome").result() {
            OutcomeResult::Refused(why) => why,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    fn done(outcome: Option<BrokerOutcome>) -> (Vec<u8>, bool) {
        match outcome.expect("an outcome").result() {
            OutcomeResult::Done(done) => {
                let read = done.fs_read.expect("an fs.read result");
                (read.content.to_bytes(), read.eof_observed)
            }
            other => panic!("not a result: {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_is_not_the_authority_is_closed_before_a_byte_either_way() {
        let scratch = Scratch::new("peer");
        let not_us = own_uid().wrapping_add(4242);
        let broker = Broker::start(&scratch.socket(), not_us, &[]);
        let file = scratch.file("f", b"secret");
        for _ in 0..3 {
            let mut peer = Peer::connect(&scratch.socket());
            let channel = ChannelNonce::new("0".repeat(32)).unwrap();
            let fd = open(&file);
            // Whatever we send, nothing comes back: not even a hello.
            let _ = peer.try_send(
                &authorisation(&channel, 1, identity(&file), 6),
                &[fd.as_fd()],
            );
            assert!(peer.closed(), "the broker said something to a stranger");
        }
        broker.wait_for("peer_refused", 3);
        assert_eq!(broker.count("connection"), 0);
        assert_eq!(broker.count("executed"), 0);
        assert!(
            broker
                .stderr()
                .contains(&format!("peer_refused peer_uid={}", own_uid()))
        );
        evidence("non-authority-peer", "closed-unread");
    }

    #[test]
    fn an_honest_exchange_reads_exactly_the_descriptor_it_was_given() {
        let scratch = Scratch::new("honest");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", b"0123456789");
        let mut peer = Peer::connect(&scratch.socket());
        let hello = peer.hello();
        assert_eq!(hello.channel.as_str().len(), 32);
        let fd = open(&file);
        peer.send(
            &authorisation(&hello.channel, 1, identity(&file), 4),
            &[fd.as_fd()],
        );
        let outcome = peer.outcome();
        let o = outcome.clone().unwrap();
        assert_eq!(o.channel, hello.channel);
        assert_eq!(o.invocation_id, invocation(1));
        assert_eq!(done(outcome), (b"0123".to_vec(), false));
        // Then the connection ends: one authorisation per connection.
        assert!(peer.closed());
        broker.wait_for("executed", 1);
        evidence("honest-exchange", "read-bounded");
    }

    #[test]
    fn an_authorisation_is_single_use() {
        let scratch = Scratch::new("single");
        let mut broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", b"payload");
        let other = scratch.file("g", b"other");

        // First use, on its own connection.
        let mut first = Peer::connect(&scratch.socket());
        let hello = first.hello();
        let spent = authorisation(&hello.channel, 1, identity(&file), 7);
        first.send(&spent, &[open(&file).as_fd()]);
        assert_eq!(done(first.outcome()).0, b"payload");
        // A second authorisation on the same connection is never read.
        let _ = first.try_send(&spent, &[open(&file).as_fd()]);
        assert!(first.closed());

        // Replayed on another connection: another channel.
        let mut second = Peer::connect(&scratch.socket());
        let fresh = second.hello();
        assert_ne!(fresh.channel, hello.channel);
        second.send(&spent, &[open(&file).as_fd()]);
        assert_eq!(refused(second.outcome()), BrokerRefusal::ChannelMismatch);

        // Changed bytes: a channel one character off is another channel.
        let mut third = Peer::connect(&scratch.socket());
        let h3 = third.hello();
        let mut altered = h3.channel.as_str().to_owned();
        let last = if altered.ends_with('0') { "1" } else { "0" };
        altered.replace_range(31.., last);
        let altered = ChannelNonce::new(altered).unwrap();
        third.send(
            &authorisation(&altered, 3, identity(&file), 7),
            &[open(&file).as_fd()],
        );
        assert_eq!(refused(third.outcome()), BrokerRefusal::ChannelMismatch);

        // Another descriptor than the authorised object.
        let mut fourth = Peer::connect(&scratch.socket());
        let h4 = fourth.hello();
        fourth.send(
            &authorisation(&h4.channel, 4, identity(&file), 7),
            &[open(&other).as_fd()],
        );
        assert_eq!(refused(fourth.outcome()), BrokerRefusal::IdentityMismatch);

        // After a restart: the old broker's channel does not exist.
        let mut fifth = Peer::connect(&scratch.socket());
        let h5 = fifth.hello();
        let before_restart = authorisation(&h5.channel, 5, identity(&file), 7);
        drop(fifth);
        broker.kill();
        let broker = Broker::shared(&scratch.socket());
        let mut sixth = Peer::connect(&scratch.socket());
        let h6 = sixth.hello();
        assert_ne!(
            h6.channel.as_str()[..16],
            h5.channel.as_str()[..16],
            "a new process prefix"
        );
        sixth.send(&before_restart, &[open(&file).as_fd()]);
        assert_eq!(refused(sixth.outcome()), BrokerRefusal::ChannelMismatch);
        assert_eq!(broker.count("executed"), 0);
        evidence("replay-other-connection", "CHANNEL_MISMATCH");
        evidence("replay-changed-bytes", "CHANNEL_MISMATCH");
        evidence("replay-other-descriptor", "IDENTITY_MISMATCH");
        evidence("replay-after-restart", "CHANNEL_MISMATCH");
        evidence("second-on-same-connection", "never-read");
    }

    #[test]
    fn a_read_bounded_at_n_reads_n_bytes_of_the_file_and_not_one_more() {
        // Measured from outside the broker: the kernel's count of bytes the
        // broker process read. A file larger than every bound, so any read
        // past N would have something to read.
        let scratch = Scratch::new("bound");
        let broker = Broker::shared(&scratch.socket());
        let contents: Vec<u8> = (0..300 * 1024u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let file = scratch.file("f", &contents);
        let id = identity(&file);
        for (k, n) in [1u32, 8, 4096, 262_144].into_iter().enumerate() {
            let before = broker.rchar();
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            let tag = u8::try_from(k).unwrap();
            peer.send(
                &authorisation(&hello.channel, tag, id, n),
                &[open(&file).as_fd()],
            );
            let (bytes, eof_observed) = done(peer.outcome());
            let read = broker.rchar() - before;
            assert_eq!(read, u64::from(n), "N={n}: the broker read {read} bytes");
            assert_eq!(bytes, contents[..usize::try_from(n).unwrap()]);
            assert!(
                !eof_observed,
                "N={n}: the end was not observed, and not probed for"
            );
            evidence(&format!("read-bound-{n}"), &format!("read-{read}-of-{n}"));
        }
        // A file shorter than N: the short read is the observed end.
        let short = scratch.file("s", b"abc");
        let before = broker.rchar();
        let mut peer = Peer::connect(&scratch.socket());
        let hello = peer.hello();
        peer.send(
            &authorisation(&hello.channel, 9, identity(&short), 8),
            &[open(&short).as_fd()],
        );
        assert_eq!(done(peer.outcome()), (b"abc".to_vec(), true));
        assert_eq!(broker.rchar() - before, 3);
        evidence("read-bound-exact", "never-n-plus-one");
    }

    #[test]
    fn a_descriptor_count_other_than_one_is_refused_unread_and_every_descriptor_closed() {
        let scratch = Scratch::new("count");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", &vec![5u8; 64 * 1024]);
        let id = identity(&file);
        // The first valid exchange settles whatever the broker allocates once.
        let mut warm = Peer::connect(&scratch.socket());
        let hello = warm.hello();
        warm.send(
            &authorisation(&hello.channel, 1, id, 4),
            &[open(&file).as_fd()],
        );
        assert_eq!(done(warm.outcome()).0, [5, 5, 5, 5]);
        drop(warm);
        std::thread::sleep(Duration::from_millis(100));
        let baseline = broker.open_fds();
        for count in [0usize, 2, 3] {
            let fds: Vec<OwnedFd> = (0..count).map(|_| open(&file)).collect();
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(std::os::fd::AsFd::as_fd).collect();
            let before = broker.rchar();
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            peer.send(&authorisation(&hello.channel, 2, id, 4096), &borrowed);
            assert_eq!(
                refused(peer.outcome()),
                BrokerRefusal::DescriptorCount,
                "{count} descriptors"
            );
            assert!(
                peer.closed(),
                "{count}: one outcome, then the connection ends"
            );
            assert_eq!(
                broker.rchar() - before,
                0,
                "{count} descriptors: not one byte of content was read"
            );
            drop(fds);
            broker.settle_fds(baseline);
            assert!(
                !broker.holds(&file),
                "{count}: the broker still holds a descriptor for the file"
            );
            // And the next valid invocation is served normally.
            let before = broker.rchar();
            let mut next = Peer::connect(&scratch.socket());
            let hello = next.hello();
            next.send(
                &authorisation(&hello.channel, 3, id, 4),
                &[open(&file).as_fd()],
            );
            assert_eq!(done(next.outcome()).0, [5, 5, 5, 5]);
            assert_eq!(broker.rchar() - before, 4);
            broker.settle_fds(baseline);
            evidence(
                &format!("descriptor-count-{count}"),
                "DESCRIPTOR_COUNT-unread-closed",
            );
        }
        // The broker logs before it answers, but its stderr reaches this
        // process through a reader thread: wait for the lines, then count
        // them exactly.
        broker.wait_for("executed", 4);
        assert_eq!(broker.count("executed"), 4);
        evidence("descriptor-count-refused-closed", "exactly-one-or-nothing");
    }

    #[test]
    fn exactly_one_descriptor_of_the_right_kind_or_nothing_is_read() {
        let scratch = Scratch::new("kinds");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", b"content");
        let id = identity(&file);
        let exchange = |fds: &[BorrowedFd<'_>], who: (u64, u64)| {
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            peer.send(&authorisation(&hello.channel, 1, who, 7), fds);
            refused(peer.outcome())
        };
        assert_eq!(exchange(&[], id), BrokerRefusal::DescriptorCount);
        let (a, b) = (open(&file), open(&file));
        assert_eq!(
            exchange(&[a.as_fd(), b.as_fd()], id),
            BrokerRefusal::DescriptorCount
        );
        let many: Vec<OwnedFd> = (0..20).map(|_| open(&file)).collect();
        let many: Vec<BorrowedFd<'_>> = many.iter().map(std::os::fd::AsFd::as_fd).collect();
        assert_eq!(exchange(&many, id), BrokerRefusal::DescriptorCount);

        let write_only =
            OwnedFd::from(std::fs::OpenOptions::new().write(true).open(&file).unwrap());
        assert_eq!(
            exchange(&[write_only.as_fd()], id),
            BrokerRefusal::DescriptorNotReadable
        );
        let read_write = OwnedFd::from(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file)
                .unwrap(),
        );
        assert_eq!(
            exchange(&[read_write.as_fd()], id),
            BrokerRefusal::DescriptorNotReadable
        );
        let path_only =
            rustix::fs::open(&file, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert_eq!(
            exchange(&[path_only.as_fd()], id),
            BrokerRefusal::DescriptorNotReadable
        );
        let dir = open(&scratch.0);
        assert_eq!(
            exchange(&[dir.as_fd()], identity(&scratch.0)),
            BrokerRefusal::DescriptorNotRegular
        );
        let (reader, _writer) = std::io::pipe().unwrap();
        assert_eq!(
            exchange(&[reader.as_fd()], id),
            BrokerRefusal::DescriptorNotRegular
        );

        // Descriptors split over two messages inside one frame.
        let mut peer = Peer::connect(&scratch.socket());
        let hello = peer.hello();
        let frame = authorisation(&hello.channel, 2, id, 7);
        let (x, y) = (open(&file), open(&file));
        peer.send(&frame[..10], &[x.as_fd()]);
        peer.send(&frame[10..], &[y.as_fd()]);
        assert_eq!(refused(peer.outcome()), BrokerRefusal::DescriptorCount);

        assert_eq!(broker.count("executed"), 0);
        evidence("descriptor-count-and-kind", "refused-before-read");
    }

    /// One line of M4c evidence for `make filesystem-operations-evidence`.
    fn fsop(case: &str, outcome: &str) {
        println!(
            "FSOP-EVIDENCE {{\"suite\":\"private-protocol\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
    }

    #[test]
    fn a_v2_descriptor_of_the_wrong_role_changes_nothing() {
        let scratch = Scratch::new("v2-roles");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", b"content");
        let other = scratch.file("g", b"other");
        let dir = scratch.0.clone();
        let elsewhere = scratch.0.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let leaf = || LeafName::new("f").unwrap();
        let common = |c: &ChannelNonce| Common::new(c.clone(), invocation(1));
        let body = |a: &Authorisation| a.encode_frame().unwrap();
        let write = |c: &ChannelNonce| {
            body(&Authorisation::FsWrite(FsWriteAuthorisation::new(
                common(c),
                identity(&dir),
                leaf(),
                Some(identity(&file)),
                HexContent::from_bytes(b"CHANGED").unwrap(),
            )))
        };
        let reclaim = |c: &ChannelNonce| {
            body(&Authorisation::FsReclaim(FsReclaimAuthorisation::new(
                common(c),
                identity(&dir),
                leaf(),
                StagingOperation::Delete,
                Some(identity(&file)),
            )))
        };
        let exchange = |make: &dyn Fn(&ChannelNonce) -> Vec<u8>, fds: &[BorrowedFd<'_>]| {
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            peer.send(&make(&hello.channel), fds);
            refused(peer.outcome())
        };
        let path_dir =
            rustix::fs::open(&dir, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let (d, f) = (open(&dir), open(&file));
        let cases: Vec<(&str, BrokerRefusal)> = vec![
            ("write-given-a-file", exchange(&write, &[f.as_fd()])),
            (
                "write-given-an-o-path-directory",
                exchange(&write, &[path_dir.as_fd()]),
            ),
            (
                "write-given-another-directory",
                exchange(&write, &[open(&elsewhere).as_fd()]),
            ),
            ("write-given-two", exchange(&write, &[d.as_fd(), d.as_fd()])),
            (
                "move-given-one",
                exchange(
                    &|c: &ChannelNonce| {
                        body(&Authorisation::FsMove(FsMoveAuthorisation::new(
                            common(c),
                            MoveSide {
                                parent: identity(&dir),
                                leaf: leaf(),
                            },
                            identity(&file),
                            MoveSide {
                                parent: identity(&dir),
                                leaf: LeafName::new("moved").unwrap(),
                            },
                        )))
                    },
                    &[d.as_fd()],
                ),
            ),
            (
                "stat-given-a-readable-descriptor",
                exchange(
                    &|c: &ChannelNonce| {
                        let (device, inode) = identity(&file);
                        body(&Authorisation::FsStat(FsStatAuthorisation::new(
                            common(c),
                            device,
                            inode,
                        )))
                    },
                    &[f.as_fd()],
                ),
            ),
            (
                "patch-given-its-descriptors-reversed",
                exchange(
                    &|c: &ChannelNonce| {
                        let revision = |fill: &str| ContentRevision {
                            sha256: ContentDigest::new(fill.repeat(64)).unwrap(),
                            length: PatchLength::new(7).unwrap(),
                        };
                        let edits = PatchEdits::new(vec![PatchEdit {
                            offset: PatchLength::new(0).unwrap(),
                            delete: PatchLength::new(1).unwrap(),
                            insert: HexContent::from_bytes(b"C").unwrap(),
                        }])
                        .unwrap();
                        body(&Authorisation::FsPatch(FsPatchAuthorisation::new(
                            common(c),
                            identity(&dir),
                            leaf(),
                            identity(&file),
                            (revision("a"), revision("b"), edits),
                        )))
                    },
                    &[f.as_fd(), d.as_fd()],
                ),
            ),
            (
                "delete-naming-another-object",
                exchange(
                    &|c: &ChannelNonce| {
                        body(&Authorisation::FsDelete(FsDeleteAuthorisation::new(
                            common(c),
                            identity(&dir),
                            leaf(),
                            identity(&other),
                            StatKind::RegularFile,
                        )))
                    },
                    &[d.as_fd()],
                ),
            ),
            ("reclaim-given-a-file", exchange(&reclaim, &[f.as_fd()])),
            (
                "reclaim-given-two",
                exchange(&reclaim, &[d.as_fd(), d.as_fd()]),
            ),
            (
                "reclaim-given-another-directory",
                exchange(&reclaim, &[open(&elsewhere).as_fd()]),
            ),
        ];
        let expected = [
            BrokerRefusal::DescriptorNotDirectory,
            BrokerRefusal::DescriptorNotReadable,
            BrokerRefusal::IdentityMismatch,
            BrokerRefusal::DescriptorCount,
            BrokerRefusal::DescriptorCount,
            BrokerRefusal::DescriptorNotPath,
            BrokerRefusal::DescriptorNotDirectory,
            BrokerRefusal::ObjectChanged,
            BrokerRefusal::DescriptorNotDirectory,
            BrokerRefusal::DescriptorCount,
            BrokerRefusal::IdentityMismatch,
        ];
        assert_eq!(cases.len(), expected.len());
        for ((case, got), want) in cases.iter().zip(expected) {
            assert_eq!(*got, want, "{case}");
            fsop(&format!("v2-{case}"), want.as_str());
        }
        // Nothing changed, nothing was left behind, nothing executed.
        assert_eq!(std::fs::read(&file).unwrap(), b"content");
        assert_eq!(std::fs::read(&other).unwrap(), b"other");
        let staged = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".dwkd-"))
            .count();
        assert_eq!(staged, 0);
        assert_eq!(broker.count("executed"), 0);
        // And the honest authorisation still performs.
        let mut peer = Peer::connect(&scratch.socket());
        let hello = peer.hello();
        peer.send(&write(&hello.channel), &[open(&dir).as_fd()]);
        assert!(matches!(
            peer.outcome().unwrap().result(),
            OutcomeResult::Done(_)
        ));
        assert_eq!(std::fs::read(&file).unwrap(), b"CHANGED");
        fsop("v2-descriptor-roles", "refused-before-any-change");
    }

    #[test]
    fn a_frame_that_is_not_one_strict_authorisation_is_closed_unanswered() {
        let scratch = Scratch::new("malformed");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", b"content");
        let id = identity(&file);
        let json =
            |text: &str| dwk_proto::frame::encode(ContentType::Json, text.as_bytes()).unwrap();
        let cases: Vec<(&str, Make)> = vec![
            (
                // One byte over one DWKP frame, the largest authorisation.
                "oversized-header",
                Box::new(|_| vec![0x00, 0x10, 0x00, 0x01, 0x01]),
            ),
            (
                "huge-header",
                Box::new(|_| vec![0x7f, 0xff, 0xff, 0xff, 0x01]),
            ),
            ("empty-frame", Box::new(|_| vec![0, 0, 0, 0, 0x01])),
            (
                "content-type",
                Box::new(|_| vec![0, 0, 0, 2, 0x02, b'{', b'}']),
            ),
            ("not-json", Box::new(move |_| json("{nope"))),
            (
                "a-hello",
                Box::new(|c| brokerp::encode_frame(&BrokerHello::new(c.clone())).unwrap()),
            ),
            (
                "unknown-member",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replacen('{', r#"{"path":"/workspace/f","#, 1))
                }),
            ),
            (
                "two-descriptors-declared",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replace(r#""descriptors":1"#, r#""descriptors":2"#))
                }),
            ),
            (
                "zero-bytes",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replace(r#""max_bytes":7"#, r#""max_bytes":0"#))
                }),
            ),
            (
                "above-the-bound",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replace(r#""max_bytes":7"#, r#""max_bytes":262145"#))
                }),
            ),
            (
                "duplicate-key",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replacen('{', r#"{"max_bytes":7,"#, 1))
                }),
            ),
            (
                "protocol-one",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    assert!(text.contains(r#""protocol":3"#));
                    json(&text.replace(r#""protocol":3"#, r#""protocol":1"#))
                }),
            ),
            (
                // M4c's protocol, which M4d's broker no longer speaks.
                "protocol-two",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replace(r#""protocol":3"#, r#""protocol":2"#))
                }),
            ),
            (
                "an-outcome",
                Box::new(|c| {
                    let outcome = BrokerOutcome::new(
                        c.clone(),
                        invocation(1),
                        OutcomeResult::Refused(BrokerRefusal::IoError),
                    );
                    brokerp::encode_frame(&outcome).unwrap()
                }),
            ),
            (
                "unknown-kind",
                Box::new(move |c| {
                    let a = authorisation(c, 1, id, 7);
                    let text = String::from_utf8(a[5..].to_vec()).unwrap();
                    json(&text.replace("broker.fs_read", "broker.fs_mkdir"))
                }),
            ),
            (
                "stat-with-two-descriptors",
                Box::new(move |c| {
                    let a =
                        FsStatAuthorisation::new(Common::new(c.clone(), invocation(1)), id.0, id.1);
                    let text = String::from_utf8(brokerp::encode_frame(&a).unwrap()[5..].to_vec())
                        .unwrap();
                    json(&text.replace(r#""descriptors":1"#, r#""descriptors":2"#))
                }),
            ),
            (
                "write-vacant-naming-a-target",
                Box::new(move |c| {
                    let a = write(c, "f", Some(id));
                    json(&a.replace(r#""object":"EXISTING""#, r#""object":"VACANT""#))
                }),
            ),
            (
                "write-existing-naming-none",
                Box::new(move |c| {
                    let a = write(c, "f", None);
                    json(&a.replace(r#""object":"VACANT""#, r#""object":"EXISTING""#))
                }),
            ),
            (
                "leaf-dotdot",
                Box::new(move |c| {
                    json(&write(c, "PLACEHOLDER", None).replace("PLACEHOLDER", ".."))
                }),
            ),
            (
                "leaf-dot",
                Box::new(move |c| json(&write(c, "PLACEHOLDER", None).replace("PLACEHOLDER", "."))),
            ),
            (
                "leaf-slash",
                Box::new(move |c| {
                    json(&write(c, "PLACEHOLDER", None).replace("PLACEHOLDER", "a/b"))
                }),
            ),
            (
                "leaf-absolute",
                Box::new(move |c| {
                    json(&write(c, "PLACEHOLDER", None).replace("PLACEHOLDER", "/etc"))
                }),
            ),
            (
                "leaf-empty",
                Box::new(move |c| json(&write(c, "PLACEHOLDER", None).replace("PLACEHOLDER", ""))),
            ),
            (
                "a-path-member",
                Box::new(move |c| {
                    json(&write(c, "f", None).replacen('{', r#"{"path":"/workspace/f","#, 1))
                }),
            ),
        ];
        let before = broker.open_fds();
        for (case, make) in &cases {
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            let fd = open(&file);
            let _ = peer.try_send(&make(&hello.channel), &[fd.as_fd()]);
            assert!(peer.closed(), "{case}: the broker answered");
        }
        broker.wait_for("malformed", cases.len());
        assert_eq!(broker.count("executed"), 0);
        assert_eq!(broker.count("refused"), 0);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            broker.open_fds(),
            before,
            "no descriptor outlived its exchange"
        );
        evidence("malformed-authorisations", "closed-unanswered");
    }

    #[test]
    fn descriptors_do_not_accumulate_and_a_stalled_peer_is_cut_off() {
        let scratch = Scratch::new("leak");
        let broker = Broker::shared(&scratch.socket());
        let file = scratch.file("f", &vec![7u8; 300 * 1024]);
        let id = identity(&file);
        let baseline = broker.open_fds();
        for n in 0..40u8 {
            let mut peer = Peer::connect(&scratch.socket());
            let hello = peer.hello();
            let fds: Vec<OwnedFd> = (0..(n % 4)).map(|_| open(&file)).collect();
            let fds: Vec<BorrowedFd<'_>> = fds.iter().map(std::os::fd::AsFd::as_fd).collect();
            peer.send(&authorisation(&hello.channel, n, id, 262_144), &fds);
            let outcome = peer.outcome().unwrap();
            if n % 4 == 1 {
                let OutcomeResult::Done(done) = outcome.result() else {
                    panic!("one descriptor is read")
                };
                let read = done.fs_read.expect("an fs.read result");
                assert_eq!(read.content.byte_len(), 262_144);
                assert!(!read.eof_observed);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(broker.open_fds(), baseline, "{}", broker.stderr());

        // A peer that takes the hello and says nothing holds the broker for
        // at most its deadline; the next exchange is then served.
        let started = Instant::now();
        let mut stalled = Peer::connect(&scratch.socket());
        let _ = stalled.hello();
        let mut next = Peer::connect(&scratch.socket());
        let hello = next.hello();
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(9), "{waited:?}");
        assert!(waited < Duration::from_secs(15), "{waited:?}");
        next.send(
            &authorisation(&hello.channel, 99, id, 1),
            &[open(&file).as_fd()],
        );
        assert_eq!(done(next.outcome()).0, [7]);
        broker.wait_for("malformed reason=timeout", 1);
        evidence("descriptor-pressure", "no-leak");
        evidence("stalled-peer", "cut-off-at-deadline");
    }

    #[test]
    fn the_broker_refuses_to_serve_where_it_cannot_be_trusted() {
        let scratch = Scratch::new("refuse");
        // The authority's own uid, unacknowledged.
        let shared = Broker::try_start(&scratch.socket(), own_uid(), &[]);
        assert!(shared.is_err_and(|text| text.contains("--allow-shared-authority-uid")));
        // A socket directory others can write.
        let dir = scratch.0.join("open");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let open_dir = Broker::try_start(&dir.join("b.sock"), own_uid().wrapping_add(1), &[]);
        assert!(open_dir.is_err_and(|text| text.contains("write bit")));
        // A second broker on a live one's name.
        let _first = Broker::shared(&scratch.socket());
        let second = Broker::try_start(
            &scratch.socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        assert!(second.is_err_and(|text| text.contains("another broker")));
        // No TCP, no other listener: the command line has no way to ask.
        let tcp = Command::new(BIN)
            .args(["serve", "--listen-tcp", "127.0.0.1:1"])
            .output()
            .unwrap();
        assert_eq!(tcp.status.code(), Some(2));
        evidence("refuses-untrusted-configuration", "refused");
    }

    // ---- M4d: process execution (ADR-0045) ----------------------------------

    mod process {
        use std::os::fd::AsFd as _;
        use std::path::{Path, PathBuf};
        use std::time::{Duration, Instant};

        use dwk_proto::brokerp::{
            self, BrokerGeneration, BrokerRefusal, ChannelNonce, Common, ExecEnvironment,
            OutcomeResult, ProcessArgs, ProcessKillAuthorisation, ProcessSpec,
            ProcessStartAuthorisation, ProcessStatusAuthorisation, StreamLimit,
        };
        use dwk_proto::wire::id::ProcessId;
        use dwk_proto::wire::scalar::{
            ContentDigest, HostPath, KillOutcome, ProcessArg, ProcessState,
        };
        use sha2::{Digest as _, Sha256};

        use super::{Broker, Peer, Scratch, identity, invocation, open};

        const PYTHON: &str = "/usr/bin/python3";

        fn proc_evidence(case: &str, outcome: &str) {
            println!(
                "PROC-EVIDENCE {{\"suite\":\"broker-private-protocol\",\"case\":\"{case}\",\
                 \"outcome\":\"{outcome}\",\"count\":1}}"
            );
        }

        fn process_id(n: u64) -> ProcessId {
            let ts = u128::from(1_758_000_000_000u64);
            let n = u128::from(n);
            ProcessId::from_uuid((ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | n)
                .unwrap()
        }

        /// A marker no other process on the machine has in its argv.
        fn marker(tag: &str) -> String {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            format!("dwp-marker-{tag}-{}-{nanos}", std::process::id())
        }

        /// Every live process whose argv holds `marker`.
        fn running(marker: &str) -> Vec<u32> {
            std::fs::read_dir("/proc")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .filter(|pid| {
                    std::fs::read(format!("/proc/{pid}/cmdline"))
                        .is_ok_and(|cmd| cmd.windows(marker.len()).any(|w| w == marker.as_bytes()))
                })
                .collect()
        }

        fn wait_gone(marker: &str) {
            let until = Instant::now() + Duration::from_secs(10);
            while !running(marker).is_empty() {
                assert!(Instant::now() < until, "{marker} still runs");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn python_bytes() -> (PathBuf, String) {
            let path = std::fs::canonicalize(PYTHON).unwrap();
            let digest = Sha256::digest(std::fs::read(&path).unwrap())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            (path, digest)
        }

        /// A launch of python with `args`, working in `cwd`.
        fn start_frame(channel: &ChannelNonce, n: u64, cwd: &Path, args: &[&str]) -> Vec<u8> {
            let (path, digest) = python_bytes();
            let args: Vec<ProcessArg> = args
                .iter()
                .map(|a| ProcessArg::new((*a).to_owned()).unwrap())
                .collect();
            let a = ProcessStartAuthorisation::new(
                Common::new(channel.clone(), invocation(1)),
                ProcessSpec {
                    process_id: process_id(n),
                    executable: identity(&path),
                    executable_sha256: ContentDigest::new(digest).unwrap(),
                    cwd: identity(cwd),
                    argv0: HostPath::new(path.display().to_string()).unwrap(),
                    args: ProcessArgs::new(args).unwrap(),
                    environment: ExecEnvironment::Base,
                    stream_limit: StreamLimit::new(4096).unwrap(),
                },
            );
            brokerp::encode_frame(&a).unwrap()
        }

        fn status_frame(channel: &ChannelNonce, n: u64, generation: &BrokerGeneration) -> Vec<u8> {
            let a = ProcessStatusAuthorisation::new(
                Common::new(channel.clone(), invocation(2)),
                process_id(n),
                generation.clone(),
            );
            brokerp::encode_frame(&a).unwrap()
        }

        fn kill_frame(channel: &ChannelNonce, n: u64, generation: &BrokerGeneration) -> Vec<u8> {
            let a = ProcessKillAuthorisation::new(
                Common::new(channel.clone(), invocation(3)),
                process_id(n),
                generation.clone(),
            );
            brokerp::encode_frame(&a).unwrap()
        }

        /// Launch: the generation, or the refusal.
        fn launch(
            broker_socket: &Path,
            n: u64,
            cwd: &Path,
            args: &[&str],
        ) -> Result<BrokerGeneration, BrokerRefusal> {
            let mut peer = Peer::connect(broker_socket);
            let hello = peer.hello();
            let (path, _) = python_bytes();
            let (exe, dir) = (open(&path), open(cwd));
            peer.send(
                &start_frame(&hello.channel, n, cwd, args),
                &[exe.as_fd(), dir.as_fd()],
            );
            match peer.outcome().expect("an outcome").result() {
                OutcomeResult::Done(done) => Ok(done.process_start.expect("a launch").generation),
                OutcomeResult::Refused(why) => Err(why),
                OutcomeResult::Indeterminate(why) => panic!("indeterminate {why:?}"),
            }
        }

        fn status(
            socket: &Path,
            n: u64,
            generation: &BrokerGeneration,
        ) -> Result<(ProcessState, Option<u8>, Vec<u8>), BrokerRefusal> {
            let mut peer = Peer::connect(socket);
            let hello = peer.hello();
            peer.send(&status_frame(&hello.channel, n, generation), &[]);
            match peer.outcome().expect("an outcome").result() {
                OutcomeResult::Done(done) => {
                    let s = done.process_status.expect("a status");
                    Ok((
                        s.state,
                        s.signal.map(|x| x.get()),
                        s.stdout.content.to_bytes(),
                    ))
                }
                OutcomeResult::Refused(why) => Err(why),
                OutcomeResult::Indeterminate(why) => panic!("indeterminate {why:?}"),
            }
        }

        fn kill(
            socket: &Path,
            n: u64,
            generation: &BrokerGeneration,
        ) -> Result<KillOutcome, BrokerRefusal> {
            let mut peer = Peer::connect(socket);
            let hello = peer.hello();
            peer.send(&kill_frame(&hello.channel, n, generation), &[]);
            match peer.outcome().expect("an outcome").result() {
                OutcomeResult::Done(done) => Ok(done.process_kill.expect("a kill").outcome),
                OutcomeResult::Refused(why) => Err(why),
                OutcomeResult::Indeterminate(why) => panic!("indeterminate {why:?}"),
            }
        }

        #[test]
        fn a_launch_takes_exactly_its_two_descriptors_and_status_and_kill_take_none() {
            let scratch = Scratch::new("proc-descriptors");
            let broker = Broker::shared(&scratch.socket());
            let socket = scratch.socket();
            let mark = marker("descriptors");
            let sleeper = [
                "-I",
                "-c",
                "import sys, time; print('up', flush=True); time.sleep(60)",
                &mark,
            ];
            let generation = launch(&socket, 1, &scratch.0, &sleeper).unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                let (state, _, out) = status(&socket, 1, &generation).unwrap();
                assert_eq!(state, ProcessState::Running);
                if out == b"up\n" {
                    break;
                }
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(running(&mark).len(), 1);
            proc_evidence("launch-two-descriptors", "RUNNING");

            // Every wrong count: refused, and nothing more is started.
            let (path, _) = python_bytes();
            for (case, fds) in [
                ("none", vec![]),
                ("one", vec![open(&path)]),
                ("three", vec![open(&path), open(&scratch.0), open(&path)]),
            ] {
                let mut peer = Peer::connect(&socket);
                let hello = peer.hello();
                let borrowed: Vec<_> = fds.iter().map(|fd| fd.as_fd()).collect();
                let other = marker(case);
                peer.send(
                    &start_frame(
                        &hello.channel,
                        50,
                        &scratch.0,
                        &["-I", "-c", "pass", &other],
                    ),
                    &borrowed,
                );
                assert_eq!(
                    super::refused(peer.outcome()),
                    BrokerRefusal::DescriptorCount,
                    "{case}"
                );
                assert!(running(&other).is_empty(), "{case}");
                proc_evidence(
                    &format!("launch-{case}-descriptors"),
                    "DESCRIPTOR_COUNT-zero-exec",
                );
            }
            // Reversed.
            let mut peer = Peer::connect(&socket);
            let hello = peer.hello();
            let (exe, dir) = (open(&path), open(&scratch.0));
            peer.send(
                &start_frame(&hello.channel, 51, &scratch.0, &["-I", "-c", "pass"]),
                &[dir.as_fd(), exe.as_fd()],
            );
            assert_eq!(
                super::refused(peer.outcome()),
                BrokerRefusal::DescriptorNotRegular
            );
            proc_evidence("launch-descriptors-reversed", "DESCRIPTOR_NOT_REGULAR");
            // A status or a kill with a descriptor.
            for frame in [
                status_frame(&ChannelNonce::new("0".repeat(32)).unwrap(), 1, &generation),
                kill_frame(&ChannelNonce::new("0".repeat(32)).unwrap(), 1, &generation),
            ] {
                let mut peer = Peer::connect(&socket);
                let hello = peer.hello();
                let text = String::from_utf8(frame[5..].to_vec())
                    .unwrap()
                    .replace(&"0".repeat(32), hello.channel.as_str());
                let bytes =
                    dwk_proto::frame::encode(dwk_proto::frame::ContentType::Json, text.as_bytes())
                        .unwrap();
                let stray = open(&path);
                peer.send(&bytes, &[stray.as_fd()]);
                assert_eq!(
                    super::refused(peer.outcome()),
                    BrokerRefusal::DescriptorCount
                );
            }
            assert_eq!(
                status(&socket, 1, &generation).unwrap().0,
                ProcessState::Running
            );
            proc_evidence("status-kill-with-descriptor", "DESCRIPTOR_COUNT-no-signal");

            // Another generation, and a handle never issued.
            let stale = BrokerGeneration::new("f".repeat(32)).unwrap();
            assert_eq!(
                status(&socket, 1, &stale).err(),
                Some(BrokerRefusal::StaleGeneration)
            );
            assert_eq!(
                kill(&socket, 1, &stale).err(),
                Some(BrokerRefusal::StaleGeneration)
            );
            assert_eq!(
                status(&socket, 999, &generation).err(),
                Some(BrokerRefusal::UnknownProcess)
            );
            assert_eq!(running(&mark).len(), 1, "no refused request touched it");
            proc_evidence("stale-generation", "STALE_GENERATION-no-signal");

            // The kill: this process, and it is gone.
            assert_eq!(kill(&socket, 1, &generation), Ok(KillOutcome::Signaled));
            wait_gone(&mark);
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                let (state, signal, _) = status(&socket, 1, &generation).unwrap();
                if state == ProcessState::Signaled {
                    assert_eq!(signal, Some(9));
                    break;
                }
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(
                kill(&socket, 1, &generation),
                Ok(KillOutcome::AlreadyExited)
            );
            proc_evidence("kill-then-status", "SIGNALED-9");
            drop(broker);
        }

        #[test]
        fn a_target_inherits_nothing_of_the_brokers_environment() {
            let scratch = Scratch::new("proc-environment");
            let socket = scratch.socket();
            let canary = marker("canary");
            let _broker = Broker::with_environment(
                &socket,
                &[
                    ("DW_M4D_SECRET_TOKEN", canary.as_str()),
                    ("AWS_SECRET_ACCESS_KEY", canary.as_str()),
                    ("PATH", "/canary/bin"),
                    ("LD_PRELOAD", "/canary/lib.so"),
                ],
            );
            let report = "import os, sys; sys.stdout.write(repr(sorted(os.environ.items())))";
            let generation = launch(&socket, 1, &scratch.0, &["-I", "-c", report]).unwrap();
            let until = Instant::now() + Duration::from_secs(20);
            let out = loop {
                let (state, _, out) = status(&socket, 1, &generation).unwrap();
                if state != ProcessState::Running {
                    break out;
                }
                assert!(Instant::now() < until, "the report did not finish");
                std::thread::sleep(Duration::from_millis(20));
            };
            let text = String::from_utf8(out).unwrap();
            assert_eq!(
                text,
                "[('HOME', '/nonexistent'), ('LANG', 'C.UTF-8'), ('PATH', \
                 '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')]"
            );
            assert!(!text.contains(&canary) && !text.contains("canary"));
            proc_evidence("environment-not-inherited", "BASE-only-canary-absent");
        }

        #[test]
        fn a_broker_that_dies_takes_its_processes_with_it_and_its_successor_knows_none() {
            let scratch = Scratch::new("proc-restart");
            let socket = scratch.socket();
            let mark = marker("restart");
            let mut first = Broker::shared(&socket);
            let generation = launch(
                &socket,
                1,
                &scratch.0,
                &["-I", "-c", "import time; time.sleep(60)", &mark],
            )
            .unwrap();
            assert_eq!(running(&mark).len(), 1);
            first.kill();
            // The parent-death signal: no orphan outlives the broker.
            wait_gone(&mark);
            let _second = Broker::shared(&socket);
            assert_eq!(
                status(&socket, 1, &generation).err(),
                Some(BrokerRefusal::StaleGeneration)
            );
            assert_eq!(
                kill(&socket, 1, &generation).err(),
                Some(BrokerRefusal::StaleGeneration)
            );
            proc_evidence("broker-restart-orphans", "none");
            proc_evidence("broker-restart-generation", "STALE_GENERATION");
        }

        #[test]
        fn a_crash_at_any_launch_point_leaves_no_target_running() {
            // E4-E6 on the broker's side. The authority's record of each is
            // the authority's crash campaign; what this proves is that the
            // host is left with no process whichever point the broker stops at.
            for (point, outcome) in [
                ("process_before_helper", "closed-no-helper"),
                ("process_helper_spawned", "closed-helper-exits"),
                ("process_helper_before_exec", "EXEC_SETUP_FAILED"),
                (
                    "process_exec_confirmed",
                    "closed-target-killed-by-death-signal",
                ),
            ] {
                let scratch = Scratch::new("proc-crash");
                let socket = scratch.socket();
                let mut broker = Broker::crashing_at(&socket, point);
                let mark = marker(point);
                let mut peer = Peer::connect(&socket);
                let hello = peer.hello();
                let (path, _) = python_bytes();
                let (exe, dir) = (open(&path), open(&scratch.0));
                peer.send(
                    &start_frame(
                        &hello.channel,
                        1,
                        &scratch.0,
                        &["-I", "-c", "import time; time.sleep(60)", &mark],
                    ),
                    &[exe.as_fd(), dir.as_fd()],
                );
                match peer.outcome() {
                    Some(outcome) => assert!(
                        matches!(
                            outcome.result(),
                            OutcomeResult::Refused(BrokerRefusal::ExecSetupFailed)
                        ),
                        "{point}"
                    ),
                    None => assert_ne!(point, "process_helper_before_exec", "{point}"),
                }
                broker.kill();
                wait_gone(&mark);
                // The helper, too, is gone.
                let helpers = running("exec-helper");
                assert!(
                    helpers.iter().all(|pid| {
                        std::fs::read_to_string(format!("/proc/{pid}/stat"))
                            .map_or(true, |stat| !stat.contains(&broker_pid_marker(&broker)))
                    }),
                    "{point}"
                );
                proc_evidence(&format!("crash-{point}"), outcome);
            }
        }

        fn broker_pid_marker(broker: &Broker) -> String {
            format!(" {} ", broker.pid)
        }
    }
}
