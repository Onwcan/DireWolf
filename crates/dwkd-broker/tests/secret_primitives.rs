//! The broker's secret primitives against the released broker binary (M4e,
//! ADR-0046 §§11–16, 22): this harness plays the authority — the kernel
//! reports its uid as the one the broker was told to read from — and speaks
//! private protocol version 4 exactly as the authority's link does.
//!
//! What is measured, on real processes:
//!
//! * mode A: the value arrives as a descriptor, is read once — `rchar` says
//!   exactly how many bytes — and nothing about it comes back; a replay on a
//!   new connection reads nothing; every hostile descriptor and message is
//!   refused;
//! * modes B and C, **the secret injection primitive** (not a sandbox: the
//!   target runs on the host with the broker's privileges, and the authority
//!   never sends this before M5): the target receives the value exactly as
//!   the mode says, the broker's own environment and argv never hold it, a
//!   sibling launch does not see it, and the target's echo of it is redacted
//!   while it is drained — across read boundaries — so the process table
//!   never retains it;
//! * residue: after each primitive the broker's readable memory does not
//!   hold the value;
//! * the production default: a broker started without `--allow-dumpable` has
//!   `RLIMIT_CORE` 0 and is not dumpable.
//!
//! Values are generated at run time; assertions compare digests and
//! booleans, never values. Each case prints one `SECRET-EVIDENCE` line.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use dwk_proto as _;
#[cfg(target_os = "linux")]
use nix as _;
#[cfg(target_os = "linux")]
use rustix as _;
#[cfg(target_os = "linux")]
use sha2 as _;
#[cfg(target_os = "linux")]
use zeroize as _;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Seek as _, SeekFrom, Write as _};
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
        self, BrokerGeneration, BrokerHello, BrokerOutcome, BrokerRefusal, ChannelNonce, Common,
        EgressSpec, ExecEnvironment, OutcomeResult, ProcessArgs, ProcessSpec,
        ProcessStartAuthorisation, ProcessStatusAuthorisation, SecretDelivery,
        SecretEgressAuthorisation, SecretEnvName, SecretHandle, SecretHeaderName,
        SecretHeaderPrefix, SecretOrigin, SecretProcessStartAuthorisation, SpawnSecret,
        StreamLimit,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{InvocationId, ProcessId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath, ProcessArg, ProcessState};
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PYTHON: &str = "/usr/bin/python3";
    const PROMPT: Duration = Duration::from_secs(10);
    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn evidence(case: &str, outcome: &str) {
        println!(
            "SECRET-EVIDENCE {{\"suite\":\"broker-secret-primitives\",\"case\":\"{case}\",\
             \"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    fn own_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    /// A value no other process holds: 40 printable bytes, fresh per call.
    fn fresh_value() -> Vec<u8> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
        let seed = Sha256::digest(format!("{nanos}-{}-{n}", std::process::id()));
        let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        (0..40)
            .map(|i| {
                alphabet[usize::from(seed[i % 32] ^ u8::try_from(i).unwrap()) % alphabet.len()]
            })
            .collect()
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("dws-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("ipc").join("broker.sock")
        }

        /// Whether any file under this directory holds `needle`.
        fn holds(&self, needle: &[u8]) -> bool {
            fn walk(dir: &Path, needle: &[u8]) -> bool {
                std::fs::read_dir(dir).is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|e| {
                        let path = e.path();
                        if path.is_dir() {
                            walk(&path, needle)
                        } else {
                            std::fs::read(&path)
                                .is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
                        }
                    })
                })
            }
            walk(&self.0, needle)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Broker {
        child: Child,
        pid: u32,
        stderr: Arc<Mutex<String>>,
    }

    impl Broker {
        /// A same-uid broker. `dumpable` lets this harness read its `/proc`.
        fn start(socket: &Path, dumpable: bool, crash: Option<&str>) -> Self {
            let mut command = Command::new(BIN);
            command.env_clear();
            if let Some(point) = crash {
                command.env("DWKD_BROKER_CRASH_AT", point);
            }
            command
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(own_uid().to_string())
                .arg("--allow-shared-authority-uid");
            if dumpable {
                command.arg("--allow-dumpable");
            }
            let mut child = command
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
                    return Self { child, pid, stderr };
                }
                assert!(
                    Instant::now() < deadline && !matches!(child.try_wait(), Ok(Some(_))),
                    "the broker did not start:\n{}",
                    stderr.lock().unwrap()
                );
            }
        }

        fn stderr(&self) -> String {
            self.stderr.lock().unwrap().clone()
        }

        fn count(&self, needle: &str) -> usize {
            self.stderr().matches(needle).count()
        }

        /// The events so far, by kind only (`closed`, `refused`, ...): a
        /// diagnostic that carries no field of any line.
        fn kinds(&self) -> String {
            self.stderr()
                .lines()
                .filter_map(|line| line.split_once("event=").map(|(_, event)| event))
                .map(|event| event.split(' ').next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join(",")
        }

        /// Require exactly `n` lines holding `needle` once this harness has
        /// read everything the broker wrote through its `exchanges`-th
        /// connection. Its stderr is drained by another thread, so a count
        /// taken when the last outcome arrives can be short. Each exchange's
        /// events precede its `closed` in the one stream, so `exchanges`
        /// closings seen means every line of those exchanges is here: fewer
        /// than `n` then, or more, is the broker's count, not the reader's lag.
        fn expect_logged(&self, needle: &str, n: usize, exchanges: usize) {
            let deadline = Instant::now() + PROMPT;
            while self.count("event=closed\n") < exchanges {
                assert!(
                    Instant::now() < deadline,
                    "SECRET_LOG_COUNT_TIMEOUT: {} of {exchanges} exchanges closed and {} of {n} \
                     `{needle}` lines read after {PROMPT:?}; events: {}",
                    self.count("event=closed\n"),
                    self.count(needle),
                    self.kinds()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let seen = self.count(needle);
            assert_eq!(
                seen,
                n,
                "SECRET_LOG_COUNT_MISMATCH: `{needle}` after {exchanges} exchanges; events: {}",
                self.kinds()
            );
        }

        fn rchar(&self) -> u64 {
            let io = std::fs::read_to_string(format!("/proc/{}/io", self.pid)).unwrap();
            io.lines()
                .find_map(|l| l.strip_prefix("rchar:"))
                .map(|v| v.trim().parse().unwrap())
                .unwrap()
        }

        fn open_fds(&self) -> usize {
            std::fs::read_dir(format!("/proc/{}/fd", self.pid))
                .unwrap()
                .count()
        }

        /// The pipes the broker holds: a secret pipe it kept would be one.
        fn pipes(&self) -> usize {
            std::fs::read_dir(format!("/proc/{}/fd", self.pid))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .is_ok_and(|to| to.to_string_lossy().starts_with("pipe:"))
                })
                .count()
        }

        fn exited(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(Some(_)))
        }
    }

    impl Drop for Broker {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Whether any readable mapping of `pid` holds `needle`: the process's
    /// whole readable address space, as a core file would hold it. A mapping
    /// the kernel will not let this process read (`[vvar]`, a guard page) is
    /// skipped; `None` when the process's memory cannot be read at all.
    fn memory_holds(pid: u32, needle: &[u8]) -> Option<bool> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
        let mut scanned = 0u64;
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !perms.starts_with('r') {
                continue;
            }
            let (start, end) = range.split_once('-').unwrap();
            let (start, end) = (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            );
            let mut offset = start;
            let mut carry: Vec<u8> = Vec::new();
            while offset < end {
                let len = usize::try_from((end - offset).min(1 << 20)).unwrap();
                let mut chunk = vec![0u8; len];
                if mem.seek(SeekFrom::Start(offset)).is_err() || mem.read_exact(&mut chunk).is_err()
                {
                    break;
                }
                scanned += u64::try_from(len).unwrap();
                carry.extend_from_slice(&chunk);
                if carry.windows(needle.len()).any(|w| w == needle) {
                    return Some(true);
                }
                let keep = carry.len().saturating_sub(needle.len());
                carry.drain(..keep);
                offset += u64::try_from(len).unwrap();
            }
        }
        (scanned > 0).then_some(false)
    }

    struct Peer {
        stream: UnixStream,
        decoder: FrameDecoder,
        pending: Vec<u8>,
    }

    impl Peer {
        fn connect(socket: &Path) -> Self {
            let stream = UnixStream::connect(socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            Self {
                stream,
                decoder: FrameDecoder::new(),
                pending: Vec::new(),
            }
        }

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

        fn send(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
            let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if !fds.is_empty() {
                assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
            }
            let sent = rustix::net::sendmsg(
                &self.stream,
                &[IoSlice::new(bytes)],
                &mut control,
                SendFlags::NOSIGNAL,
            )
            .unwrap();
            self.stream.write_all(&bytes[sent..]).unwrap();
        }

        /// The outcome's raw body, and its decoded result; `None` when the
        /// broker closed without one.
        fn outcome(&mut self) -> Option<(Vec<u8>, OutcomeResult)> {
            let body = self.frame()?;
            let result = BrokerOutcome::decode_frame_body(&body).unwrap().result();
            Some((body, result))
        }
    }

    fn invocation(n: u8) -> InvocationId {
        InvocationId::parse(&format!("inv_01M24BB8G3E0A851TRWE3M8F{:02}", n % 90 + 10)).unwrap()
    }

    /// The read end of a pipe holding `bytes`, its writer closed — what the
    /// authority's handoff makes.
    fn one_shot(bytes: &[u8]) -> OwnedFd {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(bytes).unwrap();
        drop(writer);
        OwnedFd::from(reader)
    }

    fn egress_frame(channel: &ChannelNonce) -> Vec<u8> {
        let a = SecretEgressAuthorisation::new(
            Common::new(channel.clone(), invocation(1)),
            EgressSpec {
                handle: SecretHandle::new("api-token").unwrap(),
                origin: SecretOrigin::new("api.example.com:443").unwrap(),
                header_name: SecretHeaderName::new("Authorization").unwrap(),
                header_prefix: SecretHeaderPrefix::new("Bearer "),
            },
        );
        brokerp::encode_frame(&a).unwrap()
    }

    /// One render exchange: the outcome body and result, or `None` if closed.
    fn render(socket: &Path, fds: &[BorrowedFd<'_>]) -> Option<(Vec<u8>, OutcomeResult)> {
        let mut peer = Peer::connect(socket);
        let hello = peer.hello();
        peer.send(&egress_frame(&hello.channel), fds);
        peer.outcome()
    }

    fn refusal(outcome: Option<(Vec<u8>, OutcomeResult)>) -> BrokerRefusal {
        match outcome.expect("an outcome").1 {
            OutcomeResult::Refused(why) => why,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    #[test]
    fn a_render_reads_the_value_once_through_its_descriptor_and_returns_nothing_of_it() {
        let scratch = Scratch::new("egress");
        let broker = Broker::start(&scratch.socket(), true, None);
        let socket = scratch.socket();
        let value = fresh_value();
        let baseline = broker.open_fds();

        let before = broker.rchar();
        let secret = one_shot(&value);
        let (body, result) = render(&socket, &[secret.as_fd()]).expect("an outcome");
        let OutcomeResult::Done(done) = result else {
            panic!("rendered")
        };
        assert!(done.secret_egress.is_some());
        let read = broker.rchar() - before;
        assert_eq!(
            read,
            u64::try_from(value.len()).unwrap(),
            "exactly the value was read"
        );
        assert!(
            !body.windows(value.len()).any(|w| w == value),
            "the answer holds no value"
        );
        assert!(
            !broker
                .stderr()
                .contains(std::str::from_utf8(&value).unwrap())
        );
        evidence("egress-render-one-descriptor", "DONE-rchar-exact-no-echo");

        // The same descriptor, consumed: it holds nothing now, and says so.
        assert_eq!(
            refusal(render(&socket, &[secret.as_fd()])),
            BrokerRefusal::SecretEmpty
        );
        evidence("egress-descriptor-reused-after-consumption", "SECRET_EMPTY");

        // The same authorisation on a new connection: another channel, read
        // nothing.
        let mut first = Peer::connect(&socket);
        let old = first.hello();
        drop(first);
        let before = broker.rchar();
        let mut peer = Peer::connect(&socket);
        let _ = peer.hello();
        let again = one_shot(&value);
        peer.send(&egress_frame(&old.channel), &[again.as_fd()]);
        assert_eq!(refusal(peer.outcome()), BrokerRefusal::ChannelMismatch);
        assert_eq!(broker.rchar() - before, 0, "a replay reads nothing");
        evidence(
            "egress-replay-new-connection",
            "CHANNEL_MISMATCH-zero-bytes",
        );

        // Residue: the broker's readable memory no longer holds the value.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker residue"
        );
        assert_eq!(broker.open_fds(), baseline, "every descriptor closed");
        evidence("egress-broker-residue", "absent");
    }

    #[test]
    fn every_hostile_secret_descriptor_or_message_is_refused_before_anything_is_rendered() {
        let scratch = Scratch::new("egress-hostile");
        let broker = Broker::start(&scratch.socket(), true, None);
        let socket = scratch.socket();
        let value = fresh_value();
        let dir = OwnedFd::from(std::fs::File::open(&scratch.0).unwrap());
        let file_path = scratch.0.join("plain");
        std::fs::write(&file_path, &value).unwrap();
        let file = OwnedFd::from(std::fs::File::open(&file_path).unwrap());
        let (_stalled_reader, writer) = std::io::pipe().unwrap();
        let writer = OwnedFd::from(writer);
        let (stalled, mut kept_writer) = std::io::pipe().unwrap();
        kept_writer.write_all(&value).unwrap();
        let stalled = OwnedFd::from(stalled);
        let mut unsafe_values = Vec::new();
        for bad in [b'\r', b'\n', 0] {
            let mut v = value.clone();
            v[7] = bad;
            unsafe_values.push(one_shot(&v));
        }
        let empty = one_shot(b"");
        let huge = one_shot(&vec![b'x'; brokerp::MAX_SECRET_BYTES + 1]);
        let good = one_shot(&value);
        let cases: Vec<(&str, Vec<BorrowedFd<'_>>, BrokerRefusal)> = vec![
            ("missing", vec![], BrokerRefusal::DescriptorCount),
            (
                "extra",
                vec![good.as_fd(), good.as_fd()],
                BrokerRefusal::DescriptorCount,
            ),
            (
                "directory",
                vec![dir.as_fd()],
                BrokerRefusal::SecretDescriptor,
            ),
            (
                "regular-file",
                vec![file.as_fd()],
                BrokerRefusal::SecretDescriptor,
            ),
            (
                "writable",
                vec![writer.as_fd()],
                BrokerRefusal::SecretDescriptor,
            ),
            (
                "stalled-writer-open",
                vec![stalled.as_fd()],
                BrokerRefusal::SecretDescriptor,
            ),
            (
                "zero-length",
                vec![empty.as_fd()],
                BrokerRefusal::SecretEmpty,
            ),
            (
                "oversized",
                vec![huge.as_fd()],
                BrokerRefusal::SecretTooLarge,
            ),
            (
                "carriage-return",
                vec![unsafe_values[0].as_fd()],
                BrokerRefusal::SecretUnsafeBytes,
            ),
            (
                "line-feed",
                vec![unsafe_values[1].as_fd()],
                BrokerRefusal::SecretUnsafeBytes,
            ),
            (
                "nul",
                vec![unsafe_values[2].as_fd()],
                BrokerRefusal::SecretUnsafeBytes,
            ),
        ];
        for (case, fds, want) in cases {
            let started = Instant::now();
            assert_eq!(refusal(render(&socket, &fds)), want, "{case}");
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "{case}: nothing waited"
            );
            evidence(&format!("egress-hostile-{case}"), want.as_str());
        }
        drop(kept_writer);
        // Eleven exchanges, each refused and logged once, and read in full.
        broker.expect_logged("op=broker.secret_egress", 11, 11);
        assert_eq!(
            broker.count("executed invocation"),
            0,
            "nothing was rendered"
        );

        // Messages the language does not have: closed, unanswered.
        for (case, edit) in [
            ("old-private-version", ("\"protocol\":4", "\"protocol\":3")),
            (
                "unknown-kind",
                ("broker.secret_egress", "broker.secret_fetch"),
            ),
            (
                "header-with-space",
                ("\"Authorization\"", "\"Author ization\""),
            ),
            (
                "value-field",
                ("\"handle\":", "\"value\":\"x\",\"handle\":"),
            ),
            (
                "mode-field",
                ("\"handle\":", "\"injection_mode\":\"env\",\"handle\":"),
            ),
        ] {
            let mut peer = Peer::connect(&socket);
            let hello = peer.hello();
            let text = String::from_utf8(egress_frame(&hello.channel)[5..].to_vec())
                .unwrap()
                .replacen(edit.0, edit.1, 1);
            let bytes =
                dwk_proto::frame::encode(dwk_proto::frame::ContentType::Json, text.as_bytes())
                    .unwrap();
            let secret = one_shot(&value);
            peer.send(&bytes, &[secret.as_fd()]);
            assert!(peer.outcome().is_none(), "{case}: closed unanswered");
            evidence(&format!("egress-malformed-{case}"), "closed-unanswered");
        }
        // The authority disconnecting after the descriptor arrived.
        let mut peer = Peer::connect(&socket);
        let hello = peer.hello();
        let secret = one_shot(&value);
        peer.send(&egress_frame(&hello.channel), &[secret.as_fd()]);
        drop(peer);
        let deadline = Instant::now() + PROMPT;
        while broker.count("outcome_failed") + broker.count("executed invocation") == 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker residue"
        );
        evidence("egress-authority-disconnects", "no-residue");
    }

    #[test]
    fn a_broker_stopped_after_reading_the_value_answers_nothing_and_leaves_nothing() {
        let scratch = Scratch::new("egress-crash");
        let mut broker = Broker::start(&scratch.socket(), true, Some("secret_after_read"));
        let value = fresh_value();
        let secret = one_shot(&value);
        assert!(
            render(&scratch.socket(), &[secret.as_fd()]).is_none(),
            "no outcome"
        );
        let deadline = Instant::now() + PROMPT;
        while !broker.exited() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!scratch.holds(&value), "no file holds it");
        assert!(
            !broker
                .stderr()
                .contains(std::str::from_utf8(&value).unwrap())
        );
        evidence("crash-r7-broker-after-read", "closed-no-core-no-file");
    }

    // ---- modes B and C: the secret injection primitive ----------------------

    fn python() -> (PathBuf, String) {
        let path = std::fs::canonicalize(PYTHON).unwrap();
        (path.clone(), digest(&std::fs::read(&path).unwrap()))
    }

    fn process_id(n: u64) -> ProcessId {
        let ts = u128::from(1_758_000_000_000u64);
        let n = u128::from(n);
        ProcessId::from_uuid((ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | n)
            .unwrap()
    }

    fn spec(n: u64, cwd: &Path, args: &[&str]) -> ProcessSpec {
        let (path, sha) = python();
        let meta = std::fs::metadata(&path).unwrap();
        let cwd_meta = std::fs::metadata(cwd).unwrap();
        ProcessSpec {
            process_id: process_id(n),
            executable: (meta.dev(), meta.ino()),
            executable_sha256: ContentDigest::new(sha).unwrap(),
            cwd: (cwd_meta.dev(), cwd_meta.ino()),
            argv0: HostPath::new(path.display().to_string()).unwrap(),
            args: ProcessArgs::new(
                args.iter()
                    .map(|a| ProcessArg::new((*a).to_owned()).unwrap())
                    .collect(),
            )
            .unwrap(),
            environment: ExecEnvironment::Base,
            stream_limit: StreamLimit::new(4096).unwrap(),
        }
    }

    fn secret_start_frame(
        channel: &ChannelNonce,
        n: u64,
        cwd: &Path,
        args: &[&str],
        delivery: SecretDelivery,
    ) -> Vec<u8> {
        let a = SecretProcessStartAuthorisation::new(
            Common::new(channel.clone(), invocation(2)),
            spec(n, cwd, args),
            SpawnSecret {
                handle: SecretHandle::new("deploy-key").unwrap(),
                delivery,
                env_name: (delivery == SecretDelivery::EnvAtSpawn)
                    .then(|| SecretEnvName::new("DW_TEST_TOKEN").unwrap()),
            },
        );
        brokerp::encode_frame(&a).unwrap()
    }

    /// A secret launch: the generation, or the refusal.
    fn secret_launch(
        socket: &Path,
        n: u64,
        cwd: &Path,
        args: &[&str],
        delivery: SecretDelivery,
        secret: &OwnedFd,
    ) -> Result<BrokerGeneration, BrokerRefusal> {
        let mut peer = Peer::connect(socket);
        let hello = peer.hello();
        let (path, _) = python();
        let exe = OwnedFd::from(std::fs::File::open(path).unwrap());
        let dir = OwnedFd::from(std::fs::File::open(cwd).unwrap());
        peer.send(
            &secret_start_frame(&hello.channel, n, cwd, args, delivery),
            &[exe.as_fd(), dir.as_fd(), secret.as_fd()],
        );
        match peer.outcome().expect("an outcome").1 {
            OutcomeResult::Done(done) => {
                Ok(done.secret_process_start.expect("a launch").generation)
            }
            OutcomeResult::Refused(why) => Err(why),
            OutcomeResult::Indeterminate(why) => panic!("indeterminate {why:?}"),
        }
    }

    /// A plain launch (no secret), for the sibling.
    fn plain_launch(socket: &Path, n: u64, cwd: &Path, args: &[&str]) -> BrokerGeneration {
        let mut peer = Peer::connect(socket);
        let hello = peer.hello();
        let (path, _) = python();
        let exe = OwnedFd::from(std::fs::File::open(path).unwrap());
        let dir = OwnedFd::from(std::fs::File::open(cwd).unwrap());
        let a = ProcessStartAuthorisation::new(
            Common::new(hello.channel.clone(), invocation(3)),
            spec(n, cwd, args),
        );
        peer.send(
            &brokerp::encode_frame(&a).unwrap(),
            &[exe.as_fd(), dir.as_fd()],
        );
        match peer.outcome().expect("an outcome").1 {
            OutcomeResult::Done(done) => done.process_start.expect("a launch").generation,
            other => panic!("launched: {other:?}"),
        }
    }

    /// Poll until the process ended: its stdout and stderr, as retained.
    fn finished(socket: &Path, n: u64, generation: &BrokerGeneration) -> (Vec<u8>, Vec<u8>) {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let mut peer = Peer::connect(socket);
            let hello = peer.hello();
            let a = ProcessStatusAuthorisation::new(
                Common::new(hello.channel.clone(), invocation(4)),
                process_id(n),
                generation.clone(),
            );
            peer.send(&brokerp::encode_frame(&a).unwrap(), &[]);
            let OutcomeResult::Done(done) = peer.outcome().unwrap().1 else {
                panic!("a status")
            };
            let s = done.process_status.unwrap();
            if s.state != ProcessState::Running {
                return (s.stdout.content.to_bytes(), s.stderr.content.to_bytes());
            }
            assert!(Instant::now() < until, "the target did not finish");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The pid of the live process whose argv holds `marker`.
    fn pid_of(marker: &str) -> u32 {
        let until = Instant::now() + PROMPT;
        loop {
            let found = std::fs::read_dir("/proc")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .find(|pid| {
                    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| {
                        c.starts_with(PYTHON.as_bytes())
                            && c.windows(marker.len()).any(|w| w == marker.as_bytes())
                    })
                });
            if let Some(pid) = found {
                return pid;
            }
            assert!(Instant::now() < until, "{marker} never ran");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn holds(path: &str, needle: &[u8]) -> Option<bool> {
        std::fs::read(path)
            .ok()
            .map(|b| b.windows(needle.len()).any(|w| w == needle))
    }

    /// Mode C's target: read descriptor 3 to its end; report its digest, the
    /// descriptors it holds, whether the value is in its environment or argv,
    /// whether a grandchild it starts sees descriptor 3; wait for the go file;
    /// then echo the value in two writes on stdout and once on stderr.
    const MODE_C: &str = r#"
import hashlib, os, stat, sys, time
data = b""
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    data += chunk
fifo = stat.S_ISFIFO(os.fstat(3).st_mode)
held = []
for fd in range(64):
    try:
        os.fstat(fd)
        held.append(fd)
    except OSError:
        pass
env = any(data in (k + "=" + v).encode() for k, v in os.environ.items())
argv = any(data in a.encode() for a in sys.argv)
grandchild = os.system("test -e /proc/self/fd/3") == 0
print(hashlib.sha256(data).hexdigest(), fifo, held, env, argv, grandchild, flush=True)
deadline = time.time() + 20
while not os.path.exists(sys.argv[1]) and time.time() < deadline:
    time.sleep(0.02)
sys.stdout.buffer.write(b"echo:" + data[:13]); sys.stdout.flush(); time.sleep(0.2)
sys.stdout.buffer.write(data[13:] + b"\n"); sys.stdout.flush()
sys.stderr.buffer.write(data); sys.stderr.flush()
"#;

    /// Mode B's target: the value's digest from its environment, whether it is
    /// in argv; wait for the go file; echo it split across two writes.
    const MODE_B: &str = r#"
import hashlib, os, sys, time
v = os.environ.get("DW_TEST_TOKEN", "").encode()
print(hashlib.sha256(v).hexdigest(), any(v in a.encode() for a in sys.argv), flush=True)
deadline = time.time() + 20
while not os.path.exists(sys.argv[1]) and time.time() < deadline:
    time.sleep(0.02)
sys.stdout.buffer.write(v[:9]); sys.stdout.flush(); time.sleep(0.2)
sys.stdout.buffer.write(v[9:] + b"\n"); sys.stdout.flush()
"#;

    #[test]
    fn mode_c_hands_the_target_exactly_descriptor_three_and_the_echo_is_redacted() {
        let scratch = Scratch::new("mode-c");
        let socket = scratch.socket();
        let broker = Broker::start(&socket, true, None);
        let value = fresh_value();
        let go = scratch.0.join("go-c");
        let marker = format!("dwsmark-target-c-{}", std::process::id());
        let baseline = broker.pipes();
        let secret = one_shot(&value);
        let before = broker.rchar();
        let generation = secret_launch(
            &socket,
            1,
            &scratch.0,
            &["-I", "-c", MODE_C, go.to_str().unwrap(), &marker],
            SecretDelivery::FdAtSpawn,
            &secret,
        )
        .unwrap();
        drop(secret);
        let target = pid_of(&marker);
        // While it runs: the value is in neither its argv nor its
        // environment, nor the broker's.
        assert_eq!(
            holds(&format!("/proc/{target}/cmdline"), &value),
            Some(false)
        );
        assert_eq!(
            holds(&format!("/proc/{target}/environ"), &value),
            Some(false)
        );
        assert_eq!(
            holds(&format!("/proc/{}/environ", broker.pid), &value),
            Some(false)
        );
        assert_eq!(
            holds(&format!("/proc/{}/cmdline", broker.pid), &value),
            Some(false)
        );
        std::fs::write(&go, b"").unwrap();
        let (stdout, stderr) = finished(&socket, 1, &generation);
        let text = String::from_utf8(stdout.clone()).unwrap();
        let report = text.lines().next().unwrap();
        let parts: Vec<&str> = report.splitn(2, ' ').collect();
        assert_eq!(
            parts[0],
            digest(&value),
            "the target read exactly the value"
        );
        assert!(
            parts[1].starts_with("True [0, 1, 2, 3] False False True"),
            "fd 3 a FIFO, nothing else, not in env or argv, and a grandchild inherits it: {}",
            parts[1]
        );
        evidence("mode-c-target-fd3", "FIFO-only-fd-3-not-in-env-or-argv");
        evidence(
            "mode-c-grandchild-inheritance",
            "INHERITED-documented-limitation-M5-containment",
        );
        // The echo, split across two writes: redacted in the retained output.
        assert!(text.contains("echo:[redacted:deploy-key]\n"), "{text}");
        assert!(!stdout.windows(value.len()).any(|w| w == value));
        assert_eq!(stderr, b"[redacted:deploy-key]");
        evidence("mode-c-echo-redacted-while-drained", "placeholder");
        // The broker read the value once (the pipe), then the helper's copy
        // travelled in a pipe the broker wrote, which rchar does not count.
        assert!(broker.rchar() - before >= u64::try_from(value.len()).unwrap());
        // Residue: the broker's memory, its descriptors, the filesystem.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker residue"
        );
        // The table keeps the process's pidfd until eviction (ADR-0045);
        // no pipe of the launch outlives it.
        assert_eq!(broker.pipes(), baseline, "the secret pipes are closed");
        assert!(!scratch.holds(&value), "no file holds it");
        evidence("mode-c-residue", "broker-memory-absent-fds-closed-no-file");
    }

    #[test]
    fn mode_b_puts_the_value_only_in_the_targets_environment() {
        let scratch = Scratch::new("mode-b");
        let socket = scratch.socket();
        let broker = Broker::start(&socket, true, None);
        let value = fresh_value();
        let go = scratch.0.join("go-b");
        let marker = format!("dwsmark-target-b-{}", std::process::id());
        let sibling_marker = format!("dwsmark-sibling-{}", std::process::id());
        // A sibling launched first, still running while the target runs.
        let sibling_generation = plain_launch(
            &socket,
            2,
            &scratch.0,
            &["-I", "-c", "import time; time.sleep(3)", &sibling_marker],
        );
        let secret = one_shot(&value);
        let generation = secret_launch(
            &socket,
            1,
            &scratch.0,
            &["-I", "-c", MODE_B, go.to_str().unwrap(), &marker],
            SecretDelivery::EnvAtSpawn,
            &secret,
        )
        .unwrap();
        drop(secret);
        let target = pid_of(&marker);
        let sibling = pid_of(&sibling_marker);
        // The deliberate location, and nowhere else.
        let assignment = [b"DW_TEST_TOKEN=".as_slice(), &value].concat();
        assert_eq!(
            holds(&format!("/proc/{target}/environ"), &assignment),
            Some(true)
        );
        assert_eq!(
            holds(&format!("/proc/{target}/cmdline"), &value),
            Some(false)
        );
        assert_eq!(
            holds(&format!("/proc/{sibling}/environ"), &value),
            Some(false)
        );
        assert_eq!(
            holds(&format!("/proc/{}/environ", broker.pid), &value),
            Some(false)
        );
        evidence(
            "mode-b-target-environment-only",
            "target-env-yes-argv-no-sibling-no-broker-no",
        );
        std::fs::write(&go, b"").unwrap();
        let (stdout, _) = finished(&socket, 1, &generation);
        let text = String::from_utf8(stdout.clone()).unwrap();
        assert_eq!(
            text.lines().next().unwrap(),
            format!("{} False", digest(&value))
        );
        assert!(text.contains("[redacted:deploy-key]\n"), "{text}");
        assert!(!stdout.windows(value.len()).any(|w| w == value));
        evidence("mode-b-echo-redacted-across-writes", "placeholder");
        let _ = finished(&socket, 2, &sibling_generation);
        // The environment went with the process.
        assert!(!Path::new(&format!("/proc/{target}")).exists());
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker residue"
        );
        evidence("mode-b-residue", "broker-memory-absent-process-gone");
    }

    #[test]
    fn a_secret_launch_with_the_wrong_descriptors_or_an_unsafe_value_starts_nothing() {
        let scratch = Scratch::new("mode-hostile");
        let socket = scratch.socket();
        let broker = Broker::start(&socket, true, None);
        let value = fresh_value();
        let (path, _) = python();
        let marker = format!("dwsmark-never-{}", std::process::id());
        let args = ["-I", "-c", "import time; time.sleep(30)", marker.as_str()];
        // Two descriptors: the launch without its secret.
        let mut peer = Peer::connect(&socket);
        let hello = peer.hello();
        let exe = OwnedFd::from(std::fs::File::open(&path).unwrap());
        let dir = OwnedFd::from(std::fs::File::open(&scratch.0).unwrap());
        peer.send(
            &secret_start_frame(
                &hello.channel,
                5,
                &scratch.0,
                &args,
                SecretDelivery::FdAtSpawn,
            ),
            &[exe.as_fd(), dir.as_fd()],
        );
        assert_eq!(refusal(peer.outcome()), BrokerRefusal::DescriptorCount);
        evidence("spawn-missing-secret-descriptor", "DESCRIPTOR_COUNT");
        // Reversed: the secret first.
        let mut peer = Peer::connect(&socket);
        let hello = peer.hello();
        let secret = one_shot(&value);
        let before = broker.rchar();
        peer.send(
            &secret_start_frame(
                &hello.channel,
                6,
                &scratch.0,
                &args,
                SecretDelivery::FdAtSpawn,
            ),
            &[secret.as_fd(), exe.as_fd(), dir.as_fd()],
        );
        let why = refusal(peer.outcome());
        assert!(
            matches!(
                why,
                BrokerRefusal::DescriptorNotReadable | BrokerRefusal::DescriptorNotRegular
            ),
            "{why:?}"
        );
        assert_eq!(broker.rchar() - before, 0, "the value was not read");
        evidence("spawn-descriptors-reversed", "refused-value-unread");
        // A NUL in an environment-bound value.
        let mut with_nul = value.clone();
        with_nul[5] = 0;
        let nul = one_shot(&with_nul);
        assert_eq!(
            secret_launch(
                &socket,
                7,
                &scratch.0,
                &args,
                SecretDelivery::EnvAtSpawn,
                &nul
            ),
            Err(BrokerRefusal::SecretUnsafeBytes)
        );
        evidence("spawn-env-nul", "SECRET_UNSAFE_BYTES");
        // A process-control variable as the target: not in the language.
        let mut peer = Peer::connect(&socket);
        let hello = peer.hello();
        let text = String::from_utf8(
            secret_start_frame(
                &hello.channel,
                8,
                &scratch.0,
                &args,
                SecretDelivery::EnvAtSpawn,
            )[5..]
                .to_vec(),
        )
        .unwrap()
        .replace("DW_TEST_TOKEN", "LD_PRELOAD");
        let bytes =
            dwk_proto::frame::encode(dwk_proto::frame::ContentType::Json, text.as_bytes()).unwrap();
        let secret = one_shot(&value);
        peer.send(&bytes, &[exe.as_fd(), dir.as_fd(), secret.as_fd()]);
        assert!(peer.outcome().is_none(), "closed unanswered");
        evidence("spawn-env-ld-preload", "closed-unanswered");
        std::thread::sleep(Duration::from_millis(200));
        let started = std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                std::fs::read(e.path().join("cmdline"))
                    .is_ok_and(|c| c.windows(marker.len()).any(|w| w == marker.as_bytes()))
            });
        assert!(!started, "nothing was launched");
    }

    #[test]
    fn a_production_broker_dumps_no_core_and_keeps_its_memory_from_its_own_uid() {
        let scratch = Scratch::new("hardened");
        let broker = Broker::start(&scratch.socket(), false, None);
        let limits = std::fs::read_to_string(format!("/proc/{}/limits", broker.pid)).unwrap();
        let core = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        let fields: Vec<&str> = core.split_whitespace().collect();
        assert_eq!(&fields[4..6], ["0", "0"], "{core}");
        evidence("broker-rlimit-core", "0-0");
        // Not dumpable: its /proc entries are root's, so this same-uid process
        // cannot read its memory, environment or descriptors.
        let fd_dir = std::fs::metadata(format!("/proc/{}/fd", broker.pid)).unwrap();
        assert_eq!(fd_dir.uid(), 0, "a non-dumpable process's /proc is root's");
        assert!(std::fs::read(format!("/proc/{}/environ", broker.pid)).is_err());
        assert!(
            memory_holds(broker.pid, b"anything").is_none(),
            "memory unreadable"
        );
        evidence("broker-not-dumpable", "proc-root-owned-memory-unreadable");
    }
}
