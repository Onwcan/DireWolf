//! Three real operating-system identities on the M4d process channel
//! (ADR-0045 §22, the hosted half of evidence C).
//!
//! The authority is this process's uid: this test plays the authority's end
//! of the private channel — the production authority launches nothing before
//! M6, so no released authority can be the peer here, and none is claimed to
//! be. The broker runs as `DW_BROKER_AS`, started by this harness through
//! `sudo -n -u`; a hostile local process — the runtime's position — runs as
//! `DW_PEER_AS`. Each identity is proven by numbers.
//!
//! What only this suite can show:
//!
//! * **the broker executes the descriptor, not a name**: the executable lives
//!   in a directory only the authority's uid may enter, so the broker's own
//!   uid cannot even look it up — and it runs, because `execveat(fd, "",
//!   AT_EMPTY_PATH)` walks no path; the name replaced after the handoff is
//!   never executed;
//! * the hostile runtime can neither launch, inspect nor kill: the broker
//!   reads nothing from its uid, and the launch helper run by it does
//!   nothing.
//!
//! Without the identities these tests are `#[ignore]`d, and `make
//! process-broker-evidence` fails as NOT EXERCISED rather than passing.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{IoSlice, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::{
        self, BrokerGeneration, BrokerHello, BrokerOutcome, Common, ExecEnvironment, OutcomeResult,
        ProcessArgs, ProcessKillAuthorisation, ProcessSpec, ProcessStartAuthorisation,
        ProcessStatusAuthorisation, StreamLimit,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::json::{self, ParseOptions, Value};
    use dwk_proto::wire::id::{InvocationId, ProcessId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath, ProcessArg, ProcessState};
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, broker_bin};
    use super::state_support::TempDir;
    use super::transport_support::own_uid;

    fn evidence(case: &str, outcome: &str, uids: (u32, u32, u32)) {
        println!(
            "PROC-EVIDENCE {{\"suite\":\"process-foreign\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
             \"authority_uid\":{},\"broker_uid\":{},\"runtime_uid\":{},\"count\":1}}",
            uids.0, uids.1, uids.2
        );
    }

    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user `sudo -n -u` can switch to"
        );
        let probe = super::state_support::output(
            Command::new("sudo").args(["-n", "-u", &user, "id", "-u"]),
        )
        .expect("sudo runs");
        assert!(
            probe.status.success(),
            "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let uid: u32 = String::from_utf8_lossy(&probe.stdout)
            .trim()
            .parse()
            .unwrap();
        eprintln!(
            "{variable}={user} runs as uid {uid}; this process is uid {}",
            own_uid()
        );
        assert_ne!(uid, own_uid(), "{variable} is this process's uid");
        assert_ne!(uid, 0, "{variable} is root");
        assert!(!others.contains(&uid), "{variable} shares a uid");
        (user, uid)
    }

    fn mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The broker binary and the probe client, where other users can run them.
    struct Staging {
        dir: TempDir,
        broker: PathBuf,
        client: PathBuf,
    }

    fn staging() -> Staging {
        let dir = TempDir::new("m4d-staging");
        mode(dir.path(), 0o711);
        let broker = dir.path().join("dwkd-broker");
        std::fs::copy(broker_bin(), &broker).unwrap();
        mode(&broker, 0o755);
        let client = dir.path().join("broker_foreign_client.py");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/authority/broker_foreign_client.py"),
            &client,
        )
        .unwrap();
        mode(&client, 0o644);
        Staging {
            dir,
            broker,
            client,
        }
    }

    fn broker_socket(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        PathBuf::from(format!("/tmp/dwp-{tag}-{}-{nanos}", std::process::id())).join("broker.sock")
    }

    fn run_as(user: &str, staging: &Staging, args: &[&str]) -> json::Object {
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "-u", user, "/usr/bin/python3"])
                .arg(&staging.client)
                .args(args)
                .current_dir(staging.dir.path()),
        )
        .expect("sudo runs the client");
        assert!(
            output.status.success(),
            "the client failed as {user}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = String::from_utf8(output.stdout).unwrap();
        match json::parse(line.trim().as_bytes(), ParseOptions::dwkp()) {
            Ok(Value::Object(object)) => object,
            other => panic!("not a report: {other:?}\n{line}"),
        }
    }

    fn int(object: &json::Object, key: &str) -> u64 {
        match object.get(key) {
            Some(Value::Number(json::Number::Int(n))) => u64::try_from(*n).unwrap(),
            other => panic!("{key}: {other:?}"),
        }
    }

    fn text<'a>(object: &'a json::Object, key: &str) -> &'a str {
        match object.get(key) {
            Some(Value::String(s)) => s,
            other => panic!("{key}: {other:?}"),
        }
    }

    fn flag(object: &json::Object, key: &str) -> bool {
        matches!(object.get(key), Some(Value::Bool(true)))
    }

    fn process_id(n: u64) -> ProcessId {
        let ts = u128::from(1_758_000_000_000u64);
        let n = u128::from(n);
        ProcessId::from_uuid((ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | n)
            .unwrap()
    }

    fn invocation(n: u64) -> InvocationId {
        let ts = u128::from(1_758_000_000_000u64);
        let n = u128::from(n);
        InvocationId::from_uuid((ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | n)
            .unwrap()
    }

    /// This process as the authority's end of one exchange.
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

        fn channel(&mut self) -> dwk_proto::brokerp::ChannelNonce {
            BrokerHello::decode_frame_body(&self.frame().expect("a hello"))
                .unwrap()
                .channel
        }

        fn send(&mut self, bytes: &[u8], fds: &[&OwnedFd]) {
            let borrowed: Vec<_> = fds.iter().map(|fd| fd.as_fd()).collect();
            let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
            if !borrowed.is_empty() {
                assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&borrowed)));
            }
            let sent = rustix::net::sendmsg(
                &self.stream,
                &[IoSlice::new(bytes)],
                &mut control,
                rustix::net::SendFlags::NOSIGNAL,
            )
            .unwrap();
            self.stream.write_all(&bytes[sent..]).unwrap();
        }

        fn result(&mut self) -> OutcomeResult {
            BrokerOutcome::decode_frame_body(&self.frame().expect("an outcome"))
                .unwrap()
                .result()
        }
    }

    fn start_frame(
        channel: &dwk_proto::brokerp::ChannelNonce,
        exe: &Path,
        cwd: &Path,
        args: &[&str],
    ) -> Vec<u8> {
        let (em, cm) = (
            std::fs::metadata(exe).unwrap(),
            std::fs::metadata(cwd).unwrap(),
        );
        let digest: String = Sha256::digest(std::fs::read(exe).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let args: Vec<ProcessArg> = args
            .iter()
            .map(|a| ProcessArg::new((*a).to_owned()).unwrap())
            .collect();
        brokerp::encode_frame(&ProcessStartAuthorisation::new(
            Common::new(channel.clone(), invocation(1)),
            ProcessSpec {
                process_id: process_id(1),
                executable: (em.dev(), em.ino()),
                executable_sha256: ContentDigest::new(digest).unwrap(),
                cwd: (cm.dev(), cm.ino()),
                argv0: HostPath::new(exe.display().to_string()).unwrap(),
                args: ProcessArgs::new(args).unwrap(),
                environment: ExecEnvironment::Base,
                stream_limit: StreamLimit::new(131_072).unwrap(),
            },
        ))
        .unwrap()
    }

    fn status(socket: &Path, generation: &BrokerGeneration) -> (ProcessState, Vec<u8>) {
        let mut peer = Peer::connect(socket);
        let channel = peer.channel();
        let frame = brokerp::encode_frame(&ProcessStatusAuthorisation::new(
            Common::new(channel, invocation(2)),
            process_id(1),
            generation.clone(),
        ))
        .unwrap();
        peer.send(&frame, &[]);
        match peer.result() {
            OutcomeResult::Done(done) => {
                let s = done.process_status.unwrap();
                (s.state, s.stdout.content.to_bytes())
            }
            other => panic!("a status: {other:?}"),
        }
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS and DW_PEER_AS; run by `make process-broker-evidence`"]
    fn the_broker_identity_executes_a_descriptor_it_cannot_reach_by_name() {
        let (broker_user, broker_uid) = identity("DW_BROKER_AS", &[]);
        let (peer_user, peer_uid) = identity("DW_PEER_AS", &[broker_uid]);
        let uids = (own_uid(), broker_uid, peer_uid);
        let stage = staging();
        let socket = broker_socket("3id");
        let broker = Broker::start_as(&broker_user, &stage.broker, &socket, own_uid());
        assert_eq!(
            broker.uid(),
            broker_uid,
            "the broker runs as its own identity"
        );

        // The executable: a copy of this test binary, owned by the authority,
        // in a directory only the authority may enter.
        let work = TempDir::new("m4d-exec");
        mode(work.path(), 0o711);
        let private = work.path().join("private");
        std::fs::create_dir(&private).unwrap();
        mode(&private, 0o700);
        let exe = private.join("tool");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        mode(&exe, 0o755);
        let cwd = work.path().join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        mode(&cwd, 0o711);
        let by_name = run_as(&broker_user, &stage, &["read-path", exe.to_str().unwrap()]);
        assert!(
            flag(&by_name, "refused"),
            "the broker uid cannot open it by name: {by_name:?}"
        );
        assert_eq!(text(&by_name, "errno"), "EACCES");
        evidence("broker-uid-cannot-name-the-executable", "EACCES", uids);

        // The authority's descriptor: the one object, then the name replaced.
        let mut peer = Peer::connect(&socket);
        let channel = peer.channel();
        let frame = start_frame(&channel, &exe, &cwd, &["--list", "--format", "terse"]);
        let exe_fd: OwnedFd = std::fs::File::open(&exe).unwrap().into();
        let cwd_fd: OwnedFd = std::fs::File::open(&cwd).unwrap().into();
        std::fs::rename(&exe, private.join("original")).unwrap();
        std::fs::write(&exe, b"#!/bin/sh\necho REPLACEMENT-RAN-3id\n").unwrap();
        mode(&exe, 0o755);
        peer.send(&frame, &[&exe_fd, &cwd_fd]);
        let generation = match peer.result() {
            OutcomeResult::Done(done) => done.process_start.unwrap().generation,
            other => panic!("launched: {other:?}\n{}", broker.stderr()),
        };
        let until = Instant::now() + Duration::from_secs(30);
        let out = loop {
            let (state, _) = status(&socket, &generation);
            if state != ProcessState::Running {
                std::thread::sleep(Duration::from_millis(200));
                break status(&socket, &generation).1;
            }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = String::from_utf8_lossy(&out).into_owned();
        assert!(
            out.contains(": test"),
            "the checked object ran as the broker: {out}"
        );
        assert!(!out.contains("REPLACEMENT-RAN-3id"));
        evidence(
            "descriptor-bound-exec-cross-uid",
            "checked-object-executed",
            uids,
        );
        evidence(
            "path-replaced-after-handoff-cross-uid",
            "replacement-not-executed",
            uids,
        );

        // The hostile runtime: every operation, and the helper itself.
        let hostile_launch = run_as(
            &peer_user,
            &stage,
            &[
                "launch",
                socket.to_str().unwrap(),
                &frame.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "/usr/bin/python3",
                "/tmp",
            ],
        );
        assert_eq!(int(&hostile_launch, "received"), 0, "{hostile_launch:?}");
        let status_frame = brokerp::encode_frame(&ProcessStatusAuthorisation::new(
            Common::new(channel.clone(), invocation(3)),
            process_id(1),
            generation.clone(),
        ))
        .unwrap();
        let kill_frame = brokerp::encode_frame(&ProcessKillAuthorisation::new(
            Common::new(channel, invocation(4)),
            process_id(1),
            generation.clone(),
        ))
        .unwrap();
        for frame in [&status_frame, &kill_frame] {
            let hex: String = frame.iter().map(|b| format!("{b:02x}")).collect();
            let report = run_as(
                &peer_user,
                &stage,
                &["authorise", socket.to_str().unwrap(), &hex],
            );
            assert_eq!(int(&report, "received"), 0, "{report:?}");
        }
        let helper = run_as(
            &peer_user,
            &stage,
            &["run-helper", stage.broker.to_str().unwrap()],
        );
        assert_eq!(int(&helper, "exit"), 2);
        assert_eq!(int(&helper, "stdout") + int(&helper, "stderr"), 0);
        assert!(broker.count("peer_refused") >= 3, "{}", broker.stderr());
        evidence("runtime-uid-cannot-launch", "0-bytes-read", uids);
        evidence("runtime-uid-cannot-status-or-kill", "0-bytes-read", uids);
        evidence("runtime-uid-helper-does-nothing", "exit-2", uids);
    }
}
