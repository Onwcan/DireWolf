//! M5d.3's real-container evidence at the broker (ADR-0052 §7): the released
//! `dwkd-broker` handing a **synthetic** credential to a workload in a
//! **real** OCI environment it prepared -- through its real runtime client,
//! over the client's standard input, to the digest-pinned probe as the
//! trusted launcher -- with this test process playing the authority.
//!
//! Every test here is `#[ignore]`d: it needs a runtime and the evidence
//! image `make sandbox-secret-evidence` builds (`DW_SANDBOX_*`). Run any
//! other way, a test panics with `NOT EXERCISED` rather than passing without
//! having looked.
//!
//! Every value is generated here, at run time, and is never a real
//! credential. Assertions compare lengths, fingerprints and booleans; no
//! failure message prints a value. The workload is `dwk-sandbox-probe`'s
//! `sandbox_fixture` example, carried only in the evidence image.
//!
//! What this measures, and what it does not: that the value reaches the
//! program on descriptor 3 or in the operator's variable and in no argument,
//! runtime option, container record, event or log; that the program's
//! descendants inherit it (the residual ADR-0052 §7 states); that the output
//! is redacted of it as it is drained; and that every malformed handoff is
//! refused before anything runs. Redaction keeps the value from cognition
//! only against a program that does not transform it.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use dwk_proto as _;
#[cfg(target_os = "linux")]
use nix as _;
#[cfg(target_os = "linux")]
use zeroize as _;
// M5c's HTTPS client crates (ADR-0050 §18), reached only through the binary.
#[cfg(target_os = "linux")]
use bytes as _;
#[cfg(target_os = "linux")]
use rustls as _;
#[cfg(target_os = "linux")]
use ureq_proto as _;
#[cfg(target_os = "linux")]
use webpki_roots as _;
// D11 hardening's syscall filter (ADR-0053), reached only through the binary.
#[cfg(target_os = "linux")]
use libc as _;
#[cfg(target_os = "linux")]
use seccompiler as _;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::sandbox::{
        ContainerRef, EnvironmentProfile, ImageId, NetworkTopology, StoreInstance, Verdict,
    };
    use dwk_proto::brokerp::workload::{
        ImagePath, WorkloadCollectAuthorisation, WorkloadEnding, WorkloadLaunch, WorkloadProgress,
        WorkloadRunDone, WorkloadSeconds, WorkloadSecret, WorkloadSecretStartAuthorisation,
        WorkloadSpec, WorkloadStartAuthorisation,
    };
    use dwk_proto::brokerp::{
        Authorisation, BrokerDone, BrokerGeneration, BrokerHello, BrokerOutcome, BrokerRefusal,
        Common, EnvironmentDestroyAuthorisation, EnvironmentPrepareAuthorisation, EnvironmentSpec,
        Indeterminate, OutcomeResult, ProcessArgs, RuntimeSpec, SecretDelivery, SecretEnvName,
        SecretHandle, StreamLimit,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath, ProcessArg};
    use dwk_sandbox_profile as profile;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);
    const PEER_WAIT: Duration = Duration::from_secs(180);
    const SUITE: &str = "sandbox-secret";
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    const HANDLE: &str = "deploy-key";
    const PLACEHOLDER: &str = "[redacted:deploy-key]";
    const VARIABLE: &str = "GH_TOKEN";

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn evidence(case: &str, outcome: &str) {
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
    }

    fn own_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-secret-evidence`, which \
                 builds the evidence image and pins its digests"
            )
        })
    }

    /// A synthetic value: `len` printable bytes from the kernel's random
    /// source, never a real credential and never the same twice.
    fn synthetic(len: usize) -> Vec<u8> {
        let mut raw = vec![0u8; len];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut raw)
            .unwrap();
        raw.iter()
            .map(|b| {
                b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[usize::from(*b) % 57]
            })
            .collect()
    }

    /// The fixture's fingerprint of a value (FNV-1a, 64 bits).
    fn fnv(bytes: &[u8]) -> String {
        let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash: u64, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        format!("{hash:016x}")
    }

    /// Whether `haystack` holds `value`, raw or hex-encoded -- never printed.
    fn holds(haystack: &[u8], value: &[u8]) -> bool {
        let hex: Vec<u8> = value
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        [value, &hex[..]]
            .iter()
            .any(|needle| haystack.windows(needle.len()).any(|w| w == *needle))
    }

    #[derive(Clone)]
    struct Evidence {
        runtime: PathBuf,
        socket: String,
        image: String,
        probe_sha256: String,
        fixture_sha256: String,
    }

    impl Evidence {
        fn load() -> Self {
            Self {
                runtime: PathBuf::from(var("DW_SANDBOX_RUNTIME")),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_SANDBOX_WORKLOAD_IMAGE"),
                probe_sha256: var("DW_SANDBOX_PROBE_SHA256"),
                fixture_sha256: var("DW_SANDBOX_FIXTURE_SHA256"),
            }
        }

        fn client(&self) -> Command {
            let mut command = Command::new(&self.runtime);
            command
                .env_clear()
                .env("HOME", std::env::temp_dir())
                .arg("--host")
                .arg(format!("unix://{}", self.socket));
            command
        }

        /// The runtime client, run directly by this test -- to look, or to
        /// feed the launcher by hand -- never by the broker with these
        /// arguments.
        fn docker(&self, args: &[&str]) -> Output {
            self.client().args(args).output().unwrap()
        }

        /// The launcher, run directly with `stdin` as its standard input.
        fn launch_by_hand(&self, container: &str, words: &[&str], stdin: &[u8]) -> Output {
            let mut args = vec![
                "container",
                "exec",
                "--interactive",
                "--user",
                "10001:10001",
                container,
                profile::PROBE_PATH,
                profile::PROBE_LAUNCH,
            ];
            args.extend_from_slice(words);
            let mut child = self
                .client()
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let _ = input.write_all(stdin);
            drop(input);
            child.wait_with_output().unwrap()
        }

        fn remove(&self, container: &str) {
            let _ = self.docker(&["container", "rm", "--force", "--volumes", container]);
        }
    }

    /// Everything carrying this test process's store label, removed when it
    /// ends -- passing or failing.
    struct Reaper(Evidence);

    impl Drop for Reaper {
        fn drop(&mut self) {
            let labelled = self.0.docker(&[
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                &format!("label={}={}", profile::LABEL_STORE, store().as_str()),
            ]);
            for id in String::from_utf8_lossy(&labelled.stdout).lines() {
                self.0.remove(id);
            }
        }
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

        fn workspace(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
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
        stderr: Arc<Mutex<String>>,
    }

    impl Broker {
        fn start(socket: &Path, crash: Option<&str>) -> Self {
            let mut command = Command::new(BIN);
            command
                .env_clear()
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(own_uid().to_string())
                .arg("--allow-shared-authority-uid")
                .arg("--allow-evidence-topology")
                .arg("--allow-unverified-workspace");
            if let Some(point) = crash {
                command.env("DWKD_BROKER_CRASH_AT", point);
            }
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
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
                    return Self { child, stderr };
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "the broker exited:\n{}",
                    stderr.lock().unwrap()
                );
                assert!(Instant::now() < deadline, "the broker did not start");
            }
        }

        fn stderr(&self) -> String {
            self.stderr.lock().unwrap().clone()
        }

        /// Whether the broker process has ended (a crash point aborts it).
        fn ended(&mut self) -> bool {
            let deadline = Instant::now() + PROMPT;
            while Instant::now() < deadline {
                if self.child.try_wait().unwrap().is_some() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        }
    }

    impl Drop for Broker {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn uuid(n: u64) -> u128 {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let pid = u128::from(std::process::id());
        let n = u128::from(n);
        (ms << 80) | (0x7 << 76) | ((n & 0xfff) << 64) | (0b10 << 62) | ((n >> 12) << 32) | pid
    }

    fn next() -> u64 {
        UNIQUE.fetch_add(1, Ordering::SeqCst)
    }

    fn invocation() -> InvocationId {
        InvocationId::from_uuid(uuid(next())).unwrap()
    }

    fn store() -> StoreInstance {
        StoreInstance::new(format!("{:08x}", std::process::id() ^ 0x5d30_0000)).unwrap()
    }

    fn identity(path: &Path) -> (u64, u64) {
        let meta = std::fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    fn sha256(path: &Path) -> String {
        Sha256::digest(std::fs::read(path).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn runtime(ev: &Evidence) -> (RuntimeSpec, OwnedFd, OwnedFd) {
        let canonical = std::fs::canonicalize(&ev.runtime).unwrap();
        let exe = OwnedFd::from(std::fs::File::open(&canonical).unwrap());
        let cwd = OwnedFd::from(std::fs::File::open("/").unwrap());
        (
            RuntimeSpec {
                socket: HostPath::new(ev.socket.clone()).unwrap(),
                argv0: HostPath::new(canonical.display().to_string()).unwrap(),
                executable: identity(&canonical),
                sha256: ContentDigest::new(sha256(&canonical)).unwrap(),
                cwd: identity(Path::new("/")),
            },
            exe,
            cwd,
        )
    }

    fn spec(workspace: &Path, ev: &Evidence) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: EnvironmentId::from_uuid(uuid(next())).unwrap(),
            run_id: RunId::from_uuid(uuid(next())).unwrap(),
            store: store(),
            profile: EnvironmentProfile::OciStrict,
            network: NetworkTopology::NoNetwork,
            image: ImageId::new(ev.image.clone()).unwrap(),
            probe_sha256: ContentDigest::new(ev.probe_sha256.clone()).unwrap(),
            workspace_path: HostPath::new(workspace.display().to_string()).unwrap(),
            workspace: identity(workspace),
            // The evidence's own scratch directory: no group, no bound
            // proved (M5d.4), which this broker admits only because it
            // was started with --allow-unverified-workspace.
            workspace_bound: None,
            relay_sha256: None,
            egress: None,
        }
    }

    /// One exchange for `invocation`, sending exactly `fds`: the outcome, or
    /// `None` when no broker answers or it closes without one.
    fn try_exchange(
        socket: &Path,
        invocation: InvocationId,
        make: impl FnOnce(Common) -> Authorisation,
        fds: Vec<OwnedFd>,
    ) -> Option<OutcomeResult> {
        let mut stream = UnixStream::connect(socket).ok()?;
        stream.set_read_timeout(Some(PEER_WAIT)).unwrap();
        let mut decoder = FrameDecoder::new();
        let mut pending = Vec::new();
        let mut frame = |stream: &mut UnixStream| -> Option<Vec<u8>> {
            loop {
                if !pending.is_empty() {
                    let (used, frame) = decoder.feed(&pending).unwrap();
                    pending.drain(..used);
                    if let Some(frame) = frame {
                        return Some(frame.body);
                    }
                }
                let mut chunk = [0u8; 64 * 1024];
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                }
            }
        };
        let hello = BrokerHello::decode_frame_body(&frame(&mut stream)?).unwrap();
        let authorisation = make(Common::new(hello.channel.clone(), invocation));
        let bytes = authorisation.encode_frame().unwrap();
        let descriptors: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !descriptors.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        }
        let sent = rustix::net::sendmsg(
            &stream,
            &[IoSlice::new(&bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        stream.write_all(&bytes[sent..]).unwrap();
        drop(fds);
        let outcome = BrokerOutcome::decode_frame_body(&frame(&mut stream)?).unwrap();
        assert_eq!(outcome.channel, hello.channel);
        Some(outcome.result())
    }

    fn done(result: OutcomeResult) -> BrokerDone {
        match result {
            OutcomeResult::Done(done) => *done,
            other => panic!("not done: {other:?}"),
        }
    }

    fn refusal(result: Option<OutcomeResult>) -> BrokerRefusal {
        match result {
            Some(OutcomeResult::Refused(why)) => why,
            other => panic!("not refused: {other:?}"),
        }
    }

    fn prepared(socket: &Path, ev: &Evidence, workspace: &Path) -> (EnvironmentSpec, ContainerRef) {
        let s = spec(workspace, ev);
        let (runtime, exe, cwd) = runtime(ev);
        let sent = s.clone();
        let prepared = done(
            try_exchange(
                socket,
                invocation(),
                move |common| {
                    Authorisation::EnvironmentPrepare(EnvironmentPrepareAuthorisation::new(
                        common, sent, runtime,
                    ))
                },
                vec![exe, cwd],
            )
            .unwrap(),
        )
        .environment_prepare
        .unwrap();
        assert!(prepared.retained, "the environment measured clean");
        (s, prepared.container.unwrap())
    }

    fn destroy(socket: &Path, ev: &Evidence, s: &EnvironmentSpec, container: &ContainerRef) {
        let (runtime, exe, cwd) = runtime(ev);
        let ids = (s.environment_id.clone(), s.run_id.clone(), s.store.clone());
        let container = container.clone();
        let _ = try_exchange(
            socket,
            invocation(),
            move |common| {
                Authorisation::EnvironmentDestroy(EnvironmentDestroyAuthorisation::new(
                    common,
                    ids,
                    Some(container),
                    runtime,
                ))
            },
            vec![exe, cwd],
        );
    }

    fn workload(ev: &Evidence, args: &[&str], launch: WorkloadLaunch) -> WorkloadSpec {
        WorkloadSpec {
            executable: ImagePath::new(FIXTURE).unwrap(),
            executable_sha256: ContentDigest::new(ev.fixture_sha256.clone()).unwrap(),
            args: ProcessArgs::new(args.iter().map(|a| ProcessArg::new(*a).unwrap()).collect())
                .unwrap(),
            stream_limit: StreamLimit::new(65_536).unwrap(),
            wall_clock: WorkloadSeconds::new(60).unwrap(),
            launch,
        }
    }

    fn secret(delivery: SecretDelivery) -> WorkloadSecret {
        WorkloadSecret {
            handle: SecretHandle::new(HANDLE).unwrap(),
            delivery,
            env_name: (delivery == SecretDelivery::EnvAtSpawn)
                .then(|| SecretEnvName::new(VARIABLE).unwrap()),
        }
    }

    /// A pipe holding `value` and then end of file: what the authority's
    /// one-shot handoff is.
    fn pipe_of(value: &[u8]) -> OwnedFd {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(value).unwrap();
        drop(writer);
        OwnedFd::from(reader)
    }

    /// `broker.workload_secret_start` with exactly `fds` after the runtime's
    /// two: its answer, or `None`.
    fn try_secret_start(
        socket: &Path,
        ev: &Evidence,
        (s, container): (&EnvironmentSpec, &ContainerRef),
        (invocation, spec, secret): (InvocationId, WorkloadSpec, WorkloadSecret),
        extra: Vec<OwnedFd>,
    ) -> Option<OutcomeResult> {
        let (runtime, exe, cwd) = runtime(ev);
        let (s, container) = (s.clone(), container.clone());
        let mut fds = vec![exe, cwd];
        fds.extend(extra);
        try_exchange(
            socket,
            invocation,
            move |common| {
                Authorisation::WorkloadSecretStart(WorkloadSecretStartAuthorisation::new(
                    common,
                    s,
                    (container, runtime),
                    spec,
                    secret,
                ))
            },
            fds,
        )
    }

    fn try_collect(
        socket: &Path,
        invocation: &InvocationId,
        generation: &BrokerGeneration,
    ) -> Option<OutcomeResult> {
        let generation = generation.clone();
        try_exchange(
            socket,
            invocation.clone(),
            move |common| {
                Authorisation::WorkloadCollect(WorkloadCollectAuthorisation::new(
                    common, generation,
                ))
            },
            Vec::new(),
        )
    }

    /// Collections until it is no longer `RUNNING`: its ending.
    fn collected(
        socket: &Path,
        invocation: &InvocationId,
        generation: &BrokerGeneration,
    ) -> WorkloadRunDone {
        let deadline = Instant::now() + PEER_WAIT;
        loop {
            let answer = try_collect(socket, invocation, generation).expect("a collection");
            let collected = done(answer).workload_collect.unwrap();
            if collected.progress != WorkloadProgress::Running {
                return collected.result.expect("an ending, not a refusal");
            }
            assert!(Instant::now() < deadline, "the workload never ended");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A secret-bearing workload's whole run: its ending.
    fn ran(
        socket: &Path,
        ev: &Evidence,
        env: (&EnvironmentSpec, &ContainerRef),
        (args, launch, delivery): (&[&str], WorkloadLaunch, SecretDelivery),
        value: &[u8],
    ) -> WorkloadRunDone {
        let invocation = invocation();
        let answer = try_secret_start(
            socket,
            ev,
            env,
            (
                invocation.clone(),
                workload(ev, args, launch),
                secret(delivery),
            ),
            vec![pipe_of(value)],
        )
        .expect("no answer to a start");
        let generation = done(answer).workload_secret_start.unwrap().generation;
        collected(socket, &invocation, &generation)
    }

    fn text(done: &WorkloadRunDone) -> String {
        String::from_utf8(done.stdout.content.to_bytes()).unwrap()
    }

    fn line<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {key} in the fixture's report"))
    }

    /// Everything the runtime and its client record of `container`: its
    /// record, its log, and every event since `since`.
    fn runtime_records(ev: &Evidence, container: &ContainerRef, since: u64) -> Vec<u8> {
        let mut all = Vec::new();
        for args in [
            vec!["container", "inspect", container.as_str()],
            vec!["container", "logs", container.as_str()],
        ] {
            let out = ev.docker(&args);
            all.extend(out.stdout);
            all.extend(out.stderr);
        }
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1;
        let events = ev.docker(&[
            "events",
            "--since",
            &since.to_string(),
            "--until",
            &until.to_string(),
            "--format",
            "{{json .}}",
        ]);
        all.extend(events.stdout);
        all
    }

    fn now_s() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ---- mode C ------------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn a_descriptor_secret_reaches_the_program_on_descriptor_three_and_nowhere_else() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("fd");
        let socket = dir.socket();
        let broker = Broker::start(&socket, None);
        let (s, container) = prepared(&socket, &ev, &dir.workspace("ws"));
        let env = (&s, &container);
        let since = now_s().saturating_sub(1);
        let value = synthetic(40);

        let got = ran(
            &socket,
            &ev,
            env,
            (
                &["workload-secret-fd"],
                WorkloadLaunch::Direct,
                SecretDelivery::FdAtSpawn,
            ),
            &value,
        );
        assert_eq!(got.ending, WorkloadEnding::Exited);
        assert_eq!(got.exit_code.map(|c| c.get()), Some(0));
        let out = text(&got);
        assert_eq!(line(&out, "fd3"), "pipe");
        assert_eq!(line(&out, "len"), value.len().to_string());
        assert!(
            line(&out, "fnv") == fnv(&value),
            "a different value arrived"
        );
        evidence(
            "fd-at-spawn-delivers-exactly-the-value",
            "fd3=pipe len+fnv match",
        );
        assert_eq!(line(&out, "eof"), "1");
        evidence("fd-at-spawn-one-shot", "eof after the value");
        assert_eq!(line(&out, "stdin"), "/dev/null");
        evidence("fd-at-spawn-stdin-is-dev-null", "/dev/null");
        assert_eq!(line(&out, "fds"), "0,1,2,3");
        evidence("fd-at-spawn-only-descriptor-three", "0,1,2,3");
        assert_eq!(got.redactions.map(|c| c.get()), Some(0));
        assert_eq!(got.residue, Verdict::Pass);
        evidence("fd-at-spawn-residue-clean", "pass");

        // A descendant inherits descriptor 3: the residual, measured.
        let value2 = synthetic(32);
        let child = text(&ran(
            &socket,
            &ev,
            env,
            (
                &["workload-secret-fd-child"],
                WorkloadLaunch::Direct,
                SecretDelivery::FdAtSpawn,
            ),
            &value2,
        ));
        assert_eq!(line(&child, "parent_fd3"), "pipe");
        assert_eq!(line(&child, "child.fd3"), "pipe");
        assert!(line(&child, "child.fnv") == fnv(&value2));
        evidence(
            "fd-at-spawn-inherited-by-a-descendant",
            "child.fd3=pipe (residual)",
        );

        // The hygiene launcher composes with it: its variables, and fd 3.
        let value3 = synthetic(24);
        let hygienic = text(&ran(
            &socket,
            &ev,
            env,
            (
                &["workload-env"],
                WorkloadLaunch::Hygiene,
                SecretDelivery::FdAtSpawn,
            ),
            &value3,
        ));
        for (name, _) in profile::HYGIENE_ENVIRONMENT {
            assert!(
                line(&hygienic, "names").split(',').any(|n| n == *name),
                "{name}"
            );
        }
        evidence("fd-at-spawn-with-hygiene", "hygiene variables set");

        // In no argument, record, log or event of the runtime's, nor the
        // broker's own log.
        let records = runtime_records(&ev, &container, since);
        for v in [&value, &value2, &value3] {
            assert!(!holds(&records, v), "the runtime recorded a value");
            assert!(
                !holds(broker.stderr().as_bytes(), v),
                "the broker logged a value"
            );
        }
        assert!(
            String::from_utf8_lossy(&records).contains(profile::LAUNCH_SECRET_FD),
            "the events show the launcher's profile (argv is visible; the value is not)"
        );
        evidence("fd-at-spawn-not-in-inspect-logs-events-argv", "absent");
        assert!(broker.stderr().contains("secret=FD_AT_SPAWN"));
        evidence("broker-log-names-the-mode-only", "secret=FD_AT_SPAWN");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- mode B ------------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn an_environment_secret_reaches_the_program_as_its_variable_and_nowhere_else() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("env");
        let socket = dir.socket();
        let broker = Broker::start(&socket, None);
        let (s, container) = prepared(&socket, &ev, &dir.workspace("ws"));
        let env = (&s, &container);
        let since = now_s().saturating_sub(1);
        let value = synthetic(40);

        let got = ran(
            &socket,
            &ev,
            env,
            (
                &["workload-secret-env", VARIABLE],
                WorkloadLaunch::Direct,
                SecretDelivery::EnvAtSpawn,
            ),
            &value,
        );
        assert_eq!(got.exit_code.map(|c| c.get()), Some(0));
        let out = text(&got);
        assert_eq!(line(&out, "set"), "1");
        assert_eq!(line(&out, "len"), value.len().to_string());
        assert!(
            line(&out, "fnv") == fnv(&value),
            "a different value arrived"
        );
        evidence("env-at-spawn-delivers-exactly-the-value", "len+fnv match");
        let names: Vec<&str> = line(&out, "names").split(',').collect();
        assert!(names.contains(&VARIABLE));
        for name in &names {
            assert!(
                ["PATH", "HOSTNAME", "HOME", VARIABLE].contains(name),
                "an unexpected variable: {name}"
            );
        }
        evidence("env-at-spawn-only-its-variable-added", &names.join("+"));
        assert_eq!(line(&out, "stdin"), "/dev/null");
        assert_eq!(line(&out, "fds"), "0,1,2");
        evidence("env-at-spawn-no-extra-descriptor", "0,1,2");

        let value2 = synthetic(32);
        let child = text(&ran(
            &socket,
            &ev,
            env,
            (
                &["workload-secret-env-child", VARIABLE],
                WorkloadLaunch::Direct,
                SecretDelivery::EnvAtSpawn,
            ),
            &value2,
        ));
        assert_eq!(line(&child, "child.set"), "1");
        assert!(line(&child, "child.fnv") == fnv(&value2));
        evidence(
            "env-at-spawn-inherited-by-a-descendant",
            "child.set=1 (residual)",
        );

        let value3 = synthetic(24);
        let hygienic = text(&ran(
            &socket,
            &ev,
            env,
            (
                &["workload-secret-env", VARIABLE],
                WorkloadLaunch::Hygiene,
                SecretDelivery::EnvAtSpawn,
            ),
            &value3,
        ));
        assert!(line(&hygienic, "fnv") == fnv(&value3));
        for (name, _) in profile::HYGIENE_ENVIRONMENT {
            assert!(
                line(&hygienic, "names").split(',').any(|n| n == *name),
                "{name}"
            );
        }
        evidence("env-at-spawn-with-hygiene", "variable and hygiene set");

        let records = runtime_records(&ev, &container, since);
        for v in [&value, &value2, &value3] {
            assert!(!holds(&records, v), "the runtime recorded a value");
            assert!(
                !holds(broker.stderr().as_bytes(), v),
                "the broker logged a value"
            );
        }
        let text = String::from_utf8_lossy(&records);
        assert!(
            !text.contains("--env"),
            "a value option reached the runtime"
        );
        evidence(
            "env-at-spawn-not-in-inspect-logs-events-argv",
            "absent; no --env",
        );
        destroy(&socket, &ev, &s, &container);
    }

    // ---- the return path ---------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn the_output_is_redacted_of_the_value_even_split_across_reads() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("redact");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let (s, container) = prepared(&socket, &ev, &dir.workspace("ws"));
        let env = (&s, &container);
        for (args, delivery, case) in [
            (
                &["workload-echo-fd", "5"][..],
                SecretDelivery::FdAtSpawn,
                "fd",
            ),
            (
                &["workload-echo-env", VARIABLE, "5"][..],
                SecretDelivery::EnvAtSpawn,
                "env",
            ),
        ] {
            let value = synthetic(48);
            let got = ran(
                &socket,
                &ev,
                env,
                (args, WorkloadLaunch::Direct, delivery),
                &value,
            );
            assert_eq!(got.exit_code.map(|c| c.get()), Some(0));
            let stdout = got.stdout.content.to_bytes();
            let stderr = got.stderr.content.to_bytes();
            assert!(
                !holds(&stdout, &value) && !holds(&stderr, &value),
                "{case}: a value came back"
            );
            let count = |bytes: &[u8]| String::from_utf8_lossy(bytes).matches(PLACEHOLDER).count();
            assert_eq!(count(&stdout), 5, "{case}");
            assert_eq!(count(&stderr), 1, "{case}");
            assert_eq!(got.redactions.map(|c| c.get()), Some(6), "{case}");
            evidence(
                &format!("redacted-across-reads-{case}"),
                "6 occurrences, 0 bytes back",
            );
        }
        destroy(&socket, &ev, &s, &container);
    }

    // ---- refusals ----------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn every_malformed_handoff_is_refused_and_the_value_is_read_only_after_the_judgement() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("refuse");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let (s, container) = prepared(&socket, &ev, &dir.workspace("ws"));
        let env = (&s, &container);
        let fd = || {
            (
                invocation(),
                workload(&ev, &["workload-secret-fd"], WorkloadLaunch::Direct),
                secret(SecretDelivery::FdAtSpawn),
            )
        };
        // Not a pipe; a pipe's write end; a pipe its writer still holds; an
        // empty one; one past the shared bound.
        let file = OwnedFd::from(std::fs::File::open("/proc/self/status").unwrap());
        assert_eq!(
            refusal(try_secret_start(&socket, &ev, env, fd(), vec![file])),
            BrokerRefusal::SecretDescriptor
        );
        evidence("refused-not-a-pipe", "SECRET_DESCRIPTOR");
        let (reader, writer) = std::io::pipe().unwrap();
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                fd(),
                vec![OwnedFd::from(writer)]
            )),
            BrokerRefusal::SecretDescriptor
        );
        evidence("refused-a-write-end", "SECRET_DESCRIPTOR");
        let (held, mut open_writer) = std::io::pipe().unwrap();
        open_writer.write_all(b"partial").unwrap();
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                fd(),
                vec![OwnedFd::from(held)]
            )),
            BrokerRefusal::SecretDescriptor
        );
        drop((reader, open_writer));
        evidence("refused-a-stalled-pipe", "SECRET_DESCRIPTOR");
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                fd(),
                vec![pipe_of(b"")]
            )),
            BrokerRefusal::SecretEmpty
        );
        evidence("refused-empty", "SECRET_EMPTY");
        let big = synthetic(dwk_proto::brokerp::MAX_SECRET_BYTES + 1);
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                fd(),
                vec![pipe_of(&big)]
            )),
            BrokerRefusal::SecretTooLarge
        );
        evidence("refused-past-32-kib", "SECRET_TOO_LARGE");
        let env_start = (
            invocation(),
            workload(
                &ev,
                &["workload-secret-env", VARIABLE],
                WorkloadLaunch::Direct,
            ),
            secret(SecretDelivery::EnvAtSpawn),
        );
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                env_start,
                vec![pipe_of(b"a\0b")]
            )),
            BrokerRefusal::SecretUnsafeBytes
        );
        evidence("refused-nul-in-a-variable", "SECRET_UNSAFE_BYTES");
        // Exactly three descriptors.
        assert_eq!(
            refusal(try_secret_start(&socket, &ev, env, fd(), Vec::new())),
            BrokerRefusal::DescriptorCount
        );
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                fd(),
                vec![pipe_of(b"one"), pipe_of(b"two")]
            )),
            BrokerRefusal::DescriptorCount
        );
        evidence("refused-not-three-descriptors", "DESCRIPTOR_COUNT");
        // The executable is proved first: one the manifest does not pin is
        // refused, and the value is still unread in its pipe.
        let value = synthetic(40);
        let (kept, mut writer) = std::io::pipe().unwrap();
        writer.write_all(&value).unwrap();
        drop(writer);
        let sent = OwnedFd::from(kept.try_clone().unwrap());
        let mut wrong = workload(&ev, &["workload-secret-fd"], WorkloadLaunch::Direct);
        wrong.executable_sha256 = ContentDigest::new("ab".repeat(32)).unwrap();
        assert_eq!(
            refusal(try_secret_start(
                &socket,
                &ev,
                env,
                (invocation(), wrong, secret(SecretDelivery::FdAtSpawn)),
                vec![sent],
            )),
            BrokerRefusal::DigestMismatch
        );
        let mut left = Vec::new();
        std::io::PipeReader::from(OwnedFd::from(kept))
            .read_to_end(&mut left)
            .unwrap();
        assert!(left == value, "the broker read the value before judging");
        evidence("value-unread-when-the-judgement-refuses", "pipe still full");
        // A running workload is collected only under its own generation.
        let value = synthetic(16);
        let invocation = invocation();
        let started = done(
            try_secret_start(
                &socket,
                &ev,
                env,
                (
                    invocation.clone(),
                    workload(&ev, &["workload-secret-fd"], WorkloadLaunch::Direct),
                    secret(SecretDelivery::FdAtSpawn),
                ),
                vec![pipe_of(&value)],
            )
            .unwrap(),
        )
        .workload_secret_start
        .unwrap();
        let other = BrokerGeneration::new("f".repeat(32)).unwrap();
        assert_eq!(
            try_collect(&socket, &invocation, &other),
            Some(OutcomeResult::Indeterminate(
                Indeterminate::WorkloadUnconfirmed
            ))
        );
        let ended = collected(&socket, &invocation, &started.generation);
        assert_eq!(ended.residue, Verdict::Pass);
        evidence(
            "collected-only-under-its-generation",
            "other generation unconfirmed",
        );
        // An ordinary start is unchanged: no descriptor 3, no redaction count.
        let (runtime, exe, cwd) = runtime(&ev);
        let (s2, c2) = (s.clone(), container.clone());
        let plain = invocation_ordinary(&socket, (runtime, exe, cwd), (s2, c2), &ev);
        let out = text(&plain);
        assert_eq!(line(&out, "fd3"), "absent");
        // M5d.4: the `direct` launcher in front of it changes none of that --
        // standard input `/dev/null`, exactly the three standard descriptors.
        assert_eq!(line(&out, "stdin"), "/dev/null");
        assert_eq!(line(&out, "fds"), "0,1,2");
        assert_eq!(plain.redactions, None);
        evidence("an-ordinary-workload-is-unchanged", "fd3 absent, no count");
        destroy(&socket, &ev, &s, &container);
    }

    /// An ordinary `broker.workload_start` of the fixture's descriptor
    /// report: its ending.
    fn invocation_ordinary(
        socket: &Path,
        (runtime, exe, cwd): (RuntimeSpec, OwnedFd, OwnedFd),
        (s, container): (EnvironmentSpec, ContainerRef),
        ev: &Evidence,
    ) -> WorkloadRunDone {
        let invocation = invocation();
        let spec = workload(ev, &["workload-secret-fd"], WorkloadLaunch::Direct);
        let answer = try_exchange(
            socket,
            invocation.clone(),
            move |common| {
                Authorisation::WorkloadStart(WorkloadStartAuthorisation::new(
                    common, s, container, runtime, spec,
                ))
            },
            vec![exe, cwd],
        )
        .unwrap();
        let generation = done(answer).workload_start.unwrap().generation;
        collected(socket, &invocation, &generation)
    }

    // ---- the launcher ------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn the_launcher_runs_nothing_for_a_frame_or_a_name_it_does_not_accept() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("launcher");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let (s, container) = prepared(&socket, &ev, &dir.workspace("ws"));
        let value = synthetic(20);
        let frame = |value: &[u8]| {
            let mut bytes = u32::try_from(value.len()).unwrap().to_be_bytes().to_vec();
            bytes.extend_from_slice(value);
            bytes
        };
        let fd_words = [profile::LAUNCH_SECRET_FD, FIXTURE, "workload-secret-fd"];
        // The well-formed frame runs the program, with the value on fd 3.
        let ok = ev.launch_by_hand(container.as_str(), &fd_words, &frame(&value));
        assert!(ok.status.success());
        let out = String::from_utf8_lossy(&ok.stdout).into_owned();
        assert!(line(&out, "fnv") == fnv(&value));
        evidence("launcher-accepts-one-exact-frame", "ran");
        let too_long = {
            let mut bytes = 32_769u32.to_be_bytes().to_vec();
            bytes.extend(synthetic(32_769));
            bytes
        };
        let mut extra = frame(&value);
        extra.push(b'x');
        let mut short = frame(&value);
        short.pop();
        for (case, input) in [
            ("nothing", Vec::new()),
            ("a short prefix", vec![0, 0]),
            ("length zero", 0u32.to_be_bytes().to_vec()),
            ("past 32 KiB", too_long),
            ("a byte short", short),
            ("a byte more", extra),
        ] {
            let refused = ev.launch_by_hand(container.as_str(), &fd_words, &input);
            assert_eq!(
                refused.status.code(),
                Some(i32::from(profile::LAUNCH_FAILED)),
                "{case}"
            );
            assert!(refused.stdout.is_empty(), "{case}: the program ran");
        }
        evidence("launcher-refuses-every-other-frame", "127, nothing ran");
        for (case, words) in [
            (
                "a proxy variable",
                vec![
                    profile::LAUNCH_SECRET_ENV,
                    "HTTPS_PROXY",
                    FIXTURE,
                    "workload-env",
                ],
            ),
            (
                "a hygiene variable",
                vec![
                    profile::LAUNCH_SECRET_ENV,
                    "GIT_CONFIG_GLOBAL",
                    FIXTURE,
                    "workload-env",
                ],
            ),
            (
                "a control variable",
                vec![
                    profile::LAUNCH_SECRET_ENV,
                    "LD_PRELOAD",
                    FIXTURE,
                    "workload-env",
                ],
            ),
            (
                "PATH",
                vec![profile::LAUNCH_SECRET_ENV, "PATH", FIXTURE, "workload-env"],
            ),
            (
                "a relative program",
                vec![profile::LAUNCH_SECRET_FD, "sandbox-fixture", "workload-env"],
            ),
            (
                "an unknown profile",
                vec!["secret-stdin", FIXTURE, "workload-env"],
            ),
        ] {
            let refused = ev.launch_by_hand(container.as_str(), &words, &frame(&value));
            assert_eq!(
                refused.status.code(),
                Some(i32::from(profile::LAUNCH_FAILED)),
                "{case}"
            );
            assert!(refused.stdout.is_empty(), "{case}: the program ran");
        }
        evidence(
            "launcher-refuses-reserved-names-and-bad-words",
            "127, nothing ran",
        );
        destroy(&socket, &ev, &s, &container);
    }

    // ---- a crash after the read --------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn a_broker_that_stops_after_reading_the_value_runs_nothing() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("crash");
        let socket = dir.socket();
        let workspace = dir.workspace("ws");
        let (s, container) = {
            let _broker = Broker::start(&socket, None);
            prepared(&socket, &ev, &workspace)
        };
        let mut broker = Broker::start(&socket, Some("workload_secret_after_read"));
        let value = synthetic(40);
        let answer = try_secret_start(
            &socket,
            &ev,
            (&s, &container),
            (
                invocation(),
                workload(&ev, &["workload-secret-fd"], WorkloadLaunch::Direct),
                secret(SecretDelivery::FdAtSpawn),
            ),
            vec![pipe_of(&value)],
        );
        assert!(answer.is_none(), "an answer from a broker that stopped");
        assert!(broker.ended(), "the crash point was not reached");
        assert!(
            broker
                .stderr()
                .contains("crash_point point=workload_secret_after_read")
        );
        // Nothing ran in the environment: only its init is there.
        let ps = ev.docker(&["container", "top", container.as_str(), "-o", "args"]);
        let listing = String::from_utf8_lossy(&ps.stdout).into_owned();
        assert!(
            !listing.contains("workload-secret-fd"),
            "the program ran:\n{listing}"
        );
        assert!(!holds(listing.as_bytes(), &value));
        evidence("crash-after-read-nothing-ran", "init only");
        drop(broker);
        let _broker = Broker::start(&socket, None);
        destroy(&socket, &ev, &s, &container);
    }
}
