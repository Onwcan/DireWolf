//! M5d.1's real-container evidence at the broker (ADR-0052 §§5, 13, 17):
//! the released `dwkd-broker` running **workloads** in a **real** OCI
//! environment it prepared, through its **real** runtime client, with this
//! test process playing the authority.
//!
//! Every test here is `#[ignore]`d: it needs a runtime, the evidence image
//! (the probe, and the sandbox fixture as the workload) and the pinned
//! digests, which `make sandbox-workload-evidence` builds and passes in
//! (`DW_SANDBOX_*`). Run any other way, a test panics with `NOT EXERCISED`
//! rather than passing without having looked.
//!
//! The workload is `dwk-sandbox-probe`'s `sandbox_fixture` example — a test
//! fixture carried only in the evidence's image, never shipped — in its
//! `workload-*` modes. The few containers or changes this suite makes itself
//! (a foreign container, a drifted limit, a stopped environment) are made
//! with the runtime's client directly, by this test process: the broker
//! never makes one, so a refusal of one can only be shown on a container
//! someone else touched. Every one is removed before its test ends.

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

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, OwnedFd};
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
        ImagePath, WorkloadEnding, WorkloadRunAuthorisation, WorkloadRunDone, WorkloadSeconds,
        WorkloadSpec,
    };
    use dwk_proto::brokerp::{
        Authorisation, BrokerDone, BrokerHello, BrokerOutcome, BrokerRefusal, Common,
        EnvironmentDestroyAuthorisation, EnvironmentPrepareAuthorisation, EnvironmentSpec,
        OutcomeResult, ProcessArgs, RuntimeSpec, StreamLimit,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath, ProcessArg};
    use dwk_sandbox_profile as profile;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);
    /// Longer than any workload these tests run, its judgement and `reap`.
    const PEER_WAIT: Duration = Duration::from_secs(180);
    const SUITE: &str = "sandbox-workload";
    /// Where the evidence image carries the workload fixture.
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";

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
                "NOT EXERCISED: {name} is not set; run `make sandbox-workload-evidence`, which \
                 builds the evidence image and pins its digests"
            )
        })
    }

    /// What the evidence task built and pinned.
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

        /// The runtime client, run directly by this test — never by the
        /// broker with these arguments.
        fn docker(&self, args: &[&str]) -> Output {
            Command::new(&self.runtime)
                .env_clear()
                .env("HOME", std::env::temp_dir())
                .arg("--host")
                .arg(format!("unix://{}", self.socket))
                .args(args)
                .output()
                .unwrap()
        }

        fn docker_ok(&self, args: &[&str]) -> String {
            let out = self.docker(args);
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        }

        fn exists(&self, container: &str) -> bool {
            self.docker(&["container", "inspect", "--format", "{{.Id}}", container])
                .status
                .success()
        }

        fn remove(&self, container: &str) {
            let _ = self.docker(&["container", "rm", "--force", "--volumes", container]);
        }

        /// The fixture's `mode`, run directly in `container` by this test —
        /// to look, never as the workload under test.
        fn look(&self, container: &str, mode: &[&str]) -> String {
            let mut args = vec!["container", "exec", container, FIXTURE];
            args.extend_from_slice(mode);
            String::from_utf8_lossy(&self.docker(&args).stdout).into_owned()
        }
    }

    /// Containers this test process made without its store's labels.
    static CREATED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Everything a test made or had made, removed when it ends — passing
    /// or failing: everything carrying this test process's store label, and
    /// the unlabelled containers it recorded. Nothing else is touched.
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
            let mut ids: Vec<String> = String::from_utf8_lossy(&labelled.stdout)
                .lines()
                .map(str::to_owned)
                .collect();
            ids.extend(
                CREATED
                    .lock()
                    .map(|mut c| std::mem::take(&mut *c))
                    .unwrap_or_default(),
            );
            for id in ids {
                self.0.remove(&id);
            }
        }
    }

    /// A private scratch directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("dww-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("ipc").join("broker.sock")
        }

        /// A workspace the environment's user can write: the evidence's own.
        /// The production ownership model is M5d.4's (ADR-0052 §6).
        fn workspace(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // The workload's files are uid 10001's; the directory is ours and
            // world-writable, so they can be removed by name.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The released broker, killed when dropped.
    struct Broker {
        child: Child,
        stderr: Arc<Mutex<String>>,
    }

    impl Broker {
        fn command(socket: &Path, authority_uid: u32, extra: &[&str]) -> Command {
            let mut command = Command::new(BIN);
            command.env_clear();
            command
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(authority_uid.to_string())
                .arg("--allow-shared-authority-uid")
                .args(extra);
            command
        }

        fn start(socket: &Path, crash: Option<&str>) -> Self {
            let mut command = Self::command(socket, own_uid(), &["--allow-evidence-topology"]);
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

    /// A broker that must refuse to serve: its exit status and stderr.
    fn refused_broker(socket: &Path, authority_uid: u32) -> (Option<i32>, String) {
        let out = Broker::command(socket, authority_uid, &[])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
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

    fn environment() -> EnvironmentId {
        EnvironmentId::from_uuid(uuid(next())).unwrap()
    }

    fn run() -> RunId {
        RunId::from_uuid(uuid(next())).unwrap()
    }

    /// This test process's store: distinct from any other run's.
    fn store() -> StoreInstance {
        StoreInstance::new(format!("{:08x}", std::process::id() ^ 0x5d00_0000)).unwrap()
    }

    fn identity(path: &Path) -> (u64, u64) {
        let meta = std::fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    fn sha256(path: &Path) -> String {
        let bytes = std::fs::read(path).unwrap();
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// What the authority would hand over: the client and `/`.
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

    fn spec(
        environment: &EnvironmentId,
        run: &RunId,
        workspace: &Path,
        ev: &Evidence,
    ) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: environment.clone(),
            run_id: run.clone(),
            store: store(),
            profile: EnvironmentProfile::OciStrict,
            network: NetworkTopology::NoNetwork,
            image: ImageId::new(ev.image.clone()).unwrap(),
            probe_sha256: ContentDigest::new(ev.probe_sha256.clone()).unwrap(),
            workspace_path: HostPath::new(workspace.display().to_string()).unwrap(),
            workspace: identity(workspace),
            relay_sha256: None,
            egress: None,
        }
    }

    /// One exchange: hello, the authorisation `make` builds with its two
    /// descriptors, the outcome — or `None` when the broker closes the
    /// connection without one.
    fn try_exchange(
        socket: &Path,
        make: impl FnOnce(Common) -> Authorisation,
        fds: (OwnedFd, OwnedFd),
    ) -> Option<OutcomeResult> {
        let mut stream = UnixStream::connect(socket).unwrap();
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
        let authorisation = make(Common::new(hello.channel.clone(), invocation()));
        let bytes = authorisation.encode_frame().unwrap();
        let descriptors = [fds.0.as_fd(), fds.1.as_fd()];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
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

    fn exchange(
        socket: &Path,
        make: impl FnOnce(Common) -> Authorisation,
        fds: (OwnedFd, OwnedFd),
    ) -> OutcomeResult {
        try_exchange(socket, make, fds).expect("the broker closed without an answer")
    }

    fn done(result: OutcomeResult) -> BrokerDone {
        match result {
            OutcomeResult::Done(done) => *done,
            other => panic!("not done: {other:?}"),
        }
    }

    fn refusal(result: OutcomeResult) -> BrokerRefusal {
        match result {
            OutcomeResult::Refused(why) => why,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// A clean `NO_NETWORK` environment for `workspace`, prepared by the
    /// broker: its spec and container.
    fn prepared(socket: &Path, ev: &Evidence, workspace: &Path) -> (EnvironmentSpec, ContainerRef) {
        let s = spec(&environment(), &run(), workspace, ev);
        let (runtime, exe, cwd) = runtime(ev);
        let sent = s.clone();
        let prepared = done(exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentPrepare(EnvironmentPrepareAuthorisation::new(
                    common, sent, runtime,
                ))
            },
            (exe, cwd),
        ))
        .environment_prepare
        .unwrap();
        assert!(prepared.retained, "the environment measured clean");
        (s, prepared.container.unwrap())
    }

    fn destroy(socket: &Path, ev: &Evidence, s: &EnvironmentSpec, container: &ContainerRef) {
        let (runtime, exe, cwd) = runtime(ev);
        let ids = (s.environment_id.clone(), s.run_id.clone(), s.store.clone());
        let container = container.clone();
        let _ = done(exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentDestroy(EnvironmentDestroyAuthorisation::new(
                    common,
                    ids,
                    Some(container),
                    runtime,
                ))
            },
            (exe, cwd),
        ));
    }

    /// The workload: the fixture at `executable` with `sha256`, `args`, a
    /// per-stream bound and a wall clock.
    fn workload(
        (executable, sha256): (&str, &str),
        args: &[&str],
        limit: u32,
        wall_clock: u32,
    ) -> WorkloadSpec {
        WorkloadSpec {
            executable: ImagePath::new(executable).unwrap(),
            executable_sha256: ContentDigest::new(sha256.to_owned()).unwrap(),
            args: ProcessArgs::new(args.iter().map(|a| ProcessArg::new(*a).unwrap()).collect())
                .unwrap(),
            stream_limit: StreamLimit::new(limit).unwrap(),
            wall_clock: WorkloadSeconds::new(wall_clock).unwrap(),
        }
    }

    fn try_run(
        socket: &Path,
        ev: &Evidence,
        (s, container): (&EnvironmentSpec, &ContainerRef),
        spec: WorkloadSpec,
    ) -> Option<OutcomeResult> {
        let (runtime, exe, cwd) = runtime(ev);
        let (s, container) = (s.clone(), container.clone());
        try_exchange(
            socket,
            move |common| {
                Authorisation::WorkloadRun(WorkloadRunAuthorisation::new(
                    common, s, container, runtime, spec,
                ))
            },
            (exe, cwd),
        )
    }

    fn run_workload(
        socket: &Path,
        ev: &Evidence,
        env: (&EnvironmentSpec, &ContainerRef),
        spec: WorkloadSpec,
    ) -> OutcomeResult {
        try_run(socket, ev, env, spec).expect("the broker closed without an answer")
    }

    /// A fixture run that must have completed: its answer.
    fn ran(
        socket: &Path,
        ev: &Evidence,
        env: (&EnvironmentSpec, &ContainerRef),
        args: &[&str],
    ) -> WorkloadRunDone {
        let answer = run_workload(
            socket,
            ev,
            env,
            workload((FIXTURE, &ev.fixture_sha256), args, 65_536, 60),
        );
        done(answer).workload_run.unwrap()
    }

    fn text(done: &WorkloadRunDone) -> String {
        String::from_utf8(done.stdout.content.to_bytes()).unwrap()
    }

    fn line<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {key} in:\n{text}"))
    }

    // ---- who it runs as, and with what ------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_workload_runs_as_the_environment_user_with_exactly_its_arguments() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("ident");
        let socket = dir.socket();
        let broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);

        let identity = ran(&socket, &ev, env, &["workload-identity"]);
        assert_eq!(identity.ending, WorkloadEnding::Exited);
        assert_eq!(identity.exit_code.map(|c| c.get()), Some(0));
        let out = text(&identity);
        assert!(line(&out, "uid").split(',').all(|u| u == "10001"), "{out}");
        assert!(line(&out, "gid").split(',').all(|g| g == "10001"), "{out}");
        evidence("workload-runs-as-uid-10001", "uid=gid=10001");
        assert_eq!(line(&out, "capeff"), "0000000000000000", "{out}");
        assert_eq!(line(&out, "capprm"), "0000000000000000", "{out}");
        evidence("workload-no-capabilities", "capeff=0");
        assert_eq!(line(&out, "nonewprivs"), "1", "{out}");
        evidence("workload-no-new-privileges", "1");
        assert_eq!(line(&out, "seccomp"), "2", "{out}");
        evidence("workload-seccomp-filter", "2");
        assert_eq!(line(&out, "cwd"), "/workspace", "{out}");
        evidence("workload-cwd-workspace", "/workspace");
        assert_eq!(identity.residue, Verdict::Pass);
        assert_eq!(identity.remaining_processes.get(), 0);
        evidence("workload-residue-clean", "pass");

        // Flags after the executable are the program's bytes, never the
        // runtime client's options.
        let hostile = [
            "--user",
            "0:0",
            "--privileged",
            "-e",
            "LD_PRELOAD=/x.so",
            "$(id)",
            "a b",
            "",
        ];
        let mut args = vec!["workload-args"];
        args.extend_from_slice(&hostile);
        let echoed = text(&ran(&socket, &ev, env, &args));
        let mut expected = format!("argc={}", hostile.len());
        for arg in hostile {
            expected.push('\n');
            expected.push_str(&if arg.is_empty() {
                "-".to_owned()
            } else {
                arg.bytes().map(|b| format!("{b:02x}")).collect::<String>()
            });
        }
        assert_eq!(echoed.trim_end(), expected);
        evidence("workload-arguments-exact-bytes", "echoed");
        let mut args = vec!["workload-identity"];
        args.extend_from_slice(&hostile);
        let still = text(&ran(&socket, &ev, env, &args));
        assert!(line(&still, "uid").split(',').all(|u| u == "10001"));
        assert_eq!(line(&still, "capeff"), "0000000000000000");
        evidence("workload-flags-in-arguments-inert", "uid=10001 capeff=0");

        // Its environment is the container's, never the broker's.
        let names = text(&ran(&socket, &ev, env, &["workload-env"]));
        let names: Vec<&str> = line(&names, "names")
            .split(',')
            .filter(|n| !n.is_empty())
            .collect();
        for name in &names {
            assert!(
                ["PATH", "HOSTNAME", "HOME"].contains(name),
                "an unexpected variable: {name} in {names:?}"
            );
        }
        evidence("workload-environment-container-only", &names.join("+"));

        // How it ended, as the runtime and the container say.
        let exited = ran(&socket, &ev, env, &["workload-exit", "3"]);
        assert_eq!(exited.ending, WorkloadEnding::Exited);
        assert_eq!(exited.exit_code.map(|c| c.get()), Some(3));
        evidence("workload-exit-code", "3");
        let killed = ran(&socket, &ev, env, &["workload-kill-self"]);
        assert_eq!(killed.ending, WorkloadEnding::Killed);
        assert_eq!(killed.signal.map(|s| s.get()), Some(9));
        evidence("workload-killed-by-signal", "9");
        let ambiguous = ran(&socket, &ev, env, &["workload-exit", "125"]);
        assert_eq!(ambiguous.ending, WorkloadEnding::Unobservable);
        evidence("workload-ambiguous-exit-unobservable", "125");
        // The broker's log names how it ended and how much it wrote, never
        // what it wrote.
        let log = broker.stderr();
        assert!(log.contains("event=workload_ended"), "{log}");
        assert!(!log.contains("LD_PRELOAD"), "an argument reached the log");
        assert!(
            !log.contains("ooooo") && !log.contains("eeeee"),
            "output reached the log"
        );
        evidence("workload-log-has-no-argument-or-output", "lengths-only");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- bounds ------------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn output_and_the_wall_clock_are_bounded_and_a_timed_out_workload_is_ended() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("bounds");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);

        let flood = done(run_workload(
            &socket,
            &ev,
            env,
            workload(
                (FIXTURE, &ev.fixture_sha256),
                &["workload-print", "300000", "200000"],
                4096,
                60,
            ),
        ))
        .workload_run
        .unwrap();
        assert_eq!(flood.stdout.content.to_bytes().len(), 4096);
        assert_eq!(flood.stderr.content.to_bytes().len(), 4096);
        assert!(flood.stdout.truncated && flood.stderr.truncated);
        evidence("workload-output-bounded", "4096+4096");
        assert_eq!(flood.stdout.observed.get(), 300_000);
        assert_eq!(flood.stderr.observed.get(), 200_000);
        evidence("workload-output-counted", "300000+200000");

        let since = Instant::now();
        let slow = done(run_workload(
            &socket,
            &ev,
            env,
            workload(
                (FIXTURE, &ev.fixture_sha256),
                &["workload-sleep", "600"],
                4096,
                3,
            ),
        ))
        .workload_run
        .unwrap();
        assert_eq!(slow.ending, WorkloadEnding::TimedOut);
        // The workload's own clock, as the broker measured it: it ran its
        // three seconds and was ended then — not at a later deadline.
        let ran = slow.elapsed_ms.get();
        assert!((2_900..6_000).contains(&ran), "elapsed {ran} ms");
        assert!(
            since.elapsed() < Duration::from_secs(60),
            "{:?}",
            since.elapsed()
        );
        evidence("workload-wall-clock-timed-out", "3s");
        // The runtime kept the `exec`'d process when its client died; `reap`
        // ended it.
        assert_eq!(slow.residue, Verdict::Pass);
        assert!(slow.ended_processes.get() >= 1, "{slow:?}");
        let left = ev.look(container.as_str(), &["workload-ps"]);
        assert_eq!(line(&left, "others"), "1", "init alone: {left}");
        evidence("workload-timed-out-reaped", "init-alone");

        // A child left holding the output open: the runtime ends the `exec`
        // when the program exits (measured: it does not wait for the
        // stream), and `reap` ends the child.
        let held = done(run_workload(
            &socket,
            &ev,
            env,
            workload(
                (FIXTURE, &ev.fixture_sha256),
                &["workload-hold-stdout"],
                4096,
                30,
            ),
        ))
        .workload_run
        .unwrap();
        assert_eq!(held.ending, WorkloadEnding::Exited, "{held:?}");
        assert_eq!(held.exit_code.map(|c| c.get()), Some(0));
        assert!(held.ended_processes.get() >= 1, "{held:?}");
        assert_eq!(held.residue, Verdict::Pass);
        let left = ev.look(container.as_str(), &["workload-ps"]);
        assert_eq!(line(&left, "others"), "1", "{left}");
        evidence(
            "workload-output-held-open-child-reaped",
            "exited-child-reaped",
        );
        destroy(&socket, &ev, &s, &container);
    }

    // ---- what it leaves ----------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_process_tree_is_ended_whatever_it_did_to_leave() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("tree");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);

        let tree = ran(&socket, &ev, env, &["workload-tree"]);
        assert_eq!(tree.exit_code.map(|c| c.get()), Some(0));
        assert_eq!(line(&text(&tree), "spawned"), "3");
        // A child, a process in its own session, a daemon and its child.
        assert!(tree.ended_processes.get() >= 3, "{tree:?}");
        assert_eq!(tree.residue, Verdict::Pass);
        assert_eq!(tree.remaining_processes.get(), 0);
        evidence("workload-tree-reaped", "child");
        evidence("workload-setsid-reaped", "own-session");
        evidence("workload-daemon-reaped", "orphaned-to-init");
        let left = ev.look(container.as_str(), &["workload-ps"]);
        assert_eq!(line(&left, "others"), "1", "{left}");
        assert!(!line(&left, "pids").contains(":Z"), "a zombie: {left}");
        evidence("workload-nothing-persists", "init-alone");
        evidence("workload-no-zombies", "init-reaped");

        let looped = ran(&socket, &ev, env, &["workload-fork-loop", "60"]);
        assert_eq!(line(&text(&looped), "spawned"), "60");
        assert!(looped.ended_processes.get() >= 60, "{looped:?}");
        assert_eq!(looped.residue, Verdict::Pass);
        let left = ev.look(container.as_str(), &["workload-ps"]);
        assert_eq!(line(&left, "others"), "1", "{left}");
        evidence("workload-fork-loop-reaped", "60");
        // The environment is still the clean one it was: another workload
        // runs in it.
        let after = ran(&socket, &ev, env, &["workload-exit", "0"]);
        assert_eq!(after.exit_code.map(|c| c.get()), Some(0));
        evidence("workload-environment-reusable-after-reap", "exited-0");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- what runs ---------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn only_the_pinned_bytes_run() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("digest");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);
        fn marker(name: &str) -> Vec<&str> {
            vec!["mark", name]
        }

        // Other bytes than the pinned ones: nothing runs.
        let other = "0".repeat(64);
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                env,
                workload((FIXTURE, &other), &marker("/workspace/sub"), 4096, 30)
            )),
            BrokerRefusal::DigestMismatch
        );
        evidence("workload-executable-substituted-refused", "digest-mismatch");
        // A path the image does not hold.
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                env,
                workload(
                    ("/usr/local/bin/absent-tool", &ev.fixture_sha256),
                    &[],
                    4096,
                    30
                )
            )),
            BrokerRefusal::DigestMismatch
        );
        evidence("workload-executable-missing-refused", "digest-mismatch");
        // Another file of the image under the fixture's digest.
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                env,
                workload(
                    (profile::PROBE_PATH, &ev.fixture_sha256),
                    &marker("/workspace/other"),
                    4096,
                    30
                )
            )),
            BrokerRefusal::DigestMismatch
        );
        evidence("workload-executable-other-file-refused", "digest-mismatch");
        assert!(!workspace.join("sub").exists() && !workspace.join("other").exists());
        evidence("workload-refused-ran-nothing", "no-marker");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- where it runs -----------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_workload_runs_only_in_the_clean_recorded_environment() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("where");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let mark = |name: &str| workload((FIXTURE, &ev.fixture_sha256), &["mark", name], 4096, 30);

        // Drift after preparation: a limit the record shows changed.
        let (s, container) = prepared(&socket, &ev, &workspace);
        ev.docker_ok(&[
            "container",
            "update",
            "--pids-limit",
            "4096",
            container.as_str(),
        ]);
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                (&s, &container),
                mark("/workspace/drift")
            )),
            BrokerRefusal::EnvironmentNotClean
        );
        evidence(
            "workload-drifted-environment-refused",
            "environment-not-clean",
        );

        // Stopped.
        let (s2, container2) = prepared(&socket, &ev, &workspace);
        ev.docker_ok(&["container", "stop", "--time", "1", container2.as_str()]);
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                (&s2, &container2),
                mark("/workspace/stopped")
            )),
            BrokerRefusal::EnvironmentNotClean
        );
        evidence(
            "workload-stopped-environment-refused",
            "environment-not-clean",
        );

        // Another environment's container, named as this one's.
        let (s3, container3) = prepared(&socket, &ev, &workspace);
        let (s4, _container4) = prepared(&socket, &ev, &workspace);
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                (&s4, &container3),
                mark("/workspace/foreign")
            )),
            BrokerRefusal::ForeignEnvironment
        );
        evidence(
            "workload-foreign-environment-refused",
            "foreign-environment",
        );

        // Gone.
        ev.remove(container3.as_str());
        assert_eq!(
            refusal(run_workload(
                &socket,
                &ev,
                (&s3, &container3),
                mark("/workspace/gone")
            )),
            BrokerRefusal::EnvironmentNotFound
        );
        evidence(
            "workload-missing-environment-refused",
            "environment-not-found",
        );
        for name in ["drift", "stopped", "foreign", "gone"] {
            assert!(!workspace.join(name).exists(), "{name} ran");
        }
        evidence("workload-nothing-ran-in-a-refused-environment", "no-marker");
        destroy(&socket, &ev, &s, &container);
        destroy(&socket, &ev, &s2, &container2);
    }

    // ---- what it can reach -------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn nothing_outside_the_workspace_is_reachable_from_a_workload() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("reach");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);
        let socket_text = socket.display().to_string();
        let scratch_text = dir.0.display().to_string();
        let out = text(&ran(
            &socket,
            &ev,
            env,
            &[
                "workload-escape",
                &socket_text,
                &scratch_text,
                "/etc/shadow-host-only",
            ],
        ));
        // EROFS (30) for a read-only root, a read-only `/usr`, `/etc`.
        assert_eq!(line(&out, "root"), "errno=30", "{out}");
        assert_eq!(line(&out, "usr"), "errno=30", "{out}");
        evidence("workload-root-read-only", "EROFS");
        assert_eq!(line(&out, "etc"), "errno=30", "{out}");
        evidence("workload-etc-read-only", "EROFS");
        assert_eq!(line(&out, "dotdot"), "errno=30", "{out}");
        evidence("workload-dot-dot-escape-refused", "EROFS");
        assert_eq!(line(&out, "tmp"), "written", "{out}");
        evidence("workload-tmp-writable", "written");
        assert_eq!(line(&out, "workspace"), "written", "{out}");
        let inside = workspace.join("direwolf-inside");
        assert_eq!(
            std::fs::metadata(&inside).unwrap().uid(),
            profile::SANDBOX_UID
        );
        evidence("workload-workspace-writable-as-10001", "written");
        assert_eq!(line(&out, "runtime_sockets"), "0", "{out}");
        evidence("workload-no-runtime-socket", "0");
        for host in [socket_text.as_str(), scratch_text.as_str()] {
            assert!(
                out.contains(&format!("host_path={host} exists=false")),
                "{host}: {out}"
            );
        }
        evidence("workload-no-host-path", "broker-socket-and-scratch-absent");

        let tcp = text(&ran(
            &socket,
            &ev,
            env,
            &["egress-direct", "tcp", "1.1.1.1", "443"],
        ));
        assert!(tcp.contains("errno="), "{tcp}");
        evidence("workload-direct-tcp-refused", tcp.trim());
        let dns = text(&ran(&socket, &ev, env, &["egress-dns", "8.8.8.8"]));
        assert!(
            !dns.contains("answered") && !dns.contains("tcp-connected"),
            "{dns}"
        );
        evidence("workload-direct-dns-refused", "no-answer");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- an agent-shaped workload -------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn an_agent_shaped_workload_is_contained_and_ended() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("agent");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, None);
        let workspace = dir.workspace("ws");
        let (s, container) = prepared(&socket, &ev, &workspace);
        let env = (&s, &container);
        let agent = ran(&socket, &ev, env, &["workload-agent", "3"]);
        let out = text(&agent);
        assert_eq!(agent.exit_code.map(|c| c.get()), Some(0), "{out}");
        assert_eq!(line(&out, "made"), "true", "{out}");
        assert_eq!(line(&out, "workers"), "2", "{out}");
        assert_eq!(line(&out, "read"), "true", "{out}");
        assert!(line(&out, "files").parse::<u32>().unwrap() >= 3, "{out}");
        evidence("agent-shaped-plan-and-workers-wrote", "plan+2-workers");
        assert!(line(&out, "tcp").starts_with("errno="), "{out}");
        assert!(line(&out, "udp").starts_with("errno="), "{out}");
        evidence(
            "agent-shaped-network-refused",
            &format!("tcp {} udp {}", line(&out, "tcp"), line(&out, "udp")),
        );
        // Two workers and the helper's child outlived it; `reap` ended
        // every one.
        assert!(agent.ended_processes.get() >= 3, "{agent:?}");
        assert_eq!(agent.residue, Verdict::Pass);
        let left = ev.look(container.as_str(), &["workload-ps"]);
        assert_eq!(line(&left, "others"), "1", "{left}");
        evidence("agent-shaped-helpers-and-workers-ended", "init-alone");
        evidence("agent-shaped-residue-clean", "pass");
        for name in ["plan.txt", "worker-1.txt", "worker-2.txt"] {
            let path = workspace.join("agent").join(name);
            assert_eq!(
                std::fs::metadata(&path).unwrap().uid(),
                profile::SANDBOX_UID,
                "{name}"
            );
        }
        evidence("agent-shaped-files-on-host-as-10001", "3-files");
        destroy(&socket, &ev, &s, &container);
    }

    // ---- the broker's own deployment ---------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn the_broker_refuses_an_environment_identity_and_reports_its_posture() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("deploy");
        for (uid, role, case) in [
            (
                profile::SANDBOX_UID,
                "every workload's",
                "identity-authority-workload-uid-refused",
            ),
            (
                profile::RELAY_UID,
                "every relay's",
                "identity-authority-relay-uid-refused",
            ),
        ] {
            let (code, stderr) = refused_broker(&dir.socket(), uid);
            assert_ne!(code, Some(0), "{stderr}");
            assert!(stderr.contains(role), "{stderr}");
            assert!(!dir.socket().exists(), "a refused broker bound its socket");
            evidence(case, "refused-before-binding");
        }
        let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .map(|s| s.trim().to_owned());
        let broker = Broker::start(&dir.socket(), None);
        let log = broker.stderr();
        let reported = log
            .lines()
            .find(|l| l.contains("event=deployment_posture"))
            .unwrap_or_else(|| panic!("no posture in:\n{log}"))
            .to_owned();
        let expected = scope.as_deref().unwrap_or("absent");
        assert!(
            reported.contains(&format!("ptrace_scope={expected}")),
            "{reported}"
        );
        // This broker serves, so the window is closed here — or it would have
        // refused (it was not given --allow-traceable-workers).
        assert!(
            reported.contains("startup_window_closed=true"),
            "{reported}"
        );
        assert!(!log.contains("--allow-traceable-workers)"), "{log}");
        evidence(
            "posture-reported-matches-host",
            &format!("ptrace_scope={expected}"),
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_broker_killed_mid_workload_leaves_it_to_the_environments_destruction() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("crash");
        let socket = dir.socket();
        let workspace = dir.workspace("ws");

        // Before the exec: no answer, and nothing ran.
        let (s, container) = {
            let _broker = Broker::start(&socket, None);
            prepared(&socket, &ev, &workspace)
        };
        {
            let _crashing = Broker::start(&socket, Some("workload_judged"));
            let answer = try_run(
                &socket,
                &ev,
                (&s, &container),
                workload(
                    (FIXTURE, &ev.fixture_sha256),
                    &["mark", "/workspace/judged"],
                    4096,
                    30,
                ),
            );
            assert!(answer.is_none(), "{answer:?}");
        }
        assert!(!workspace.join("judged").exists());
        evidence("broker-crash-before-exec-nothing-ran", "no-marker");

        // During it: no answer, and the workload runs on in its environment —
        // the runtime keeps an `exec`'d process when its client dies.
        let mut broker = Broker::start(&socket, None);
        let (sent, got) = mpsc::channel();
        let (socket2, ev2, s2, container2) =
            (socket.clone(), ev.clone(), s.clone(), container.clone());
        let fixture = ev.fixture_sha256.clone();
        std::thread::spawn(move || {
            let _ = sent.send(try_run(
                &socket2,
                &ev2,
                (&s2, &container2),
                workload((FIXTURE, &fixture), &["workload-sleep", "120"], 4096, 120),
            ));
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let seen = ev.look(container.as_str(), &["workload-ps"]);
            if line(&seen, "others").parse::<u32>().unwrap_or(0) >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the workload never started: {seen}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        broker.kill();
        let answer = got.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(answer.is_none(), "an answer from a dead broker: {answer:?}");
        evidence("broker-crash-mid-workload-no-answer", "none");
        let seen = ev.look(container.as_str(), &["workload-ps"]);
        assert!(line(&seen, "others").parse::<u32>().unwrap() >= 2, "{seen}");
        evidence("broker-crash-workload-still-running", "outlived-its-client");
        // What ends it is the environment's destruction.
        let _broker = Broker::start(&socket, None);
        destroy(&socket, &ev, &s, &container);
        assert!(!ev.exists(container.as_str()));
        evidence("broker-restart-destroy-ends-it", "container-removed");
    }
}
