//! M5b's real-topology evidence at the broker (ADR-0048): the built
//! `dwkd-broker` preparing `PROXY_ONLY` environments in a **real** OCI
//! runtime — the environment, its one-shot setup and its relay are real
//! containers in a real network namespace, and every byte a workload sends
//! crosses the real relay and the broker's real CONNECT proxy — with this
//! test process playing the authority.
//!
//! Every test is `#[ignore]`d: `make sandbox-egress-evidence` builds the
//! images, pins the probe and relay digests and passes them in
//! (`DW_SANDBOX_*`, `DW_EGRESS_*`). Run any other way a test panics with
//! `NOT EXERCISED`.
//!
//! What is a fixture here, and what is not:
//!
//! * The **destinations** are fixtures: the broker is started with
//!   `--allow-evidence-egress`, so names resolve from a file this test writes
//!   and the loopback origin it runs is reachable as the file's one
//!   exception. That flag is evidence-only and the production resolver has
//!   no exception (`a_production_broker_has_no_exception_and_no_fixture`).
//! * The **workload** is a fixture: the evidence image carries the test-only
//!   `sandbox-fixture` beside the real probe and relay, and this test runs it
//!   in the environment with the runtime's own `exec` — as the environment's
//!   user, under its profile. Nothing in the product runs a workload (M5d).
//! * The **boundary** is not: the namespace, the setup, the relay, the
//!   broker's socket, its proxy, guard, resolver deadline, server-name check
//!   and budgets are the real ones. Weakened topologies are built here, in
//!   test code, and measured by the real broker; no product path builds one.

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

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, IoSlice, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::net::TcpListener;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::egress::{
        EgressByteBudget, EgressCounters, EgressDisposition as D, EgressGrant, EgressHost,
        EgressPort, EgressTarget, EgressTargets, EgressTunnelLimit,
    };
    use dwk_proto::brokerp::sandbox::{
        ContainerRef, ContainerRole, EnvironmentProfile, ImageId, NetworkTopology,
        SandboxInvariant as I, StoreInstance, Verdict, required_invariants,
    };
    use dwk_proto::brokerp::{
        Authorisation, BrokerDone, BrokerHello, BrokerOutcome, BrokerRefusal, Common,
        ContainerState, DestroyState, EnvironmentDestroyAuthorisation, EnvironmentDestroyDone,
        EnvironmentListAuthorisation, EnvironmentMeasureAuthorisation, EnvironmentMeasurement,
        EnvironmentPrepareAuthorisation, EnvironmentSpec, OutcomeResult, OwnedEnvironment,
        RuntimeSpec,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath};
    use dwk_sandbox_profile as profile;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);
    const PEER_WAIT: Duration = Duration::from_secs(150);
    const SUITE: &str = "sandbox-egress";
    /// Where the evidence image carries the test-only workload fixture.
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    /// The origin's name in every grant and in the resolver fixture.
    const ORIGIN: &str = "origin.test";

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn evidence(case: &str, outcome: &str) {
        let outcome = outcome.replace(['"', '\\'], "'");
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
    }

    fn own_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    /// What the evidence task built and pinned.
    #[derive(Clone)]
    struct Evidence {
        runtime: PathBuf,
        socket: String,
        /// The product image: the probe and the relay, nothing else.
        image: String,
        /// The product image and the test-only workload fixture.
        fixture_image: String,
        /// The probe and a relay one byte different from the pinned one.
        tampered_relay: String,
        probe_sha256: String,
        relay_sha256: String,
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-egress-evidence`, which builds \
                 the evidence images and pins their digests"
            )
        })
    }

    impl Evidence {
        fn load() -> Self {
            Self {
                runtime: PathBuf::from(var("DW_SANDBOX_RUNTIME")),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_EGRESS_IMAGE"),
                fixture_image: var("DW_EGRESS_IMAGE_FIXTURE"),
                tampered_relay: var("DW_EGRESS_IMAGE_TAMPERED_RELAY"),
                probe_sha256: var("DW_SANDBOX_PROBE_SHA256"),
                relay_sha256: var("DW_EGRESS_RELAY_SHA256"),
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

        /// This store's containers of `environment` with `role`, by id.
        fn labelled(
            &self,
            environment: &EnvironmentId,
            role: Option<ContainerRole>,
        ) -> Vec<String> {
            let mut args = vec![
                "container".to_owned(),
                "ls".to_owned(),
                "--all".to_owned(),
                "--no-trunc".to_owned(),
                "--quiet".to_owned(),
                "--filter".to_owned(),
                format!("label={}={}", profile::LABEL_STORE, store().as_str()),
                "--filter".to_owned(),
                format!(
                    "label={}={}",
                    profile::LABEL_ENVIRONMENT,
                    environment.as_str()
                ),
            ];
            if let Some(role) = role {
                args.push("--filter".to_owned());
                args.push(format!("label={}={}", profile::LABEL_ROLE, role.label()));
            }
            let words: Vec<&str> = args.iter().map(String::as_str).collect();
            self.docker_ok(&words).lines().map(str::to_owned).collect()
        }

        /// Run the workload fixture inside `container`, as its own user.
        fn workload(&self, container: &ContainerRef, args: &[&str]) -> String {
            self.workload_with(container, &[], args)
        }

        fn workload_with(&self, container: &ContainerRef, env: &[&str], args: &[&str]) -> String {
            let mut words = vec!["container", "exec"];
            for e in env {
                words.push("--env");
                words.push(e);
            }
            words.push(container.as_str());
            words.push(FIXTURE);
            words.extend_from_slice(args);
            let out = self.docker(&words);
            assert!(
                out.status.success(),
                "{args:?}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        }
    }

    /// Containers this test made without its store's labels, by id.
    static CREATED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Every container a test made or had made, removed when the test ends:
    /// everything carrying this process's store label, and the unlabelled
    /// ones it recorded. Nothing else is touched.
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
            let path = std::env::temp_dir().join(format!("dwe-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("ipc").join("broker.sock")
        }

        fn egress_root(&self) -> PathBuf {
            self.0.join("ipc").join("egress")
        }

        fn workspace(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
            path
        }

        /// The resolver fixture: every evidence name, and the loopback
        /// origin as the one exception.
        fn resolver_fixture(&self) -> PathBuf {
            let path = self.0.join("egress-fixture.txt");
            std::fs::write(
                &path,
                format!(
                    "# The M5b egress evidence's names.\n\
                     resolve {ORIGIN} 127.0.0.1\n\
                     resolve second.test 127.0.0.1\n\
                     resolve blocked.test 10.0.0.1\n\
                     resolve metadata.test 169.254.169.254\n\
                     resolve mixed.test 127.0.0.1,10.0.0.1\n\
                     resolve rebind.test 127.0.0.1;10.0.0.1\n\
                     resolve fail.test fail\n\
                     resolve slow.test timeout\n\
                     allow 127.0.0.1\n"
                ),
            )
            .unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// How a broker is started.
    #[derive(Default)]
    struct Start<'a> {
        evidence_egress: Option<&'a Path>,
        crash: Option<&'a str>,
        /// Variables put in the broker's own environment.
        ambient: &'a [(&'a str, &'a str)],
    }

    /// The built broker, killed when dropped.
    struct Broker {
        child: Child,
        stderr: Arc<Mutex<String>>,
    }

    impl Broker {
        fn start(socket: &Path, how: &Start<'_>) -> Self {
            let mut command = Command::new(BIN);
            command.env_clear();
            for (name, value) in how.ambient {
                command.env(name, value);
            }
            if let Some(point) = how.crash {
                command.env("DWKD_BROKER_CRASH_AT", point);
            }
            command
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(own_uid().to_string())
                .arg("--allow-shared-authority-uid");
            if let Some(fixture) = how.evidence_egress {
                command.arg("--allow-evidence-egress").arg(fixture);
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

        fn evidence(socket: &Path, fixture: &Path) -> Self {
            Self::start(
                socket,
                &Start {
                    evidence_egress: Some(fixture),
                    ..Start::default()
                },
            )
        }

        fn stderr(&self) -> String {
            self.stderr.lock().unwrap().clone()
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

    /// A loopback TCP origin: counts connections, keeps what it receives,
    /// and sends `reply` bytes to each connection once it has received any.
    struct Origin {
        port: u16,
        accepted: Arc<AtomicUsize>,
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl Origin {
        fn start(reply: usize, eager: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepted = Arc::new(AtomicUsize::new(0));
            let received = Arc::new(Mutex::new(Vec::new()));
            let (count, keep) = (Arc::clone(&accepted), Arc::clone(&received));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    count.fetch_add(1, Ordering::SeqCst);
                    let keep = Arc::clone(&keep);
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                        let mut replied = false;
                        if eager {
                            let _ = stream.write_all(&vec![b'r'; reply]);
                            replied = true;
                        }
                        let mut buffer = [0u8; 16 * 1024];
                        while let Ok(n) = stream.read(&mut buffer) {
                            if n == 0 {
                                break;
                            }
                            keep.lock().unwrap().extend_from_slice(&buffer[..n]);
                            if !replied {
                                let _ = stream.write_all(&vec![b'r'; reply]);
                                replied = true;
                            }
                        }
                    });
                }
            });
            Self {
                port,
                accepted,
                received,
            }
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }

        fn received(&self) -> Vec<u8> {
            self.received.lock().unwrap().clone()
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

    fn environment() -> EnvironmentId {
        EnvironmentId::from_uuid(uuid(next())).unwrap()
    }

    fn run() -> RunId {
        RunId::from_uuid(uuid(next())).unwrap()
    }

    /// This test process's store.
    fn store() -> StoreInstance {
        StoreInstance::new(format!("e{:07x}", std::process::id() & 0x0fff_ffff)).unwrap()
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

    fn target(host: &str, port: u16) -> EgressTarget {
        EgressTarget {
            host: EgressHost::new(host.to_owned()).unwrap(),
            port: EgressPort::new(port).unwrap(),
        }
    }

    fn grant(targets: Vec<EgressTarget>, tunnels: u16, up: u64, down: u64) -> EgressGrant {
        EgressGrant {
            targets: EgressTargets::new(targets).unwrap(),
            max_tunnels: EgressTunnelLimit::new(tunnels).unwrap(),
            max_upload_bytes: EgressByteBudget::new(up).unwrap(),
            max_download_bytes: EgressByteBudget::new(down).unwrap(),
        }
    }

    /// A `PROXY_ONLY` specification.
    fn spec(
        (environment, run): (&EnvironmentId, &RunId),
        workspace: &Path,
        image: &str,
        relay: &str,
        egress: EgressGrant,
        ev: &Evidence,
    ) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: environment.clone(),
            run_id: run.clone(),
            store: store(),
            profile: EnvironmentProfile::OciStrict,
            network: NetworkTopology::ProxyOnly,
            image: ImageId::new(image.to_owned()).unwrap(),
            probe_sha256: ContentDigest::new(ev.probe_sha256.clone()).unwrap(),
            workspace_path: HostPath::new(workspace.display().to_string()).unwrap(),
            workspace: identity(workspace),
            relay_sha256: Some(ContentDigest::new(relay.to_owned()).unwrap()),
            egress: Some(egress),
        }
    }

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

    fn prepare(socket: &Path, ev: &Evidence, spec: &EnvironmentSpec) -> OutcomeResult {
        let (runtime, exe, cwd) = runtime(ev);
        let spec = spec.clone();
        exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentPrepare(EnvironmentPrepareAuthorisation::new(
                    common, spec, runtime,
                ))
            },
            (exe, cwd),
        )
    }

    fn measure(
        socket: &Path,
        ev: &Evidence,
        spec: &EnvironmentSpec,
        container: &ContainerRef,
    ) -> (
        EnvironmentMeasurement,
        Option<EgressCounters>,
        ContainerState,
    ) {
        let (runtime, exe, cwd) = runtime(ev);
        let (spec, container) = (spec.clone(), container.clone());
        let measured = done(exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentMeasure(EnvironmentMeasureAuthorisation::new(
                    common, spec, container, runtime,
                ))
            },
            (exe, cwd),
        ))
        .environment_measure
        .unwrap();
        (
            measured.measurement.unwrap(),
            measured.egress,
            measured.state,
        )
    }

    fn destroy(
        socket: &Path,
        ev: &Evidence,
        (environment, run): (&EnvironmentId, &RunId),
        container: Option<&ContainerRef>,
    ) -> EnvironmentDestroyDone {
        let (runtime, exe, cwd) = runtime(ev);
        let (environment, run, container) = (environment.clone(), run.clone(), container.cloned());
        done(exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentDestroy(EnvironmentDestroyAuthorisation::new(
                    common,
                    (environment, run, store()),
                    container,
                    runtime,
                ))
            },
            (exe, cwd),
        ))
        .environment_destroy
        .unwrap()
    }

    fn list(socket: &Path, ev: &Evidence) -> Vec<OwnedEnvironment> {
        let (runtime, exe, cwd) = runtime(ev);
        let listed = done(exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentList(EnvironmentListAuthorisation::new(
                    common,
                    store(),
                    runtime,
                ))
            },
            (exe, cwd),
        ))
        .environment_list
        .unwrap();
        assert!(listed.complete);
        listed.environments.into_iter().collect()
    }

    fn verdict(measurement: &EnvironmentMeasurement, invariant: I) -> Verdict {
        let found: Vec<Verdict> = measurement
            .checks
            .iter()
            .filter(|c| c.invariant == invariant)
            .map(|c| c.verdict)
            .collect();
        assert_eq!(found.len(), 1, "{invariant:?} reported once");
        found[0]
    }

    fn not_passing(measurement: &EnvironmentMeasurement) -> Vec<(I, Verdict)> {
        let required = required_invariants(NetworkTopology::ProxyOnly);
        measurement
            .checks
            .iter()
            .filter(|c| required.contains(&c.invariant) && c.verdict != Verdict::Pass)
            .map(|c| (c.invariant, c.verdict))
            .collect()
    }

    /// A clean `PROXY_ONLY` preparation's container.
    fn prepared_clean(
        socket: &Path,
        ev: &Evidence,
        spec: &EnvironmentSpec,
        broker: &Broker,
    ) -> (ContainerRef, EnvironmentMeasurement) {
        let prepared = done(prepare(socket, ev, spec)).environment_prepare.unwrap();
        let measurement = prepared.measurement.clone().unwrap_or_else(|| {
            panic!("no measurement:\n{}", broker.stderr());
        });
        assert!(
            prepared.retained,
            "not clean: {:?}\n{}",
            not_passing(&measurement),
            broker.stderr()
        );
        assert_eq!(measurement.checks.len(), I::ALL.len());
        assert!(not_passing(&measurement).is_empty());
        (prepared.container.unwrap(), measurement)
    }

    fn count(counters: &EgressCounters, disposition: D) -> u64 {
        counters.count(disposition)
    }

    /// The `key=value` field of a fixture's line.
    fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{key}=")))
    }

    /// The broker's directory for an environment, if it still exists.
    fn egress_dir(dir: &Scratch, environment: &EnvironmentId) -> PathBuf {
        dir.egress_root().join(environment.as_str())
    }

    // ---- the strict topology ---------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn a_proxy_only_environment_measures_clean_and_reaches_only_its_proxy() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("strict");
        let socket = dir.socket();
        let broker = Broker::evidence(&socket, &dir.resolver_fixture());
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, 443)], 4, 1 << 20, 1 << 20),
            &ev,
        );
        let since = Instant::now();
        let (container, measurement) = prepared_clean(&socket, &ev, &s, &broker);
        evidence(
            "proxy-only-prepare-clean",
            &format!(
                "pass-{}-in-{}ms",
                measurement.checks.len(),
                since.elapsed().as_millis()
            ),
        );
        for (case, invariant) in [
            ("proxy-only-host-network-isolated", I::HostNetworkIsolated),
            ("proxy-only-host-proxy-environment", I::HostProxyEnvironment),
            ("proxy-only-host-proxy-relay", I::HostProxyRelay),
            ("proxy-only-host-relay-digest", I::HostRelayDigest),
            (
                "proxy-only-container-network-isolated",
                I::ContainerNetworkIsolated,
            ),
            (
                "proxy-only-container-proxy-reachable",
                I::ContainerProxyReachable,
            ),
            (
                "proxy-only-container-direct-egress-refused",
                I::ContainerDirectEgressRefused,
            ),
            (
                "proxy-only-container-direct-dns-refused",
                I::ContainerDirectDnsRefused,
            ),
            (
                "proxy-only-container-raw-sockets-refused",
                I::ContainerRawSocketsRefused,
            ),
            (
                "proxy-only-container-capabilities-empty",
                I::ContainerCapabilitiesEmpty,
            ),
            (
                "proxy-only-host-capabilities-dropped",
                I::HostCapabilitiesDropped,
            ),
        ] {
            assert_eq!(verdict(&measurement, invariant), Verdict::Pass, "{case}");
            evidence(case, "pass");
        }

        // Exactly two containers live: the environment and its relay. The
        // setup removed itself.
        let environments = ev.labelled(&e, Some(ContainerRole::Environment));
        let relays = ev.labelled(&e, Some(ContainerRole::Relay));
        let setups = ev.labelled(&e, Some(ContainerRole::Setup));
        assert_eq!(environments, [container.as_str().to_owned()]);
        assert_eq!(relays.len(), 1);
        assert!(setups.is_empty(), "{setups:?}");
        assert_eq!(ev.labelled(&e, None).len(), 2);
        evidence(
            "proxy-only-environment-and-relay-only",
            "2-containers-no-setup",
        );
        let relay_mode = ev.docker_ok(&[
            "container",
            "inspect",
            "--format",
            "{{.HostConfig.NetworkMode}} {{.Config.User}} {{json .HostConfig.CapAdd}} {{.HostConfig.ReadonlyRootfs}}",
            &relays[0],
        ]);
        assert_eq!(
            relay_mode.trim(),
            format!("container:{} 10002:10002 null true", container.as_str())
        );
        evidence("proxy-only-relay-shares-the-namespace-unprivileged", "pass");

        // The broker's listener for it exists, its own, beneath a root only
        // the broker enters; the relay alone has it mounted.
        let edir = egress_dir(&dir, &e);
        let meta = std::fs::symlink_metadata(edir.join(profile::EGRESS_SOCKET_NAME)).unwrap();
        assert_eq!(meta.uid(), own_uid());
        let root_mode = std::fs::metadata(dir.egress_root())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(root_mode & 0o777, 0o700);
        evidence("proxy-only-listener-open", "socket-present-root-0700");
        let env_mounts = ev.docker_ok(&[
            "container",
            "inspect",
            "--format",
            "{{json .Mounts}}",
            container.as_str(),
        ]);
        assert!(!env_mounts.contains(profile::EGRESS_TARGET), "{env_mounts}");
        let relay_mounts = ev.docker_ok(&[
            "container",
            "inspect",
            "--format",
            "{{json .Mounts}}",
            &relays[0],
        ]);
        assert!(
            relay_mounts.contains(profile::EGRESS_TARGET),
            "{relay_mounts}"
        );
        evidence("proxy-only-socket-mounted-in-relay-only", "relay-only");

        // Who reaches the socket is the kernel's check on the directory, by
        // uid, wherever the directory is exposed (Docker Desktop re-exposes
        // every bind source to every WSL distribution): the same directory,
        // mounted into a test-only container as any other uid — the
        // environment's, root without capabilities, nobody — is refused; as
        // the relay's uid it connects.
        let dir_mode = std::fs::metadata(&edir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o710,
            "owner rwx, the ACL's mask --x, others none"
        );
        let mount = format!("{}:{}:ro", edir.display(), profile::EGRESS_TARGET);
        let inside = format!("{}/{}", profile::EGRESS_TARGET, profile::EGRESS_SOCKET_NAME);
        let attempt = |user: &str| {
            ev.docker_ok(&[
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                user,
                "--cap-drop",
                "ALL",
                "--read-only",
                "--security-opt",
                "no-new-privileges",
                "--volume",
                &mount,
                "--entrypoint",
                FIXTURE,
                &ev.fixture_image,
                "egress-unix",
                &inside,
            ])
            .trim()
            .to_owned()
        };
        for user in ["10001:10001", "0:0", "65534:65534", "10003:10002"] {
            assert_eq!(attempt(user), "errno=13 name=EACCES", "{user}");
        }
        let relay_user = format!("{}:{}", profile::RELAY_UID, profile::RELAY_GID);
        assert_eq!(attempt(&relay_user), "connected");
        evidence(
            "proxy-only-socket-directory-relay-uid-only",
            "environment-uid-root-nobody-relay-gid-EACCES-relay-uid-connected",
        );

        // Listed with roles, every label exact.
        let listed = list(&socket, &ev);
        let mine: Vec<_> = listed
            .iter()
            .filter(|o| o.environment_id.as_ref() == Some(&e))
            .collect();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|o| o.labels_exact));
        let mut roles: Vec<_> = mine.iter().map(|o| o.role.unwrap().label()).collect();
        roles.sort_unstable();
        assert_eq!(roles, ["environment", "relay"]);
        evidence("proxy-only-listed-with-roles", "environment+relay");

        // Measured again: clean; the counters say what the probe asked.
        let (again, counters, state) = measure(&socket, &ev, &s, &container);
        assert_eq!(state, ContainerState::Running);
        assert!(not_passing(&again).is_empty(), "{:?}", not_passing(&again));
        let counters = counters.unwrap();
        assert!(count(&counters, D::TargetNotGranted) >= 2, "{counters:?}");
        evidence("proxy-only-measure-clean-again", "pass");

        // Destroyed: every role removed, the listener closed, the counters
        // returned.
        let destroyed = destroy(&socket, &ev, (&e, &r), Some(&container));
        assert_eq!(destroyed.state, DestroyState::Removed);
        assert!(ev.labelled(&e, None).is_empty());
        assert!(!ev.exists(&relays[0]));
        evidence("proxy-only-destroy-removes-every-role", "removed");
        assert!(!edir.exists(), "the listener's directory is gone");
        evidence("proxy-only-destroy-closes-listener", "closed");
        let counters = destroyed.egress.unwrap();
        assert_eq!(count(&counters, D::Closed), 0);
        assert!(count(&counters, D::TargetNotGranted) >= 2);
        assert_eq!(counters.bytes_upstream.get(), 0);
        evidence(
            "proxy-only-destroy-counters",
            &format!(
                "target-not-granted-{}",
                count(&counters, D::TargetNotGranted)
            ),
        );
        let again = destroy(&socket, &ev, (&e, &r), Some(&container));
        assert_eq!(again.state, DestroyState::AlreadyGone);
        assert!(again.egress.is_none());
        evidence("proxy-only-destroy-idempotent", "already-gone");
    }

    // ---- tunnels through the real topology -------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn tunnels_through_the_real_topology_obey_the_grant_the_guard_and_the_server_name() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("tunnels");
        let socket = dir.socket();
        let broker = Broker::evidence(&socket, &dir.resolver_fixture());
        let origin = Origin::start(5, false);
        let port = origin.port;
        let p = port.to_string();
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let granted: Vec<EgressTarget> = [
            ORIGIN,
            "blocked.test",
            "metadata.test",
            "mixed.test",
            "rebind.test",
            "fail.test",
            "slow.test",
        ]
        .iter()
        .map(|h| target(h, port))
        .collect();
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(granted, 8, 16 << 20, 16 << 20),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let run_fixture = |args: &[&str]| ev.workload(&container, args);

        // A granted host, its own name in the hello: carried both ways.
        let line = run_fixture(&["egress-connect", ORIGIN, &p, ORIGIN, "1000"]);
        assert!(
            line.contains("HTTP/1.1 200 Connection Established"),
            "{line}"
        );
        assert_eq!(field(&line, "received"), Some("5"), "{line}");
        let wait = Instant::now() + Duration::from_secs(5);
        while origin.received().len() < 1000 {
            assert!(
                Instant::now() < wait,
                "the origin got {}",
                origin.received().len()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(origin.accepted(), 1);
        evidence("tunnel-granted-carries-bytes", &line);

        // The broker's own variable leads a tool that honours it there.
        let line = ev.workload(&container, &["egress-via-variable", ORIGIN, &p]);
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(origin.accepted(), 2);
        evidence("tunnel-via-proxy-variable", &line);

        let refused = |args: &[&str], decision: D, status: &str| {
            let before = origin.accepted();
            let line = run_fixture(args);
            assert!(line.contains(status), "{args:?}: {line}");
            assert_eq!(field(&line, "decision"), Some(decision.as_str()), "{line}");
            assert_eq!(origin.accepted(), before, "{args:?} reached the origin");
            line
        };
        for (case, args, decision, status) in [
            (
                "tunnel-host-not-granted",
                vec!["egress-connect", "second.test", &p, "second.test", "0"],
                D::TargetNotGranted,
                "403",
            ),
            (
                "tunnel-port-not-granted",
                vec!["egress-connect", ORIGIN, "443", ORIGIN, "0"],
                D::TargetNotGranted,
                "403",
            ),
            (
                "tunnel-address-literal-refused",
                vec!["egress-connect", "127.0.0.1", &p, ORIGIN, "0"],
                D::TargetNotCanonical,
                "400",
            ),
            (
                "resolver-blocked",
                vec!["egress-connect", "blocked.test", &p, "blocked.test", "0"],
                D::AddressBlocked,
                "403",
            ),
            (
                "resolver-metadata-blocked",
                vec!["egress-connect", "metadata.test", &p, "metadata.test", "0"],
                D::AddressBlocked,
                "403",
            ),
            (
                "resolver-mixed-refused-outright",
                vec!["egress-connect", "mixed.test", &p, "mixed.test", "0"],
                D::AddressMixed,
                "403",
            ),
            (
                "resolver-failure",
                vec!["egress-connect", "fail.test", &p, "fail.test", "0"],
                D::ResolutionFailed,
                "403",
            ),
            (
                "resolver-timeout",
                vec!["egress-connect", "slow.test", &p, "slow.test", "0"],
                D::ResolutionTimeout,
                "403",
            ),
        ] {
            let line = refused(&args, decision, status);
            evidence(case, &line);
        }

        // Rebinding: the first answer is pinned and used; the next tunnel
        // resolves again, gets the blocked answer, and is refused — the
        // name is resolved once per tunnel and never re-resolved inside one.
        let before = origin.accepted();
        let line = run_fixture(&["egress-connect", "rebind.test", &p, "rebind.test", "10"]);
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(origin.accepted(), before + 1);
        let line = refused(
            &["egress-connect", "rebind.test", &p, "rebind.test", "0"],
            D::AddressBlocked,
            "403",
        );
        evidence("resolver-rebinding-pinned", &line);

        // The server name must be the CONNECT host before anything is dialled.
        for (case, args) in [
            (
                "tunnel-sni-mismatch-closed",
                vec!["egress-connect", ORIGIN, &p, "evil.example", "100"],
            ),
            (
                "tunnel-sni-missing-closed",
                vec!["egress-connect", ORIGIN, &p, "-", "100"],
            ),
            (
                "tunnel-ech-refused",
                vec!["egress-connect", ORIGIN, &p, ORIGIN, "100", "ech"],
            ),
            (
                "tunnel-plain-http-refused",
                vec!["egress-connect", ORIGIN, &p, ORIGIN, "0", "plain"],
            ),
        ] {
            let before = origin.accepted();
            let line = run_fixture(&args);
            assert!(line.contains("HTTP/1.1 200"), "{case}: {line}");
            assert_eq!(field(&line, "received"), Some("0"), "{case}: {line}");
            assert_eq!(origin.accepted(), before, "{case} reached the origin");
            evidence(case, &line);
        }

        // Every ending counted by its disposition, never by its content.
        let destroyed = destroy(&socket, &ev, (&e, &r), Some(&container));
        let counters = destroyed.egress.unwrap();
        for (disposition, at_least) in [
            (D::Closed, 3),
            (D::TargetNotGranted, 2),
            (D::TargetNotCanonical, 1),
            (D::AddressBlocked, 3),
            (D::AddressMixed, 1),
            (D::ResolutionFailed, 1),
            (D::ResolutionTimeout, 1),
            (D::SniMismatch, 1),
            (D::SniMissing, 1),
            (D::EchRefused, 1),
            (D::ClientHelloMalformed, 1),
        ] {
            assert!(
                count(&counters, disposition) >= at_least,
                "{disposition:?}: {counters:?}"
            );
        }
        let text = format!("{counters:?}");
        for secret in ["evil.example", ORIGIN, "fronted"] {
            assert!(!text.contains(secret), "a counter names {secret}");
        }
        assert!(!broker.stderr().contains("evil.example"));
        evidence(
            "counters-at-destroy-by-disposition",
            &format!(
                "dispositions-{}-upstream-{}",
                counters.dispositions.len(),
                counters.bytes_upstream.get()
            ),
        );
        evidence(
            "audit-observability-no-payload",
            "no-host-or-payload-in-counters-or-log",
        );
    }

    // ---- budgets ---------------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn budgets_hold_at_the_socket_in_the_real_topology() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("budgets");
        let socket = dir.socket();
        let broker = Broker::evidence(&socket, &dir.resolver_fixture());
        let workspace = dir.workspace("ws");

        // Upload: 8 KiB for the whole environment.
        let origin = Origin::start(0, false);
        let p = origin.port.to_string();
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, origin.port)], 4, 8192, 1 << 20),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "65536"]);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            origin.received().len() <= 8192,
            "{}",
            origin.received().len()
        );
        evidence("budget-upload-exhausted", &line);
        // Spent stays spent: the next tunnel is closed before it is dialled.
        let before = origin.accepted();
        let next = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "10"]);
        assert_eq!(origin.accepted(), before, "{next}");
        evidence("budget-upload-spent-stays-spent", &next);
        let counters = destroy(&socket, &ev, (&e, &r), Some(&container))
            .egress
            .unwrap();
        assert!(count(&counters, D::UploadBudget) >= 2, "{counters:?}");
        assert_eq!(counters.bytes_upstream.get(), 8192);
        evidence("budget-upload-exact-at-socket", "8192-of-8192");

        // Download: 4 KiB, against an origin that sends 64 KiB.
        let origin = Origin::start(65536, true);
        let p = origin.port.to_string();
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, origin.port)], 4, 1 << 20, 4096),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        let received: usize = field(&line, "received").unwrap().parse().unwrap();
        assert!(received <= 4096, "{line}");
        let counters = destroy(&socket, &ev, (&e, &r), Some(&container))
            .egress
            .unwrap();
        assert_eq!(count(&counters, D::DownloadBudget), 1, "{counters:?}");
        assert_eq!(counters.bytes_downstream.get(), 4096);
        evidence("budget-download-exhausted", &line);

        // Connections: one tunnel at a time.
        let origin = Origin::start(0, false);
        let p = origin.port.to_string();
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, origin.port)], 1, 1 << 20, 1 << 20),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        // The first tunnel holds the one slot: the origin never closes it.
        let holder = {
            let mut words: Vec<String> = ["container", "exec", container.as_str(), FIXTURE]
                .iter()
                .map(|w| (*w).to_owned())
                .collect();
            for w in ["egress-connect", ORIGIN, &p, ORIGIN, "0", "hold"] {
                words.push(w.to_owned());
            }
            Command::new(&ev.runtime)
                .env_clear()
                .env("HOME", std::env::temp_dir())
                .arg("--host")
                .arg(format!("unix://{}", ev.socket))
                .args(&words)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let wait = Instant::now() + Duration::from_secs(10);
        while origin.accepted() == 0 {
            assert!(Instant::now() < wait, "the first tunnel never opened");
            std::thread::sleep(Duration::from_millis(20));
        }
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(field(&line, "decision"), Some("TUNNEL_LIMIT"), "{line}");
        assert_eq!(origin.accepted(), 1);
        evidence("budget-tunnel-limit", &line);
        let mut holder = holder;
        let _ = holder.kill();
        let _ = holder.wait();
        destroy(&socket, &ev, (&e, &r), Some(&container));

        // The fronting residual, honestly: inside an agreeing tunnel the
        // proxy cannot see a request for another origin, so it is carried —
        // and the environment's budget is what bounds it.
        let origin = Origin::start(0, false);
        let p = origin.port.to_string();
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, origin.port)], 4, 4096, 1 << 20),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let line = ev.workload(
            &container,
            &["egress-connect", ORIGIN, &p, ORIGIN, "65536", "front"],
        );
        std::thread::sleep(Duration::from_millis(300));
        let received = origin.received();
        let inner = b"Host: fronted.example";
        assert!(
            received.windows(inner.len()).any(|w| w == inner),
            "the fronted request was not carried: {line}"
        );
        assert!(received.len() <= 4096);
        let counters = destroy(&socket, &ev, (&e, &r), Some(&container))
            .egress
            .unwrap();
        assert!(count(&counters, D::UploadBudget) >= 1);
        evidence(
            "fronting-residual-carried-and-bounded",
            &format!("carried-unseen-bounded-{}-of-4096", received.len()),
        );
        drop(broker);
    }

    // ---- a process that ignores the proxy --------------------------------

    /// Why an attempt failed: the topology (no route, nothing listening on
    /// the namespace's own addresses), the capabilities, the seccomp
    /// profile, or the platform.
    fn mechanism(line: &str, kind: &str) -> &'static str {
        match (kind, field(line, "name")) {
            // No route at all. `EHOSTUNREACH` is not that: it is what a
            // route to a neighbour that never answered gives — a path, as
            // the probe judges it too.
            (_, Some("ENETUNREACH")) => "topology-no-route",
            ("local", Some("ECONNREFUSED")) => "topology-nothing-listening",
            ("caps", Some("EPERM")) => "capabilities",
            ("seccomp", Some("EPERM")) => "seccomp",
            (_, Some("EAFNOSUPPORT" | "EPROTONOSUPPORT")) => "platform",
            _ => "unexpected",
        }
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn a_process_that_ignores_the_proxy_has_no_path() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("bypass");
        let socket = dir.socket();
        let broker = Broker::evidence(&socket, &dir.resolver_fixture());
        let origin = Origin::start(5, false);
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, origin.port)], 4, 1 << 20, 1 << 20),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let w = |args: &[&str]| ev.workload(&container, args);
        let p = origin.port.to_string();

        // TCP and UDP, straight at addresses: nothing routes.
        for (case, kind, ip, port) in [
            ("bypass-tcp-external", "tcp", "1.1.1.1", "443"),
            ("bypass-tcp-external-dns", "tcp", "8.8.8.8", "53"),
            ("bypass-tcp-cloud-metadata", "tcp", "169.254.169.254", "80"),
            ("bypass-tcp-bridge-host", "tcp", "172.17.0.1", "80"),
            ("bypass-tcp-desktop-host", "tcp", "192.168.65.254", "80"),
            ("bypass-tcp-private-lan", "tcp", "10.0.0.1", "80"),
            (
                "bypass-tcp-link-local-neighbour",
                "tcp",
                "169.254.7.2",
                "8080",
            ),
            ("bypass-tcp-host-loopback-origin", "tcp", "127.0.0.1", &p),
            (
                "bypass-tcp-ipv6-external",
                "tcp",
                "2606:4700:4700::1111",
                "443",
            ),
            ("bypass-tcp-ipv4-mapped", "tcp", "::ffff:1.1.1.1", "443"),
            (
                "bypass-tcp-nat64-metadata",
                "tcp",
                "64:ff9b::a9fe:a9fe",
                "80",
            ),
            ("bypass-udp-external", "udp", "1.1.1.1", "443"),
            (
                "bypass-udp-ipv6-external",
                "udp",
                "2606:4700:4700::1111",
                "53",
            ),
        ] {
            let line = w(&["egress-direct", kind, ip, port]);
            // The environment's own loopback has nothing on the origin's
            // port: the host's loopback is another namespace's.
            let how = if ip == "127.0.0.1" { "local" } else { "remote" };
            let mechanism = mechanism(&line, how);
            assert_ne!(mechanism, "unexpected", "{case}: {line}");
            assert!(
                !line.contains("connected") && !line.contains("sent"),
                "{case}: {line}"
            );
            evidence(case, &format!("{line} mechanism={mechanism}"));
        }
        assert_eq!(
            origin.accepted(),
            0,
            "a direct attempt reached the host's origin"
        );

        // The proxy's address on any other port: nothing listens.
        for port in ["22", "80", "443", "8081"] {
            let line = w(&["egress-direct", "tcp", "169.254.7.1", port]);
            assert_eq!(field(&line, "name"), Some("ECONNREFUSED"), "{line}");
        }
        evidence(
            "bypass-proxy-address-other-ports",
            "ECONNREFUSED-x4 mechanism=topology-nothing-listening",
        );

        // DNS, direct: no resolver answers, over UDP or TCP.
        for (case, ip) in [
            ("bypass-dns-external", "8.8.8.8"),
            ("bypass-dns-embedded-runtime-resolver", "127.0.0.11"),
            ("bypass-dns-local-stub", "127.0.0.53"),
            ("bypass-dns-desktop-host", "192.168.65.7"),
            ("bypass-dns-ipv6-external", "2001:4860:4860::8888"),
        ] {
            let line = w(&["egress-dns", ip]);
            assert!(!line.contains("udp-answered"), "{case}: {line}");
            assert!(!line.contains("tcp-connected"), "{case}: {line}");
            evidence(case, &line);
        }
        let line = w(&["egress-resolve", ORIGIN]);
        assert!(line.starts_with("unresolved"), "{line}");
        evidence("bypass-library-resolver", &line);
        let line = w(&["egress-resolve", "example.com"]);
        assert!(line.starts_with("unresolved"), "{line}");
        evidence("bypass-library-resolver-public-name", &line);

        // Raw, packet, ICMP and virtual sockets.
        let line = w(&["egress-raw"]);
        let part = |name: &str| {
            line.split("; ")
                .find_map(|p| p.strip_prefix(&format!("{name}: ")))
                .unwrap()
                .to_owned()
        };
        for (case, name, kind) in [
            ("bypass-raw-ipv4", "raw4", "caps"),
            ("bypass-raw-ipv6", "raw6", "caps"),
            ("bypass-packet", "packet", "caps"),
            ("bypass-vsock", "vsock", "seccomp"),
        ] {
            let found = part(name);
            assert!(found.starts_with("errno="), "{case}: {found}");
            evidence(
                case,
                &format!("{found} mechanism={}", mechanism(&found, kind)),
            );
        }
        let ping = part("ping");
        // Where the platform admits an ICMP socket at all, it reaches
        // nothing; where it does not, the platform refused it.
        assert!(
            ping.starts_with("send-errno=101") || ping.starts_with("socket-errno="),
            "{ping}"
        );
        let how = if ping.starts_with("send-") {
            "topology-no-route"
        } else {
            "platform-or-capabilities"
        };
        evidence("bypass-icmp", &format!("{ping} mechanism={how}"));

        // Proxy variables: unset, or pointed elsewhere by the process
        // itself — either way there is no other path.
        let line = ev.workload_with(
            &container,
            &["HTTPS_PROXY=http://1.1.1.1:3128"],
            &["egress-via-variable", ORIGIN, &p],
        );
        assert!(line.contains("ENETUNREACH"), "{line}");
        evidence("bypass-proxy-variable-redirected", &line);
        let line = ev.workload_with(
            &container,
            &["HTTPS_PROXY=http://169.254.7.2:8080"],
            &["egress-via-variable", ORIGIN, &p],
        );
        assert!(line.contains("ENETUNREACH"), "{line}");
        evidence("bypass-proxy-variable-other-peer", &line);
        assert_eq!(origin.accepted(), 0);
        evidence("bypass-origin-never-reached", "0-connections");
        destroy(&socket, &ev, (&e, &r), Some(&container));
    }

    // ---- the proxy variables are the broker's ----------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn ambient_proxy_settings_never_reach_an_environment() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("ambient");
        let socket = dir.socket();
        // A home whose runtime client configuration would inject proxies,
        // and proxy variables in the broker's own environment.
        let home = dir.workspace("home");
        std::fs::create_dir_all(home.join(".docker")).unwrap();
        std::fs::write(
            home.join(".docker").join("config.json"),
            r#"{"proxies":{"default":{"httpProxy":"http://proxy.corp.example:3128","httpsProxy":"http://proxy.corp.example:3128","noProxy":"*"}}}"#,
        )
        .unwrap();
        let fixture = dir.resolver_fixture();
        let home_text = home.display().to_string();
        let broker = Broker::start(
            &socket,
            &Start {
                evidence_egress: Some(&fixture),
                ambient: &[
                    ("HOME", &home_text),
                    ("HTTP_PROXY", "http://proxy.corp.example:3128"),
                    ("HTTPS_PROXY", "http://proxy.corp.example:3128"),
                    ("ALL_PROXY", "socks5://proxy.corp.example:1080"),
                    ("NO_PROXY", "*"),
                    ("https_proxy", "http://proxy.corp.example:3128"),
                ],
                ..Start::default()
            },
        );
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(vec![target(ORIGIN, 443)], 4, 1 << 20, 1 << 20),
            &ev,
        );
        let (container, measurement) = prepared_clean(&socket, &ev, &s, &broker);
        assert_eq!(
            verdict(&measurement, I::HostProxyEnvironment),
            Verdict::Pass
        );
        let seen = ev.workload(&container, &["egress-env"]);
        let mut expected: Vec<String> = profile::PROXY_VARIABLES
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect();
        expected.sort();
        assert_eq!(seen.lines().collect::<Vec<_>>(), expected, "{seen}");
        assert!(!seen.contains("corp.example") && !seen.contains("NO_PROXY=*"));
        evidence("proxy-variables-broker-owned", "exactly-8-broker-values");
        evidence("proxy-variables-ambient-ignored", "no-inherited-value");
        evidence("runtime-client-config-proxies-ignored", "no-injected-value");
        destroy(&socket, &ev, (&e, &r), Some(&container));
    }

    // ---- weakened topologies, built here and measured by the broker ------

    /// A test-only environment container: the strict plan's words with the
    /// environment's labels and `extra` options. **Test code only.**
    fn test_only_environment(
        ev: &Evidence,
        seccomp: &Path,
        workspace: &Path,
        (environment, run): (&EnvironmentId, &RunId),
        network: &str,
        proxy_variables: bool,
    ) -> String {
        let mut argv: Vec<String> = vec!["create".into(), "--pull".into(), "never".into()];
        for (key, value) in [
            (profile::LABEL_OWNER, profile::LABEL_OWNER_VALUE.to_owned()),
            (
                profile::LABEL_SCHEMA,
                profile::LABEL_SCHEMA_VALUE.to_owned(),
            ),
            (profile::LABEL_STORE, store().as_str().to_owned()),
            (profile::LABEL_ENVIRONMENT, environment.as_str().to_owned()),
            (profile::LABEL_RUN, run.as_str().to_owned()),
            (
                profile::LABEL_PROFILE,
                EnvironmentProfile::OciStrict.label().to_owned(),
            ),
            (profile::LABEL_ROLE, "environment".to_owned()),
        ] {
            argv.push("--label".into());
            argv.push(format!("{key}={value}"));
        }
        if proxy_variables {
            for (name, value) in profile::PROXY_VARIABLES {
                argv.push("--env".into());
                argv.push(format!("{name}={value}"));
            }
        }
        for word in [
            "--user".to_owned(),
            format!("{}:{}", profile::SANDBOX_UID, profile::SANDBOX_GID),
            "--read-only".to_owned(),
            "--cap-drop".to_owned(),
            "ALL".to_owned(),
            "--security-opt".to_owned(),
            "no-new-privileges=true".to_owned(),
            "--security-opt".to_owned(),
            format!("seccomp={}", seccomp.display()),
            "--ipc".to_owned(),
            "private".to_owned(),
            "--cgroupns".to_owned(),
            "private".to_owned(),
            "--network".to_owned(),
            network.to_owned(),
        ] {
            argv.push(word);
        }
        for (target, options) in profile::TMPFS {
            argv.push("--tmpfs".into());
            argv.push(format!("{target}:{options}"));
        }
        argv.push("--mount".into());
        argv.push(format!(
            "type=bind,source={},target={},bind-propagation=rprivate",
            workspace.display(),
            profile::WORKSPACE_TARGET
        ));
        for word in [
            "--workdir".to_owned(),
            profile::WORKSPACE_TARGET.to_owned(),
            "--pids-limit".to_owned(),
            profile::PIDS_LIMIT.to_string(),
            "--memory".to_owned(),
            profile::MEMORY_BYTES.to_string(),
            "--memory-swap".to_owned(),
            profile::MEMORY_SWAP_BYTES.to_string(),
            "--cpus".to_owned(),
            "2".to_owned(),
        ] {
            argv.push(word);
        }
        for (name, value) in [
            ("nofile", profile::RLIMIT_NOFILE),
            ("nproc", profile::RLIMIT_NPROC),
            ("fsize", profile::RLIMIT_FSIZE),
            ("core", profile::RLIMIT_CORE),
        ] {
            argv.push("--ulimit".into());
            argv.push(format!("{name}={value}:{value}"));
        }
        for word in [
            "--oom-score-adj".to_owned(),
            profile::OOM_SCORE_ADJ.to_string(),
            "--restart".to_owned(),
            "no".to_owned(),
            "--log-driver".to_owned(),
            "none".to_owned(),
            "--entrypoint".to_owned(),
            profile::PROBE_PATH.to_owned(),
            ev.fixture_image.clone(),
            profile::PROBE_HOLD.to_owned(),
        ] {
            argv.push(word);
        }
        let words: Vec<&str> = argv.iter().map(String::as_str).collect();
        let id = ev.docker_ok(&words).trim().to_owned();
        CREATED.lock().unwrap().push(id.clone());
        ev.docker_ok(&["container", "start", &id]);
        id
    }

    /// A test-only extra peer in `environment`'s namespace, running the
    /// fixture's `mode` as root with the one capability a low port needs.
    fn extra_peer(ev: &Evidence, environment: &ContainerRef, mode: &[&str]) -> String {
        let mut words = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--network".to_owned(),
            format!("container:{}", environment.as_str()),
            "--user".to_owned(),
            "0:0".to_owned(),
            "--cap-drop".to_owned(),
            "ALL".to_owned(),
            "--cap-add".to_owned(),
            "NET_BIND_SERVICE".to_owned(),
            "--entrypoint".to_owned(),
            FIXTURE.to_owned(),
            ev.fixture_image.clone(),
        ];
        words.extend(mode.iter().map(|m| (*m).to_owned()));
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let id = ev.docker_ok(&refs).trim().to_owned();
        CREATED.lock().unwrap().push(id.clone());
        std::thread::sleep(Duration::from_millis(500));
        id
    }

    fn seccomp_file(socket: &Path) -> PathBuf {
        std::fs::canonicalize(socket.parent().unwrap().join("oci-strict.seccomp.json")).unwrap()
    }

    fn failing(measurement: &EnvironmentMeasurement, expected: &[I], case: &str) -> String {
        // The probe answered within the broker's step: its report is there,
        // so the inside vantage is measured, not lost to a timeout.
        assert_ne!(
            verdict(measurement, I::ContainerUidGid),
            Verdict::Unobservable,
            "{case}: the probe's report did not arrive; failing {:?}",
            not_passing(measurement)
        );
        for invariant in expected {
            assert_eq!(
                verdict(measurement, *invariant),
                Verdict::Fail,
                "{case}: {invariant:?} not caught; failing {:?}",
                not_passing(measurement)
            );
        }
        format!(
            "detected:{};measured-in-{}ms",
            expected
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>()
                .join("+"),
            measurement.measure_ms.get()
        )
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn weakened_topologies_are_detected() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("weakened");
        let socket = dir.socket();
        let fixture = dir.resolver_fixture();
        let broker = Broker::evidence(&socket, &fixture);
        let workspace = dir.workspace("ws");
        let seccomp = seccomp_file(&socket);
        let the_grant = || grant(vec![target(ORIGIN, 443)], 4, 1 << 20, 1 << 20);
        let fresh = |image: &str| {
            let (e, r) = (environment(), run());
            let s = spec(
                (&e, &r),
                &workspace,
                image,
                &ev.relay_sha256,
                the_grant(),
                &ev,
            );
            (e, r, s)
        };
        let mut detected = 0usize;

        // Ordinary bridged networking, proxy variables and all, is not
        // PROXY_ONLY: there is a route, and the checks find it — from inside
        // too, within the probe's step, whatever the destinations past the
        // route do (a runner's network leaves some silent).
        let (e, r, s) = fresh(&ev.fixture_image);
        let id = test_only_environment(&ev, &seccomp, &workspace, (&e, &r), "bridge", true);
        let (m, _, _) = measure(&socket, &ev, &s, &ContainerRef::new(id.clone()).unwrap());
        let outcome = failing(
            &m,
            &[
                I::HostNetworkIsolated,
                I::ContainerNetworkIsolated,
                I::ContainerDirectEgressRefused,
                I::ContainerDirectDnsRefused,
                I::ContainerProxyReachable,
                I::HostProxyRelay,
            ],
            "weakened-bridge-network",
        );
        ev.remove(&id);
        evidence("weakened-bridge-network", &outcome);
        detected += 1;

        // No relay: nothing answers at the proxy address.
        let (e, r, s) = fresh(&ev.fixture_image);
        let id = test_only_environment(&ev, &seccomp, &workspace, (&e, &r), "none", true);
        let (m, _, _) = measure(&socket, &ev, &s, &ContainerRef::new(id.clone()).unwrap());
        let outcome = failing(
            &m,
            &[I::HostProxyRelay, I::ContainerProxyReachable],
            "weakened-missing-relay",
        );
        ev.remove(&id);
        evidence("weakened-missing-relay", &outcome);
        detected += 1;

        // No proxy variables.
        let (e, r, s) = fresh(&ev.fixture_image);
        let id = test_only_environment(&ev, &seccomp, &workspace, (&e, &r), "none", false);
        let (m, _, _) = measure(&socket, &ev, &s, &ContainerRef::new(id.clone()).unwrap());
        let outcome = failing(
            &m,
            &[I::HostProxyEnvironment],
            "weakened-proxy-variables-removed",
        );
        ev.remove(&id);
        evidence("weakened-proxy-variables-removed", &outcome);
        detected += 1;

        // Drift of a clean environment: each change below, made after the
        // broker measured it clean, is found by the next measurement.
        type Weaken<'a> = Box<dyn Fn(&ContainerRef, &EnvironmentId) + 'a>;
        let cases: Vec<(&str, Weaken<'_>, Vec<I>)> = vec![
            (
                "drift-relay-stopped",
                Box::new(|_c, e| {
                    let relay = ev.labelled(e, Some(ContainerRole::Relay));
                    ev.docker_ok(&["container", "stop", "--time", "1", &relay[0]]);
                }),
                vec![I::HostProxyRelay, I::ContainerProxyReachable],
            ),
            (
                "drift-extra-peer-listening",
                Box::new(|c, _e| {
                    let _ = extra_peer(&ev, c, &["egress-listen", "169.254.7.1", "8081"]);
                }),
                vec![I::ContainerDirectEgressRefused],
            ),
            (
                "drift-fake-resolver-in-namespace",
                Box::new(|c, _e| {
                    let _ = extra_peer(&ev, c, &["egress-dns-answer", "127.0.0.11"]);
                }),
                vec![I::ContainerDirectDnsRefused],
            ),
            (
                "drift-setup-left-running",
                Box::new(|c, e| {
                    let mut words = vec![
                        "run".to_owned(),
                        "--detach".to_owned(),
                        "--network".to_owned(),
                        format!("container:{}", c.as_str()),
                    ];
                    for (key, value) in [
                        (profile::LABEL_OWNER, profile::LABEL_OWNER_VALUE),
                        (profile::LABEL_SCHEMA, profile::LABEL_SCHEMA_VALUE),
                        (profile::LABEL_STORE, store().as_str()),
                        (profile::LABEL_ENVIRONMENT, e.as_str()),
                        (profile::LABEL_PROFILE, "oci-strict"),
                        (profile::LABEL_ROLE, "setup"),
                    ] {
                        words.push("--label".to_owned());
                        words.push(format!("{key}={value}"));
                    }
                    let run_label = ev
                        .docker_ok(&[
                            "container",
                            "inspect",
                            "--format",
                            &format!("{{{{index .Config.Labels \"{}\"}}}}", profile::LABEL_RUN),
                            c.as_str(),
                        ])
                        .trim()
                        .to_owned();
                    words.push("--label".to_owned());
                    words.push(format!("{}={run_label}", profile::LABEL_RUN));
                    for w in [
                        "--entrypoint",
                        profile::PROBE_PATH,
                        &ev.fixture_image,
                        "hold",
                    ] {
                        words.push(w.to_owned());
                    }
                    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
                    let id = ev.docker_ok(&refs).trim().to_owned();
                    CREATED.lock().unwrap().push(id);
                }),
                vec![I::HostProxyRelay],
            ),
            (
                // The socket's directory opened to every uid (what the ACL
                // closes): the broker's own record of it no longer holds.
                "drift-egress-directory-opened",
                Box::new(|_c, e| {
                    std::fs::set_permissions(
                        egress_dir(&dir, e),
                        std::fs::Permissions::from_mode(0o711),
                    )
                    .unwrap();
                }),
                vec![I::HostProxyRelay],
            ),
        ];
        for (case, weaken, expected) in cases {
            let (e, r, s) = fresh(&ev.fixture_image);
            let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
            weaken(&container, &e);
            let (m, _, _) = measure(&socket, &ev, &s, &container);
            let outcome = failing(&m, &expected, case);
            let destroyed = destroy(&socket, &ev, (&e, &r), Some(&container));
            assert_eq!(destroyed.state, DestroyState::Removed, "{case}");
            evidence(case, &outcome);
            detected += 1;
        }

        // A relay that is not the pinned one is never started — the setup
        // would run it as root — and the environment is not kept.
        let (e, _r, s) = fresh(&ev.tampered_relay);
        let prepared = done(prepare(&socket, &ev, &s)).environment_prepare.unwrap();
        assert!(!prepared.retained);
        let m = prepared.measurement.unwrap();
        let outcome = failing(
            &m,
            &[I::HostRelayDigest, I::HostProxyRelay],
            "weakened-relay-tampered",
        );
        assert!(
            ev.labelled(&e, None).is_empty(),
            "a tampered environment was left"
        );
        assert!(broker.stderr().contains("relay_withheld"));
        assert!(!egress_dir(&dir, &e).exists());
        evidence(
            "weakened-relay-tampered",
            &format!("{outcome}+never-started+nothing-left"),
        );
        detected += 1;

        evidence(
            "weakened-topology-count",
            &format!("detected-{detected}-of-{detected}"),
        );
    }

    // ---- lifecycle: crash, restart, foreign resources --------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn crashes_and_restarts_fail_closed_and_leave_only_labelled_reapable_resources() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("lifecycle");
        let socket = dir.socket();
        let fixture = dir.resolver_fixture();
        let workspace = dir.workspace("ws");
        let the_grant = || grant(vec![target(ORIGIN, 443)], 4, 1 << 20, 1 << 20);

        // A broker that aborts after the relay started.
        for point in ["environment_network_set", "environment_relay_started"] {
            let mut crashing = Broker::start(
                &socket,
                &Start {
                    evidence_egress: Some(&fixture),
                    crash: Some(point),
                    ..Start::default()
                },
            );
            let (e, r) = (environment(), run());
            let s = spec(
                (&e, &r),
                &workspace,
                &ev.image,
                &ev.relay_sha256,
                the_grant(),
                &ev,
            );
            let (runtime, exe, cwd) = runtime(&ev);
            let sent = s.clone();
            let answer = try_exchange(
                &socket,
                move |common| {
                    Authorisation::EnvironmentPrepare(EnvironmentPrepareAuthorisation::new(
                        common, sent, runtime,
                    ))
                },
                (exe, cwd),
            );
            assert!(
                answer.is_none(),
                "{point}: an answer after a crash: {answer:?}"
            );
            let deadline = Instant::now() + PROMPT;
            while !crashing.exited() {
                assert!(Instant::now() < deadline, "the broker did not stop");
                std::thread::sleep(Duration::from_millis(20));
            }
            drop(crashing);
            let stale = egress_dir(&dir, &e);
            assert!(stale.exists(), "{point}: the dead broker's directory");
            // A fresh broker: the stale listener directory is removed at
            // start; the containers are found by their labels and roles.
            let broker = Broker::evidence(&socket, &fixture);
            assert!(
                !stale.exists(),
                "{point}: a stale directory survived a restart"
            );
            let listed = list(&socket, &ev);
            let mine: Vec<_> = listed
                .iter()
                .filter(|o| o.environment_id.as_ref() == Some(&e))
                .collect();
            assert!(mine.iter().all(|o| o.labels_exact), "{point}");
            let expected = if point == "environment_relay_started" {
                2
            } else {
                1
            };
            assert_eq!(mine.len(), expected, "{point}: {mine:?}");
            let destroyed = destroy(&socket, &ev, (&e, &r), None);
            assert_eq!(destroyed.state, DestroyState::Removed, "{point}");
            assert!(destroyed.egress.is_none(), "no listener survived the crash");
            assert!(ev.labelled(&e, None).is_empty(), "{point}: left behind");
            evidence(
                &format!("crash-{}", point.replace('_', "-")),
                &format!("stale-dir-removed+{expected}-found-by-label+reaped"),
            );
            drop(broker);
        }

        // A broker restart under a live environment: its proxy is gone, so
        // it measures as drift and is destroyed — never silently reconnected.
        let broker = Broker::evidence(&socket, &fixture);
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.image,
            &ev.relay_sha256,
            the_grant(),
            &ev,
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        drop(broker);
        let broker = Broker::evidence(&socket, &fixture);
        let (m, counters, _) = measure(&socket, &ev, &s, &container);
        let outcome = failing(
            &m,
            &[I::HostProxyRelay, I::ContainerProxyReachable],
            "restart-proxy-closed",
        );
        assert!(counters.is_none());
        let destroyed = destroy(&socket, &ev, (&e, &r), Some(&container));
        assert_eq!(destroyed.state, DestroyState::Removed);
        assert!(ev.labelled(&e, None).is_empty());
        evidence(
            "restart-proxy-closed-fails-closed",
            &format!("{outcome}+destroyed"),
        );

        // Foreign resources: containers that look like a relay or a setup
        // but are not this store's, and a network named like DireWolf's.
        let (fe, fr) = (environment(), run());
        let prefix = format!("dw-egress-foreign-{}", std::process::id());
        let create = |name: &str, labels: &[(&str, &str)]| {
            let mut argv = vec!["create".to_owned(), "--name".to_owned(), name.to_owned()];
            for (key, value) in labels {
                argv.push("--label".to_owned());
                argv.push(format!("{key}={value}"));
            }
            for word in [
                "--network",
                "none",
                "--entrypoint",
                profile::PROBE_PATH,
                &ev.image,
                profile::PROBE_HOLD,
            ] {
                argv.push(word.to_owned());
            }
            let words: Vec<&str> = argv.iter().map(String::as_str).collect();
            let id = ev.docker_ok(&words).trim().to_owned();
            CREATED.lock().unwrap().push(id.clone());
            id
        };
        let foreign = [
            create(
                &format!("{prefix}-other-store-relay"),
                &[
                    (profile::LABEL_OWNER, profile::LABEL_OWNER_VALUE),
                    (profile::LABEL_SCHEMA, profile::LABEL_SCHEMA_VALUE),
                    (profile::LABEL_STORE, "ffffffff"),
                    (profile::LABEL_ENVIRONMENT, fe.as_str()),
                    (profile::LABEL_RUN, fr.as_str()),
                    (profile::LABEL_PROFILE, "oci-strict"),
                    (profile::LABEL_ROLE, "relay"),
                ],
            ),
            create(&format!("{prefix}-unlabelled-relay-name"), &[]),
            create(
                &format!("{prefix}-other-owner-setup"),
                &[
                    (profile::LABEL_OWNER, "someone-else"),
                    (profile::LABEL_STORE, store().as_str()),
                    (profile::LABEL_ENVIRONMENT, fe.as_str()),
                    (profile::LABEL_ROLE, "setup"),
                ],
            ),
        ];
        let network = format!("{prefix}-net");
        ev.docker_ok(&["network", "create", "--internal", &network]);
        let listed = list(&socket, &ev);
        for id in &foreign {
            assert!(
                !listed.iter().any(|o| o.container.as_str() == id),
                "listed {id}"
            );
        }
        let destroyed = destroy(&socket, &ev, (&fe, &fr), None);
        assert_eq!(destroyed.state, DestroyState::AlreadyGone);
        for id in &foreign {
            assert!(ev.exists(id), "{id} was touched");
            ev.remove(id);
        }
        let networks = ev.docker_ok(&["network", "ls", "--format", "{{.Name}}"]);
        assert!(
            networks.lines().any(|n| n == network),
            "the foreign network was touched"
        );
        ev.docker_ok(&["network", "rm", &network]);
        evidence(
            "foreign-resources-untouched",
            "3-containers+1-network-survive",
        );
        drop(broker);
    }

    // ---- production: no fixture, no exception ----------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn a_production_broker_has_no_exception_and_no_fixture() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("production");
        let socket = dir.socket();
        let broker = Broker::start(&socket, &Start::default());
        assert!(!broker.stderr().contains("EVIDENCE EGRESS"));
        let origin = Origin::start(5, false);
        let p = origin.port.to_string();
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(
            (&e, &r),
            &workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(
                vec![
                    target(ORIGIN, origin.port),
                    target("localhost", origin.port),
                ],
                4,
                1 << 20,
                1 << 20,
            ),
            &ev,
        );
        // PROXY_ONLY needs no evidence flag: it is the product's topology.
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        evidence("production-proxy-only-prepared", "clean");
        // The fixture's names do not exist for the host's resolver …
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(
            field(&line, "decision"),
            Some("RESOLUTION_FAILED"),
            "{line}"
        );
        evidence("production-no-fixture-resolver", &line);
        // … and a granted name that resolves to loopback is blocked: there
        // is no exception mechanism at all.
        let line = ev.workload(
            &container,
            &["egress-connect", "localhost", &p, "localhost", "0"],
        );
        assert_eq!(field(&line, "decision"), Some("ADDRESS_BLOCKED"), "{line}");
        assert_eq!(origin.accepted(), 0);
        evidence("production-loopback-blocked-no-exception", &line);
        // A preparation without its grant or relay digest is refused before
        // anything is made.
        let (e2, r2) = (environment(), run());
        let mut bare = s.clone();
        bare.environment_id = e2.clone();
        bare.run_id = r2;
        bare.egress = None;
        assert_eq!(
            refusal(prepare(&socket, &ev, &bare)),
            BrokerRefusal::ProxyUnavailable
        );
        let mut probe_named = s.clone();
        probe_named.environment_id = e2.clone();
        probe_named.egress = Some(grant(vec![target(profile::PROXY_PROBE_HOST, 443)], 1, 1, 1));
        assert_eq!(
            refusal(prepare(&socket, &ev, &probe_named)),
            BrokerRefusal::Unsupported
        );
        assert!(ev.labelled(&e2, None).is_empty());
        evidence(
            "production-proxy-only-needs-its-grant",
            "proxy-unavailable+nothing-made",
        );
        destroy(&socket, &ev, (&e, &r), Some(&container));
    }
}
