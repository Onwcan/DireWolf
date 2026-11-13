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
//!   user, under its profile.
//! * The **authorisation** is played by this test (F-17, ADR-0061,
//!   Proposed): since F-17 the proxy carries a tunnel only while a workload
//!   the broker supervises holds an egress authorisation in the
//!   environment. Every tunnel of M5b's cases is opened while a held
//!   workload (`workload-sleep`, started through the broker's real
//!   `workload_start`) carries an authorisation allowing the environment's
//!   whole grant, so each case is still decided by the mechanism it always
//!   was; the same CONNECT with no workload held is refused
//!   (`authorisation-none-outside-a-workload`), and the F-17 cases hold
//!   narrower authorisations built here.
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
mod runtime_support;

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
        EgressBits, EgressByteBudget, EgressCell, EgressCounters, EgressDisposition as D,
        EgressGrant, EgressHost, EgressPort, EgressPrefix, EgressPrefixes, EgressTarget,
        EgressTargets, EgressTunnelLimit, WorkloadEgress, WorkloadEgressTarget,
        WorkloadEgressTargets,
    };
    use dwk_proto::brokerp::sandbox::{
        ContainerRef, ContainerRole, EnvironmentProfile, ImageId, NetworkTopology,
        SandboxInvariant as I, StoreInstance, Verdict, WorkspaceContract, required_invariants,
    };
    use dwk_proto::brokerp::workload::{
        ImagePath, WorkloadCollectAuthorisation, WorkloadCollectDone, WorkloadLaunch,
        WorkloadProgress, WorkloadSeconds, WorkloadSpec, WorkloadStartAuthorisation,
    };
    use dwk_proto::brokerp::{
        Authorisation, BrokerDone, BrokerGeneration, BrokerHello, BrokerOutcome, BrokerRefusal,
        Common, ContainerState, DestroyState, EnvironmentDestroyAuthorisation,
        EnvironmentDestroyDone, EnvironmentListAuthorisation, EnvironmentMeasureAuthorisation,
        EnvironmentMeasurement, EnvironmentPrepareAuthorisation, EnvironmentSpec, OutcomeResult,
        OwnedEnvironment, ProcessArgs, RuntimeSpec, StreamLimit,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::json::{Object, Value, to_canonical_string};
    use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath, ProcessArg};
    use dwk_sandbox_profile as profile;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);
    const PEER_WAIT: Duration = Duration::from_secs(150);
    const SUITE: &str = "sandbox-egress";
    /// What every line of this suite is (M5e.1): the released broker on a
    /// real runtime, this process playing the authority.
    const LEVEL: &str = "real-oci";
    /// Where the evidence image carries the test-only workload fixture.
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    /// The origin's name in every grant and in the resolver fixture.
    const ORIGIN: &str = "origin.test";

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    /// One line of evidence, printed only after the assertions before it
    /// held: the case, how it ended, and what enforced or observed it (M5e.1,
    /// OD-E1) -- canonical JSON, so no outcome can break the line. An
    /// outcome's quotes are still spelt `'`, as they always were.
    fn evidence(case: &str, outcome: &str, enforcement: &str) {
        let outcome = outcome.replace(['"', '\\'], "'");
        let mut fields = Object::new();
        for (key, value) in [
            ("suite", SUITE),
            ("case", case),
            ("outcome", outcome.as_str()),
            ("level", LEVEL),
            ("enforcement", enforcement),
        ] {
            fields
                .insert(key.to_owned(), Value::String(value.to_owned()))
                .unwrap();
        }
        println!(
            "SANDBOX-EVIDENCE {}",
            to_canonical_string(&Value::Object(fields))
        );
    }

    /// The vantage that measured `invariants`: the host's (the runtime's
    /// record and the broker's own), the probe's from inside, or both.
    fn vantage(invariants: &[I]) -> &'static str {
        let host = invariants.iter().any(|i| i.as_str().starts_with("HOST_"));
        let inside = invariants
            .iter()
            .any(|i| i.as_str().starts_with("CONTAINER_"));
        match (host, inside) {
            (true, false) => "measured-host",
            (false, true) => "measured-inside",
            _ => "measured-both",
        }
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
        /// The workload fixture's digest: what a held workload is started
        /// with (F-17).
        fixture_sha256: String,
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

        /// Whether the runtime holds `container`: a listing of exactly its id,
        /// never an inspection's failure (`runtime_support`).
        fn exists(&self, container: &str) -> bool {
            super::runtime_support::exists(|args| self.docker(args), container)
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
                .arg("--allow-shared-authority-uid")
                .arg("--allow-unverified-workspace");
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
            Self::serve(reply, eager, Duration::ZERO)
        }

        /// An origin that answers only `after` it first heard from a
        /// connection: time for the proxy to end the tunnel first (F-17).
        fn late(reply: usize, after: Duration) -> Self {
            Self::serve(reply, false, after)
        }

        fn serve(reply: usize, eager: bool, after: Duration) -> Self {
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
                                std::thread::sleep(after);
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
            // The evidence's own scratch directory: no group, no bound
            // proved (M5d.4), which this broker admits only because it
            // was started with --allow-unverified-workspace.
            workspace_bound: None,
            relay_sha256: Some(ContentDigest::new(relay.to_owned()).unwrap()),
            egress: Some(egress),
        }
    }

    fn try_exchange(
        socket: &Path,
        make: impl FnOnce(Common) -> Authorisation,
        fds: (OwnedFd, OwnedFd),
    ) -> Option<OutcomeResult> {
        try_exchange_as(socket, invocation(), make, Some(fds))
    }

    /// One exchange for `invocation`, carrying the runtime's descriptors or
    /// none (a workload's collection carries none).
    fn try_exchange_as(
        socket: &Path,
        invocation: InvocationId,
        make: impl FnOnce(Common) -> Authorisation,
        fds: Option<(OwnedFd, OwnedFd)>,
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
        let authorisation = make(Common::new(hello.channel.clone(), invocation));
        let bytes = authorisation.encode_frame().unwrap();
        if let Some(fds) = fds {
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
        } else {
            stream.write_all(&bytes).unwrap();
        }
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
        let required = required_invariants(
            NetworkTopology::ProxyOnly,
            WorkspaceContract::UnverifiedEvidence,
        );
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

    // ---- F-17: the workload whose authorisation the proxy holds -----------

    /// A workload this test holds in an environment through the broker's
    /// real `workload_start` (F-17, ADR-0061, Proposed): the fixture's
    /// `workload-sleep`, its egress authorisation in force on the
    /// environment's proxy until it ends.
    struct Held {
        invocation: InvocationId,
        generation: BrokerGeneration,
    }

    /// Start `workload-sleep seconds` in `container`, carrying `egress`.
    fn hold(
        socket: &Path,
        ev: &Evidence,
        (spec, container): (&EnvironmentSpec, &ContainerRef),
        seconds: u32,
        egress: WorkloadEgress,
    ) -> Held {
        let invocation = invocation();
        let (runtime, exe, cwd) = runtime(ev);
        let (spec, container) = (spec.clone(), container.clone());
        let seconds_text = seconds.to_string();
        let work = WorkloadSpec {
            executable: ImagePath::new(FIXTURE).unwrap(),
            executable_sha256: ContentDigest::new(ev.fixture_sha256.clone()).unwrap(),
            args: ProcessArgs::new(
                ["workload-sleep", seconds_text.as_str()]
                    .iter()
                    .map(|a| ProcessArg::new(*a).unwrap())
                    .collect(),
            )
            .unwrap(),
            stream_limit: StreamLimit::new(4096).unwrap(),
            wall_clock: WorkloadSeconds::new(seconds.saturating_add(30).min(600)).unwrap(),
            launch: WorkloadLaunch::Direct,
        };
        let answer = try_exchange_as(
            socket,
            invocation.clone(),
            move |common| {
                Authorisation::WorkloadStart(
                    WorkloadStartAuthorisation::new(common, spec, container, runtime, work)
                        .with_egress(Some(egress)),
                )
            },
            Some((exe, cwd)),
        )
        .expect("no answer to a held workload's start");
        let generation = done(answer).workload_start.unwrap().generation;
        Held {
            invocation,
            generation,
        }
    }

    /// One collection of a held workload.
    fn collect(socket: &Path, held: &Held) -> WorkloadCollectDone {
        let generation = held.generation.clone();
        let answer = try_exchange_as(
            socket,
            held.invocation.clone(),
            move |common| {
                Authorisation::WorkloadCollect(WorkloadCollectAuthorisation::new(
                    common, generation,
                ))
            },
            None,
        )
        .expect("no answer to a collection");
        done(answer).workload_collect.unwrap()
    }

    /// Collections until the held workload has ended: its last.
    fn ended(socket: &Path, held: &Held) -> WorkloadCollectDone {
        let deadline = Instant::now() + PEER_WAIT;
        loop {
            let collected = collect(socket, held);
            if collected.progress != WorkloadProgress::Running {
                return collected;
            }
            assert!(Instant::now() < deadline, "the held workload never ended");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// An authorisation allowing every address of every destination of
    /// `spec`'s grant, in every cell: M5b's cases decided exactly as before.
    fn the_whole_grant(spec: &EnvironmentSpec) -> WorkloadEgress {
        let grant = spec.egress.as_ref().unwrap();
        let destinations: Vec<(&str, u16)> = grant
            .targets
            .iter()
            .map(|t| (t.host.as_str(), t.port.get()))
            .collect();
        WorkloadEgress::uniform(&destinations, true, false).unwrap()
    }

    /// A clean `PROXY_ONLY` preparation's container, a workload held in it
    /// whose authorisation allows the whole grant (E6).
    fn prepared_held(
        socket: &Path,
        ev: &Evidence,
        spec: &EnvironmentSpec,
        broker: &Broker,
    ) -> (ContainerRef, EnvironmentMeasurement) {
        let (container, measurement) = prepared_clean(socket, ev, spec, broker);
        let _held = hold(
            socket,
            ev,
            (spec, &container),
            WORKLOAD_HOLD_SECONDS,
            the_whole_grant(spec),
        );
        (container, measurement)
    }

    /// How long a held workload sleeps: past any case; the environment's
    /// destruction ends it first.
    const WORKLOAD_HOLD_SECONDS: u32 = 540;

    /// A cell allowing exactly the pieces `allowed` names, with an optional
    /// per-tunnel download bound.
    fn cell(allowed: &[bool], cap: Option<u64>) -> EgressCell {
        EgressCell {
            allowed: EgressBits::from_pieces(allowed).unwrap(),
            max_tunnel_download_bytes: cap.map(|c| EgressByteBudget::new(c).unwrap()),
        }
    }

    /// One destination's four cells: `novel` before the workspace is
    /// exposed, `exposed` after, whether reached or not unless `seen` says.
    fn destination(
        (host, port): (&str, u16),
        seen: bool,
        pristine: &EgressCell,
        exposed: &EgressCell,
    ) -> WorkloadEgressTarget {
        WorkloadEgressTarget {
            host: EgressHost::new(host.to_owned()).unwrap(),
            port: EgressPort::new(port).unwrap(),
            seen,
            novel_pristine: pristine.clone(),
            novel_exposed: exposed.clone(),
            seen_pristine: pristine.clone(),
            seen_exposed: exposed.clone(),
        }
    }

    /// An authorisation over `prefixes` and `targets`, checked as the broker
    /// will check it.
    fn authorisation(prefixes: &[&str], targets: Vec<WorkloadEgressTarget>) -> WorkloadEgress {
        let egress = WorkloadEgress {
            exposed: false,
            prefixes: EgressPrefixes::new(
                prefixes
                    .iter()
                    .map(|p| EgressPrefix::new((*p).to_owned()).unwrap())
                    .collect(),
            )
            .unwrap(),
            targets: WorkloadEgressTargets::new(targets).unwrap(),
        };
        egress.check().unwrap();
        egress
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
            "measured-both",
        );
        // The runtime's own record of this environment, measured clean, kept
        // for the broker's in-process judgement of each hard rule broken in
        // it (M5e.2, R3) -- only when the evidence task asks for it. The
        // runtime never runs a weakened record.
        if let Ok(captured) = std::env::var("DW_CAPTURED_RECORD_DIR") {
            let captured = Path::new(&captured);
            let record = ev.docker_ok(&["container", "inspect", container.as_str()]);
            std::fs::write(captured.join("proxy-only-record.json"), record).unwrap();
            let facts = format!(
                "environment_id={}\nrun_id={}\nstore={}\nimage={}\nworkspace_path={}\nsocket={}\n",
                s.environment_id.as_str(),
                s.run_id.as_str(),
                s.store.as_str(),
                s.image.as_str(),
                s.workspace_path.as_str(),
                ev.socket,
            );
            std::fs::write(captured.join("proxy-only-spec.txt"), facts).unwrap();
        }
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
            evidence(case, "pass", vantage(&[invariant]));
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
            "proxy-only-topology",
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
        evidence(
            "proxy-only-relay-shares-the-namespace-unprivileged",
            "pass",
            "proxy-only-topology",
        );

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
        evidence(
            "proxy-only-listener-open",
            "socket-present-root-0700",
            "egress-socket-acl",
        );
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
        evidence(
            "proxy-only-socket-mounted-in-relay-only",
            "relay-only",
            "proxy-only-topology",
        );

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
            "egress-socket-acl",
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
        evidence(
            "proxy-only-listed-with-roles",
            "environment+relay",
            "exact-label-ownership",
        );

        // Measured again: clean; the counters say what the probe asked.
        let (again, counters, state) = measure(&socket, &ev, &s, &container);
        assert_eq!(state, ContainerState::Running);
        assert!(not_passing(&again).is_empty(), "{:?}", not_passing(&again));
        let counters = counters.unwrap();
        assert!(count(&counters, D::TargetNotGranted) >= 2, "{counters:?}");
        evidence("proxy-only-measure-clean-again", "pass", "measured-both");

        // Destroyed: every role removed, the listener closed, the counters
        // returned.
        let destroyed = destroy(&socket, &ev, (&e, &r), Some(&container));
        assert_eq!(destroyed.state, DestroyState::Removed);
        assert!(ev.labelled(&e, None).is_empty());
        assert!(!ev.exists(&relays[0]));
        evidence(
            "proxy-only-destroy-removes-every-role",
            "removed",
            "exact-label-cleanup",
        );
        assert!(!edir.exists(), "the listener's directory is gone");
        evidence(
            "proxy-only-destroy-closes-listener",
            "closed",
            "egress-listener-lifecycle",
        );
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
            "egress-disposition-counters",
        );
        let again = destroy(&socket, &ev, (&e, &r), Some(&container));
        assert_eq!(again.state, DestroyState::AlreadyGone);
        assert!(again.egress.is_none());
        evidence(
            "proxy-only-destroy-idempotent",
            "already-gone",
            "exact-label-cleanup",
        );
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

        // F-17 (E6): with no workload held, no authorisation is in force and
        // the proxy refuses a granted destination before it resolves the
        // name -- a name that would fail resolution is refused the same way
        // -- and the origin is never dialled.
        for host in [ORIGIN, "fail.test"] {
            let line = run_fixture(&["egress-connect", host, &p, host, "0"]);
            assert!(line.contains("403"), "{line}");
            assert_eq!(
                field(&line, "decision"),
                Some(D::NotAuthorised.as_str()),
                "{line}"
            );
        }
        assert_eq!(origin.accepted(), 0);
        evidence(
            "authorisation-none-outside-a-workload",
            "403-NOT_AUTHORISED-before-resolution",
            "connect-proxy:workload-authorisation",
        );
        let _held = hold(
            &socket,
            &ev,
            (&s, &container),
            WORKLOAD_HOLD_SECONDS,
            the_whole_grant(&s),
        );

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
        evidence(
            "tunnel-granted-carries-bytes",
            &line,
            "relay-and-connect-proxy-grant",
        );

        // The broker's own variable leads a tool that honours it there.
        let line = ev.workload(&container, &["egress-via-variable", ORIGIN, &p]);
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(origin.accepted(), 2);
        evidence(
            "tunnel-via-proxy-variable",
            &line,
            "relay-and-connect-proxy-grant",
        );

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
            // Which part of the proxy decided, by the decision it gave.
            let enforcement = match decision {
                D::TargetNotGranted => "connect-proxy:grant",
                D::TargetNotCanonical => "connect-proxy:canonical-target",
                D::AddressBlocked | D::AddressMixed => "connect-proxy:address-guard",
                D::ResolutionFailed => "connect-proxy:resolver",
                D::ResolutionTimeout => "connect-proxy:resolver-deadline",
                other => panic!("{case}: {other:?} is no refusal"),
            };
            evidence(case, &line, enforcement);
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
        evidence(
            "resolver-rebinding-pinned",
            &line,
            "connect-proxy:address-guard",
        );

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
            // Tunnelled, then closed before anything was dialled: the
            // server-name check on the first bytes.
            evidence(case, &line, "connect-proxy:server-name");
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
            "egress-disposition-counters",
        );
        evidence(
            "audit-observability-no-payload",
            "no-host-or-payload-in-counters-or-log",
            "egress-disposition-counters",
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
        let (container, _) = prepared_held(&socket, &ev, &s, &broker);
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "65536"]);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            origin.received().len() <= 8192,
            "{}",
            origin.received().len()
        );
        evidence(
            "budget-upload-exhausted",
            &line,
            "connect-proxy:upload-budget",
        );
        // Spent stays spent: the next tunnel is closed before it is dialled.
        let before = origin.accepted();
        let next = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "10"]);
        assert_eq!(origin.accepted(), before, "{next}");
        evidence(
            "budget-upload-spent-stays-spent",
            &next,
            "connect-proxy:upload-budget",
        );
        let counters = destroy(&socket, &ev, (&e, &r), Some(&container))
            .egress
            .unwrap();
        assert!(count(&counters, D::UploadBudget) >= 2, "{counters:?}");
        assert_eq!(counters.bytes_upstream.get(), 8192);
        evidence(
            "budget-upload-exact-at-socket",
            "8192-of-8192",
            "connect-proxy:upload-budget",
        );

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
        let (container, _) = prepared_held(&socket, &ev, &s, &broker);
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        let received: usize = field(&line, "received").unwrap().parse().unwrap();
        assert!(received <= 4096, "{line}");
        let counters = destroy(&socket, &ev, (&e, &r), Some(&container))
            .egress
            .unwrap();
        assert_eq!(count(&counters, D::DownloadBudget), 1, "{counters:?}");
        assert_eq!(counters.bytes_downstream.get(), 4096);
        evidence(
            "budget-download-exhausted",
            &line,
            "connect-proxy:download-budget",
        );

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
        let (container, _) = prepared_held(&socket, &ev, &s, &broker);
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
        evidence("budget-tunnel-limit", &line, "connect-proxy:tunnel-limit");
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
        let (container, _) = prepared_held(&socket, &ev, &s, &broker);
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
            "connect-proxy:upload-budget",
        );
        drop(broker);
    }

    // ---- F-17: a workload's egress authorisation in the real topology ----

    /// The fixture started in `container` in the background; its line is
    /// read when it ends ([`line_of`]).
    fn spawned(ev: &Evidence, container: &ContainerRef, args: &[&str]) -> Child {
        Command::new(&ev.runtime)
            .env_clear()
            .env("HOME", std::env::temp_dir())
            .arg("--host")
            .arg(format!("unix://{}", ev.socket))
            .args(["container", "exec", container.as_str(), FIXTURE])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn line_of(child: Child) -> String {
        let out = child.wait_with_output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// Until `origin` has accepted `n` connections: the tunnel was dialled.
    fn dialled(origin: &Origin, n: usize) {
        let wait = Instant::now() + Duration::from_secs(10);
        while origin.accepted() < n {
            assert!(Instant::now() < wait, "the tunnel was never dialled");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// How many of a held workload's CONNECTs for its `target`th destination
    /// ended `disposition`, as its supervisor reported them.
    fn reported(collected: &WorkloadCollectDone, target: usize, disposition: D) -> u64 {
        collected
            .egress
            .as_ref()
            .unwrap()
            .targets
            .iter()
            .nth(target)
            .unwrap()
            .dispositions
            .iter()
            .find(|c| c.disposition == disposition)
            .map_or(0, |c| c.count.get())
    }

    /// A specification granting `origins`, on `workspace`.
    fn spec_to(workspace: &Path, ev: &Evidence, origins: &[(&str, u16)]) -> EnvironmentSpec {
        let (e, r) = (environment(), run());
        spec(
            (&e, &r),
            workspace,
            &ev.fixture_image,
            &ev.relay_sha256,
            grant(
                origins.iter().map(|(h, p)| target(h, *p)).collect(),
                8,
                1 << 20,
                1 << 20,
            ),
            ev,
        )
    }

    /// Destroy `container`: its proxy's counters.
    fn destroyed(
        socket: &Path,
        ev: &Evidence,
        s: &EnvironmentSpec,
        container: &ContainerRef,
    ) -> EgressCounters {
        destroy(socket, ev, (&s.environment_id, &s.run_id), Some(container))
            .egress
            .unwrap()
    }

    /// F-17 (ADR-0061, Proposed) at the broker, in the real topology: a
    /// workload's authorisation decides each tunnel by its destination, its
    /// address and the workspace's exposure, bounds what one tunnel carries
    /// back, and lives exactly as long as the workload.
    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn a_workloads_egress_authorisation_holds_in_the_real_topology() {
        let ev = Evidence::load();
        let _reaper = Reaper(ev.clone());
        let dir = Scratch::new("authorised");
        let socket = dir.socket();
        let broker = Broker::evidence(&socket, &dir.resolver_fixture());

        // One workload, four destinations: one allowed, one denied whole, one
        // denied at the address its name resolves to, one bounded per tunnel.
        // Pieces over one range (127.0.0.0/8): IPv4 in no range, IPv6, the
        // range's.
        let every = cell(&[true, true, true], None);
        let nothing = cell(&[false, false, false], None);
        let no_loopback = cell(&[true, true, false], None);
        let bounded = cell(&[true, true, true], Some(100));
        let allowed = Origin::start(5, false);
        let ranged = Origin::start(5, false);
        let capped = Origin::start(4096, true);
        let s = spec_to(
            &dir.workspace("one"),
            &ev,
            &[
                (ORIGIN, allowed.port),
                ("fail.test", allowed.port),
                (ORIGIN, ranged.port),
                (ORIGIN, capped.port),
            ],
        );
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        let held = hold(
            &socket,
            &ev,
            (&s, &container),
            12,
            authorisation(
                &["127.0.0.0/8"],
                vec![
                    destination((ORIGIN, allowed.port), false, &every, &every),
                    destination(("fail.test", allowed.port), false, &nothing, &nothing),
                    destination((ORIGIN, ranged.port), false, &no_loopback, &no_loopback),
                    destination((ORIGIN, capped.port), false, &bounded, &bounded),
                ],
            ),
        );
        let pa = allowed.port.to_string();
        let reached = ev.workload(&container, &["egress-connect", ORIGIN, &pa, ORIGIN, "10"]);
        assert!(reached.contains("HTTP/1.1 200"), "{reached}");
        assert_eq!(field(&reached, "received"), Some("5"), "{reached}");
        // Denied before the name is resolved: the resolver would have failed
        // it (`RESOLUTION_FAILED`), and nothing is dialled.
        let denied = ev.workload(
            &container,
            &["egress-connect", "fail.test", &pa, "fail.test", "0"],
        );
        assert!(denied.contains("403"), "{denied}");
        assert_eq!(
            field(&denied, "decision"),
            Some(D::PolicyDenied.as_str()),
            "{denied}"
        );
        assert_eq!(allowed.accepted(), 1);
        evidence(
            "authorisation-allowed-and-denied-same-workload",
            "200-reached+403-POLICY_DENIED-before-resolution",
            "connect-proxy:workload-authorisation",
        );
        let pr = ranged.port.to_string();
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &pr, ORIGIN, "0"]);
        assert!(line.contains("403"), "{line}");
        assert_eq!(
            field(&line, "decision"),
            Some(D::PolicyAddressDenied.as_str()),
            "{line}"
        );
        assert_eq!(ranged.accepted(), 0, "a denied address was dialled");
        evidence(
            "authorisation-address-range-denied",
            &line,
            "connect-proxy:workload-authorisation-address",
        );
        let pc = capped.port.to_string();
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &pc, ORIGIN, "0"]);
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(field(&line, "received"), Some("100"), "{line}");
        assert_eq!(capped.accepted(), 1);
        evidence(
            "authorisation-tunnel-output-bounded",
            &line,
            "connect-proxy:tunnel-output-bound",
        );
        // What the workload's tunnels did, as its supervisor reports it when
        // it ends: per destination, no payload.
        let report = ended(&socket, &held);
        let egress = report.egress.as_ref().unwrap();
        assert!(egress.exposed, "{egress:?}");
        let reach: Vec<bool> = egress.targets.iter().map(|t| t.reached).collect();
        assert_eq!(reach, [true, false, false, true], "{egress:?}");
        assert_eq!(reported(&report, 1, D::PolicyDenied), 1, "{egress:?}");
        assert_eq!(
            reported(&report, 2, D::PolicyAddressDenied),
            1,
            "{egress:?}"
        );
        assert_eq!(reported(&report, 3, D::TunnelOutputLimit), 1, "{egress:?}");
        assert_eq!(
            egress.targets.iter().nth(3).unwrap().bytes_downstream.get(),
            100
        );
        assert!(
            egress
                .targets
                .iter()
                .nth(2)
                .unwrap()
                .addresses
                .iter()
                .any(|a| a.address.as_str() == "127.0.0.1" && a.refused.get() == 1),
            "{egress:?}"
        );
        assert!(!format!("{egress:?}").contains(ORIGIN));
        evidence(
            "authorisation-report-per-destination",
            "reached-1+0+0+1;POLICY_DENIED;POLICY_ADDRESS_DENIED;TUNNEL_OUTPUT_LIMIT",
            "workload-supervisor-report",
        );

        // A tunnel open when its workload ends is ended with it, before the
        // origin's answer comes back; a CONNECT after it is refused. The
        // environment's init ends what the workload left -- the client here
        // with it (ADR-0052) -- so what the tunnel carried is read from the
        // supervisor's report, the broker's own vantage.
        let late = Origin::late(64, Duration::from_secs(20));
        let s2 = spec_to(&dir.workspace("two"), &ev, &[(ORIGIN, late.port)]);
        let (container2, _) = prepared_clean(&socket, &ev, &s2, &broker);
        let short = hold(&socket, &ev, (&s2, &container2), 5, the_whole_grant(&s2));
        let pl = late.port.to_string();
        let open = spawned(
            &ev,
            &container2,
            &["egress-connect", ORIGIN, &pl, ORIGIN, "0"],
        );
        dialled(&late, 1);
        let last = ended(&socket, &short);
        let _ = line_of(open);
        let tunnel = last.egress.as_ref().unwrap().targets.iter().next().unwrap();
        assert_eq!(reported(&last, 0, D::WorkloadEnded), 1, "{last:?}");
        assert_eq!(tunnel.bytes_downstream.get(), 0, "{last:?}");
        assert!(!tunnel.reached, "{last:?}");
        evidence(
            "authorisation-ends-with-the-workload",
            "WORKLOAD_ENDED=1;bytes-back-0;not-reached",
            "connect-proxy:workload-lifetime",
        );
        let after = ev.workload(&container2, &["egress-connect", ORIGIN, &pl, ORIGIN, "0"]);
        assert_eq!(
            field(&after, "decision"),
            Some(D::NotAuthorised.as_str()),
            "{after}"
        );
        assert_eq!(late.accepted(), 1);
        evidence(
            "authorisation-none-after-the-workload",
            &after,
            "connect-proxy:workload-authorisation",
        );

        // Exposure inside one workload: a tunnel to a destination whose
        // exposed cell denies it is open, waiting for its origin; the first
        // byte another tunnel carries back exposes the workspace, and the
        // open tunnel is ended before its origin answers -- its client gets
        // nothing -- and a novel destination is refused from then on.
        let all = cell(&[true, true], None);
        let none = cell(&[false, false], None);
        let first = Origin::start(5, false);
        let slow = Origin::late(64, Duration::from_secs(6));
        let other = Origin::start(5, false);
        let s3 = spec_to(
            &dir.workspace("three"),
            &ev,
            &[
                (ORIGIN, first.port),
                (ORIGIN, slow.port),
                (ORIGIN, other.port),
            ],
        );
        let (container3, _) = prepared_clean(&socket, &ev, &s3, &broker);
        let _exposing = hold(
            &socket,
            &ev,
            (&s3, &container3),
            WORKLOAD_HOLD_SECONDS,
            authorisation(
                &[],
                vec![
                    destination((ORIGIN, first.port), false, &all, &all),
                    destination((ORIGIN, slow.port), false, &all, &none),
                    destination((ORIGIN, other.port), false, &all, &none),
                ],
            ),
        );
        let ps = slow.port.to_string();
        let waiting = spawned(
            &ev,
            &container3,
            &["egress-connect", ORIGIN, &ps, ORIGIN, "0"],
        );
        dialled(&slow, 1);
        let pf = first.port.to_string();
        let line = ev.workload(&container3, &["egress-connect", ORIGIN, &pf, ORIGIN, "0"]);
        assert_eq!(field(&line, "received"), Some("5"), "{line}");
        let revoked = line_of(waiting);
        assert!(revoked.contains("HTTP/1.1 200"), "{revoked}");
        assert_eq!(field(&revoked, "received"), Some("0"), "{revoked}");
        evidence(
            "exposure-revokes-an-open-tunnel",
            &revoked,
            "connect-proxy:workspace-exposure",
        );
        let po = other.port.to_string();
        let line = ev.workload(&container3, &["egress-connect", ORIGIN, &po, ORIGIN, "0"]);
        assert_eq!(
            field(&line, "decision"),
            Some(D::PolicyDenied.as_str()),
            "{line}"
        );
        assert_eq!(other.accepted(), 0);
        evidence(
            "exposure-novel-refused-after-first-origin-byte",
            &line,
            "connect-proxy:workspace-exposure",
        );

        // Exposure from a sibling: two environments on one workspace root,
        // a third on another, the second and third refusing a novel
        // destination once their root is exposed and allowing a reached one.
        // The first one's origin byte exposes the root it shares, so the
        // sibling's novel destination is refused; the other root is
        // untouched -- its tunnel admitted -- and that tunnel, whose own first
        // byte then exposes its root, is held to its destination's seen cell
        // and carries the answer.
        let origin = Origin::start(5, false);
        let shared = dir.workspace("shared");
        let apart = dir.workspace("apart");
        let reached_one = [(ORIGIN, origin.port)];
        let (s4, s5, s6) = (
            spec_to(&shared, &ev, &reached_one),
            spec_to(&shared, &ev, &reached_one),
            spec_to(&apart, &ev, &reached_one),
        );
        let (c4, _) = prepared_clean(&socket, &ev, &s4, &broker);
        let (c5, _) = prepared_clean(&socket, &ev, &s5, &broker);
        let (c6, _) = prepared_clean(&socket, &ev, &s6, &broker);
        let narrow = || {
            let (host, port) = reached_one[0];
            authorisation(
                &[],
                vec![WorkloadEgressTarget {
                    host: EgressHost::new(host.to_owned()).unwrap(),
                    port: EgressPort::new(port).unwrap(),
                    seen: false,
                    novel_pristine: all.clone(),
                    novel_exposed: none.clone(),
                    seen_pristine: all.clone(),
                    seen_exposed: all.clone(),
                }],
            )
        };
        let _h4 = hold(
            &socket,
            &ev,
            (&s4, &c4),
            WORKLOAD_HOLD_SECONDS,
            the_whole_grant(&s4),
        );
        let _h5 = hold(&socket, &ev, (&s5, &c5), WORKLOAD_HOLD_SECONDS, narrow());
        let _h6 = hold(&socket, &ev, (&s6, &c6), WORKLOAD_HOLD_SECONDS, narrow());
        let p = origin.port.to_string();
        let line = ev.workload(&c4, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(field(&line, "received"), Some("5"), "{line}");
        let line = ev.workload(&c5, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(
            field(&line, "decision"),
            Some(D::PolicyDenied.as_str()),
            "{line}"
        );
        assert_eq!(origin.accepted(), 1);
        evidence(
            "exposure-sibling-on-the-shared-root",
            &line,
            "connect-proxy:workspace-exposure",
        );
        let line = ev.workload(&c6, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(field(&line, "received"), Some("5"), "{line}");
        assert_eq!(origin.accepted(), 2);
        evidence(
            "exposure-other-root-untouched",
            &line,
            "connect-proxy:workspace-exposure",
        );

        // Every ending counted by its disposition at destruction.
        let mut seen = std::collections::BTreeMap::new();
        for (spec, container) in [
            (&s, &container),
            (&s2, &container2),
            (&s3, &container3),
            (&s4, &c4),
            (&s5, &c5),
            (&s6, &c6),
        ] {
            let counters = destroyed(&socket, &ev, spec, container);
            for disposition in [
                D::PolicyDenied,
                D::PolicyAddressDenied,
                D::TunnelOutputLimit,
                D::WorkloadEnded,
                D::NotAuthorised,
                D::ExposureRevoked,
            ] {
                *seen.entry(disposition.as_str()).or_insert(0) += count(&counters, disposition);
            }
        }
        for (disposition, at_least) in [
            (D::PolicyDenied, 3),
            (D::PolicyAddressDenied, 1),
            (D::TunnelOutputLimit, 1),
            (D::WorkloadEnded, 1),
            (D::NotAuthorised, 1),
            (D::ExposureRevoked, 1),
        ] {
            assert!(seen[disposition.as_str()] >= at_least, "{seen:?}");
        }
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
            evidence(case, &format!("{line} mechanism={mechanism}"), mechanism);
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
            "topology-nothing-listening",
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
            evidence(case, &line, "topology-no-resolver");
        }
        let line = w(&["egress-resolve", ORIGIN]);
        assert!(line.starts_with("unresolved"), "{line}");
        evidence("bypass-library-resolver", &line, "topology-no-resolver");
        let line = w(&["egress-resolve", "example.com"]);
        assert!(line.starts_with("unresolved"), "{line}");
        evidence(
            "bypass-library-resolver-public-name",
            &line,
            "topology-no-resolver",
        );

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
            let mechanism = mechanism(&found, kind);
            evidence(case, &format!("{found} mechanism={mechanism}"), mechanism);
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
        evidence("bypass-icmp", &format!("{ping} mechanism={how}"), how);

        // Proxy variables: unset, or pointed elsewhere by the process
        // itself — either way there is no other path.
        let line = ev.workload_with(
            &container,
            &["HTTPS_PROXY=http://1.1.1.1:3128"],
            &["egress-via-variable", ORIGIN, &p],
        );
        assert!(line.contains("ENETUNREACH"), "{line}");
        evidence(
            "bypass-proxy-variable-redirected",
            &line,
            "topology-no-route",
        );
        let line = ev.workload_with(
            &container,
            &["HTTPS_PROXY=http://169.254.7.2:8080"],
            &["egress-via-variable", ORIGIN, &p],
        );
        assert!(line.contains("ENETUNREACH"), "{line}");
        evidence(
            "bypass-proxy-variable-other-peer",
            &line,
            "topology-no-route",
        );
        assert_eq!(origin.accepted(), 0);
        evidence(
            "bypass-origin-never-reached",
            "0-connections",
            "topology-no-route",
        );
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
        evidence(
            "proxy-variables-broker-owned",
            "exactly-8-broker-values",
            "launch-environment",
        );
        evidence(
            "proxy-variables-ambient-ignored",
            "no-inherited-value",
            "launch-environment",
        );
        evidence(
            "runtime-client-config-proxies-ignored",
            "no-injected-value",
            "launch-environment",
        );
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
        evidence("weakened-bridge-network", &outcome, "measured-both");
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
        evidence("weakened-missing-relay", &outcome, "measured-both");
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
        evidence(
            "weakened-proxy-variables-removed",
            &outcome,
            "measured-host",
        );
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
            evidence(case, &outcome, vantage(&expected));
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
            "relay-digest-pin",
        );
        detected += 1;

        evidence(
            "weakened-topology-count",
            &format!("detected-{detected}-of-{detected}"),
            "measured-both",
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
                "exact-label-cleanup",
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
            "measured-both",
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
            "exact-label-ownership",
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
        let (container, _) = prepared_held(&socket, &ev, &s, &broker);
        evidence("production-proxy-only-prepared", "clean", "measured-both");
        // The fixture's names do not exist for the host's resolver …
        let line = ev.workload(&container, &["egress-connect", ORIGIN, &p, ORIGIN, "0"]);
        assert_eq!(
            field(&line, "decision"),
            Some("RESOLUTION_FAILED"),
            "{line}"
        );
        evidence(
            "production-no-fixture-resolver",
            &line,
            "connect-proxy:resolver",
        );
        // … and a granted name that resolves to loopback is blocked: there
        // is no exception mechanism at all.
        let line = ev.workload(
            &container,
            &["egress-connect", "localhost", &p, "localhost", "0"],
        );
        assert_eq!(field(&line, "decision"), Some("ADDRESS_BLOCKED"), "{line}");
        assert_eq!(origin.accepted(), 0);
        evidence(
            "production-loopback-blocked-no-exception",
            &line,
            "connect-proxy:address-guard",
        );
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
            "broker-admission",
        );
        destroy(&socket, &ev, (&e, &r), Some(&container));
    }

    // ---- E6: one hard rule weakened in a real PROXY_ONLY environment -------

    /// ADR-0057's E6 (M5e.2, R3; the owner's R-B): a real `PROXY_ONLY`
    /// environment, prepared by the released broker along its production path
    /// -- its proxy opened, the environment created and started, the relay in
    /// the image hashed, the setup run, the relay started -- measured from
    /// both vantages and judged by the production decision, with exactly one
    /// hard rule of the environment weakened.
    ///
    /// The broker never asks for a weaker container: its plan spells
    /// `oci-strict` and nothing else (TX032, `plan_tests.rs`). So the
    /// weakening is the runtime's, as ADR-0057 §4 says one could arise: the
    /// broker is handed a runtime that does not do what the plan asks -- a
    /// test-only socket between the real client the authority hashed and the
    /// real daemon ([`faulty`]). It forwards every byte both ways unchanged
    /// but for one request, the environment's `create`, in which it changes
    /// the field (or the two fields) the matching weakening flag of M5a's real
    /// `NO_NETWORK` cases puts there (`sandbox_foundation.rs`). The daemon then
    /// records and runs exactly that container, and the broker's record of it
    /// and its probe's report are the daemon's and the kernel's own, read
    /// through the same socket and never changed: the socket keeps a copy of
    /// each, which this test checks and writes out for the evidence task to
    /// check again (`DW_E6_RAW_DIR`).
    ///
    /// **Test code only.** No product path reaches it; the broker under test
    /// is the released binary, unmodified, and the socket is a value the test
    /// -- playing the authority -- passes, as the authority passes the
    /// operator's. The conforming control goes through the same socket with
    /// no fault and must be kept, clean from both vantages, so a refusal below
    /// is the weakening's and never the socket's.
    mod e6 {
        use std::net::Shutdown;
        use std::os::unix::net::UnixListener;

        use dwk_proto::brokerp::sandbox::ProbeReport;
        use dwk_proto::json::{self, Number, ParseOptions};

        use super::*;

        /// `PROXY_ONLY`'s own invariants: the topology's, not hard rules.
        /// Reported for every case -- how a weakening and the topology
        /// interact is observed, never assumed (ADR-0057 §3, U3).
        const TOPOLOGY: [I; 4] = [
            I::HostProxyEnvironment,
            I::HostProxyRelay,
            I::HostRelayDigest,
            I::ContainerProxyReachable,
        ];

        /// The address the setup adds to the environment's loopback.
        const PROXY_ADDRESS: &str = "169.254.7.1/32";

        /// What a weakening needs to know of the evidence: the tag the task
        /// gave the product image, and the runtime's socket as the host has it.
        #[derive(Clone, Debug)]
        struct Facts {
            tag: String,
            runtime_socket: String,
        }

        /// One field (or two) of a `create` changed, in place.
        type Weaken = fn(&mut Object, &Facts);

        // ---- the JSON of a `create` and of a record ----------------------

        fn text_value(text: &str) -> Value {
            Value::String(text.to_owned())
        }

        fn int(value: i64) -> Value {
            Value::Number(Number::from_i64(value).unwrap())
        }

        /// The value at `path`.
        fn at<'a>(object: &'a Object, path: &[&str]) -> Option<&'a Value> {
            let (first, rest) = path.split_first()?;
            let value = object.get(first)?;
            if rest.is_empty() {
                return Some(value);
            }
            match value {
                Value::Object(inner) => at(inner, rest),
                _ => None,
            }
        }

        /// Replace (or add) the value at `path`; every object above it must exist.
        fn set(object: &mut Object, path: &[&str], value: Value) {
            let (first, rest) = path.split_first().unwrap();
            if rest.is_empty() {
                let _ = object.remove(first);
                object.insert((*first).to_owned(), value).unwrap();
                return;
            }
            let Some(Value::Object(mut inner)) = object.remove(first) else {
                panic!("{first} is not an object in the create");
            };
            set(&mut inner, rest, value);
            object
                .insert((*first).to_owned(), Value::Object(inner))
                .unwrap();
        }

        /// The strings of the array at `path`; `null` or absent is none.
        fn strings(object: &Object, path: &[&str]) -> Vec<String> {
            match at(object, path) {
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| match item {
                        Value::String(s) => s.clone(),
                        other => panic!("{path:?} holds {other:?}"),
                    })
                    .collect(),
                None | Some(Value::Null) => Vec::new(),
                Some(other) => panic!("{path:?} is {other:?}"),
            }
        }

        fn string_array(items: Vec<String>) -> Value {
            Value::Array(items.into_iter().map(Value::String).collect())
        }

        fn is_text(object: &Object, path: &[&str], wanted: &str) -> bool {
            matches!(at(object, path), Some(Value::String(s)) if s == wanted)
        }

        fn is_bool(object: &Object, path: &[&str], wanted: bool) -> bool {
            matches!(at(object, path), Some(Value::Bool(b)) if *b == wanted)
        }

        fn is_int(object: &Object, path: &[&str], wanted: i64) -> bool {
            matches!(at(object, path), Some(Value::Number(Number::Int(n))) if *n == wanted)
        }

        /// Change `HostConfig.SecurityOpt` with `edit`, which must change it.
        fn security_opt(create: &mut Object, edit: impl FnOnce(&mut Vec<String>)) {
            let path = ["HostConfig", "SecurityOpt"];
            let before = strings(create, &path);
            let mut after = before.clone();
            edit(&mut after);
            assert_ne!(before, after, "the weakening changed no security option");
            set(create, &path, string_array(after));
        }

        /// Exactly one JSON object, or `None`.
        fn try_object(bytes: &[u8]) -> Option<Object> {
            match json::parse(bytes, ParseOptions::ijson()) {
                Ok(Value::Object(object)) => Some(object),
                _ => None,
            }
        }

        /// Exactly one JSON object.
        fn object(bytes: &[u8]) -> Object {
            try_object(bytes)
                .unwrap_or_else(|| panic!("not one JSON object ({} bytes)", bytes.len()))
        }

        /// Every path at which `a` and `b` differ: an object's members one
        /// by one, any other value (an array included) as a whole.
        fn differing(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
            if let (Value::Object(x), Value::Object(y)) = (a, b) {
                let mut keys: Vec<&str> = x.iter().map(|(k, _)| k).collect();
                keys.extend(y.iter().map(|(k, _)| k));
                keys.sort_unstable();
                keys.dedup();
                for key in keys {
                    let inner = if path.is_empty() {
                        key.to_owned()
                    } else {
                        format!("{path}.{key}")
                    };
                    match (x.get(key), y.get(key)) {
                        (Some(p), Some(q)) => differing(p, q, &inner, out),
                        _ => out.push(inner),
                    }
                }
            } else if a != b {
                out.push(path.to_owned());
            }
        }

        fn changed(a: &Object, b: &Object) -> Vec<String> {
            let mut out = Vec::new();
            differing(
                &Value::Object(a.clone()),
                &Value::Object(b.clone()),
                "",
                &mut out,
            );
            out
        }

        // ---- the weakenings: M5a's flags, as the API carries them ---------

        fn writable_root(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "ReadonlyRootfs"], Value::Bool(false));
        }
        fn root_user(c: &mut Object, _: &Facts) {
            set(c, &["User"], text_value("0:0"));
        }
        fn privileged(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "Privileged"], Value::Bool(true));
        }
        fn runtime_socket(c: &mut Object, f: &Facts) {
            let mut binds = strings(c, &["HostConfig", "Binds"]);
            binds.push(format!("{}:/var/run/docker.sock", f.runtime_socket));
            set(c, &["HostConfig", "Binds"], string_array(binds));
        }
        fn capability_added(c: &mut Object, _: &Facts) {
            set(
                c,
                &["HostConfig", "CapAdd"],
                string_array(vec!["NET_RAW".into()]),
            );
        }
        fn no_new_privileges_off(c: &mut Object, _: &Facts) {
            security_opt(c, |o| o.retain(|opt| !opt.starts_with("no-new-privileges")));
        }
        fn seccomp_unconfined(c: &mut Object, _: &Facts) {
            security_opt(c, |o| {
                for opt in o.iter_mut().filter(|opt| opt.starts_with("seccomp=")) {
                    "seccomp=unconfined".clone_into(opt);
                }
            });
        }
        fn seccomp_default(c: &mut Object, _: &Facts) {
            security_opt(c, |o| o.retain(|opt| !opt.starts_with("seccomp=")));
        }
        fn host_pid(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "PidMode"], text_value("host"));
        }
        fn host_ipc(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "IpcMode"], text_value("host"));
        }
        fn host_uts(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "UTSMode"], text_value("host"));
        }
        fn host_network(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "NetworkMode"], text_value("host"));
        }
        fn mutable_tag(c: &mut Object, f: &Facts) {
            set(c, &["Image"], text_value(&f.tag));
        }
        fn extra_device(c: &mut Object, _: &Facts) {
            let mut device = Object::new();
            for (key, value) in [
                ("PathOnHost", "/dev/zero"),
                ("PathInContainer", "/dev/extra"),
                ("CgroupPermissions", "rwm"),
            ] {
                device.insert(key.to_owned(), text_value(value)).unwrap();
            }
            set(
                c,
                &["HostConfig", "Devices"],
                Value::Array(vec![Value::Object(device)]),
            );
        }
        fn limits_dropped(c: &mut Object, _: &Facts) {
            set(c, &["HostConfig", "PidsLimit"], int(-1));
            set(c, &["HostConfig", "MemorySwap"], int(-1));
        }
        fn backstop_at_256(c: &mut Object, _: &Facts) {
            let Some(Value::Array(limits)) = at(c, &["HostConfig", "Ulimits"]).cloned() else {
                panic!("the create has no ulimits");
            };
            let mut found = 0usize;
            let limits = limits
                .into_iter()
                .map(|limit| match limit {
                    Value::Object(mut l) if is_text(&l, &["Name"], "nproc") => {
                        found += 1;
                        set(&mut l, &["Soft"], int(256));
                        set(&mut l, &["Hard"], int(256));
                        Value::Object(l)
                    }
                    other => other,
                })
                .collect();
            assert_eq!(found, 1, "one nproc limit in the create");
            set(c, &["HostConfig", "Ulimits"], Value::Array(limits));
        }

        // ---- what the daemon's own record shows of each ---------------------

        fn recorded_writable_root(r: &Object, _: &Facts) -> bool {
            is_bool(r, &["HostConfig", "ReadonlyRootfs"], false)
        }
        fn recorded_root_user(r: &Object, _: &Facts) -> bool {
            is_text(r, &["Config", "User"], "0:0")
        }
        fn recorded_privileged(r: &Object, _: &Facts) -> bool {
            is_bool(r, &["HostConfig", "Privileged"], true)
        }
        fn recorded_runtime_socket(r: &Object, _: &Facts) -> bool {
            matches!(at(r, &["Mounts"]), Some(Value::Array(mounts)) if mounts.iter().any(|m| {
                matches!(m, Value::Object(m) if is_text(m, &["Destination"], "/var/run/docker.sock"))
            }))
        }
        fn recorded_capability(r: &Object, _: &Facts) -> bool {
            strings(r, &["HostConfig", "CapAdd"])
                .iter()
                .any(|c| c == "NET_RAW" || c == "CAP_NET_RAW")
        }
        fn recorded_no_new_privileges_off(r: &Object, _: &Facts) -> bool {
            !strings(r, &["HostConfig", "SecurityOpt"])
                .iter()
                .any(|o| o.starts_with("no-new-privileges"))
        }
        fn recorded_seccomp_unconfined(r: &Object, _: &Facts) -> bool {
            strings(r, &["HostConfig", "SecurityOpt"])
                .iter()
                .any(|o| o == "seccomp=unconfined")
        }
        fn recorded_seccomp_default(r: &Object, _: &Facts) -> bool {
            !strings(r, &["HostConfig", "SecurityOpt"])
                .iter()
                .any(|o| o.starts_with("seccomp="))
        }
        fn recorded_host_pid(r: &Object, _: &Facts) -> bool {
            is_text(r, &["HostConfig", "PidMode"], "host")
        }
        fn recorded_host_ipc(r: &Object, _: &Facts) -> bool {
            is_text(r, &["HostConfig", "IpcMode"], "host")
        }
        fn recorded_host_uts(r: &Object, _: &Facts) -> bool {
            is_text(r, &["HostConfig", "UTSMode"], "host")
        }
        fn recorded_host_network(r: &Object, _: &Facts) -> bool {
            is_text(r, &["HostConfig", "NetworkMode"], "host")
        }
        fn recorded_mutable_tag(r: &Object, f: &Facts) -> bool {
            is_text(r, &["Config", "Image"], &f.tag)
        }
        fn recorded_extra_device(r: &Object, _: &Facts) -> bool {
            matches!(at(r, &["HostConfig", "Devices"]), Some(Value::Array(devices)) if devices.iter().any(|d| {
                matches!(d, Value::Object(d) if is_text(d, &["PathInContainer"], "/dev/extra"))
            }))
        }
        fn recorded_limits_dropped(r: &Object, _: &Facts) -> bool {
            let pids = i64::try_from(profile::PIDS_LIMIT).unwrap();
            !is_int(r, &["HostConfig", "PidsLimit"], pids)
                && is_int(r, &["HostConfig", "MemorySwap"], -1)
        }
        fn recorded_backstop_at_256(r: &Object, _: &Facts) -> bool {
            matches!(at(r, &["HostConfig", "Ulimits"]), Some(Value::Array(limits)) if limits.iter().any(|l| {
                matches!(l, Value::Object(l) if is_text(l, &["Name"], "nproc")
                    && is_int(l, &["Soft"], 256) && is_int(l, &["Hard"], 256))
            }))
        }

        /// One E6 case: one hard rule of ADR-0057 §1a's rows weakened.
        struct Row {
            case: &'static str,
            /// The row of ADR-0057 §1a (and issue #19) it is evidence for.
            row: &'static str,
            weaken: Weaken,
            /// The fields of the `create` the weakening changes, and no other.
            changed: &'static [&'static str],
            /// The weakening, as the daemon's own record of the container shows it.
            recorded: fn(&Object, &Facts) -> bool,
            /// The invariants that must fail, from the vantage(s) §1a names.
            caught: &'static [I],
            /// Whether the environment is given the host's network namespace:
            /// the broker must make no peer there (ADR-0059) -- a setup
            /// would add the proxy address to the host's own loopback, and a
            /// relay serve the run's proxy on the host's network -- and the
            /// host's loopback is observed before and after. A disposable
            /// runner's alone: a broker without that gate changes the host.
            on_host_network: bool,
        }

        /// ADR-0057 §1a's fifteen rows -- the seccomp rule twice -- one case
        /// each, the resource-limit row's task backstop (ADR-0056) as a
        /// second case of that row. The host's network last: it is the one
        /// that could touch the host.
        const ROWS: &[Row] = &[
            Row {
                case: "e6-weakened-writable-root-refused",
                row: "read-only-root",
                weaken: writable_root,
                changed: &["HostConfig.ReadonlyRootfs"],
                recorded: recorded_writable_root,
                caught: &[I::HostRootReadOnly, I::ContainerRootReadOnly],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-root-user-refused",
                row: "non-root-user",
                weaken: root_user,
                changed: &["User"],
                recorded: recorded_root_user,
                caught: &[I::HostUserNonRoot, I::ContainerUidGid],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-privileged-refused",
                row: "not-privileged",
                weaken: privileged,
                changed: &["HostConfig.Privileged"],
                recorded: recorded_privileged,
                caught: &[
                    I::HostNotPrivileged,
                    I::ContainerCapabilitiesEmpty,
                    I::ContainerDevicesMinimal,
                    I::ContainerProcRestricted,
                ],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-runtime-socket-mounted-refused",
                row: "no-runtime-socket",
                weaken: runtime_socket,
                changed: &["HostConfig.Binds"],
                recorded: recorded_runtime_socket,
                caught: &[
                    I::HostNoRuntimeSocket,
                    I::HostMountsExact,
                    I::ContainerNoRuntimeSocket,
                ],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-capability-added-refused",
                row: "capabilities-dropped",
                weaken: capability_added,
                changed: &["HostConfig.CapAdd"],
                recorded: recorded_capability,
                caught: &[I::HostCapabilitiesDropped, I::ContainerCapabilitiesEmpty],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-no-new-privileges-disabled-refused",
                row: "no-new-privileges",
                weaken: no_new_privileges_off,
                changed: &["HostConfig.SecurityOpt"],
                recorded: recorded_no_new_privileges_off,
                caught: &[I::HostNoNewPrivileges, I::ContainerNoNewPrivileges],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-seccomp-unconfined-refused",
                row: "seccomp-not-unconfined",
                weaken: seccomp_unconfined,
                changed: &["HostConfig.SecurityOpt"],
                recorded: recorded_seccomp_unconfined,
                caught: &[I::HostSeccompProfile, I::ContainerSeccompProfileActive],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-seccomp-default-profile-refused",
                row: "seccomp-not-runtime-default",
                weaken: seccomp_default,
                changed: &["HostConfig.SecurityOpt"],
                recorded: recorded_seccomp_default,
                caught: &[I::HostSeccompProfile, I::ContainerSeccompProfileActive],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-host-pid-refused",
                row: "private-pid-namespace",
                weaken: host_pid,
                changed: &["HostConfig.PidMode"],
                recorded: recorded_host_pid,
                caught: &[I::HostPidNamespacePrivate, I::ContainerPidNamespacePrivate],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-host-ipc-refused",
                row: "private-ipc-namespace",
                weaken: host_ipc,
                changed: &["HostConfig.IpcMode"],
                recorded: recorded_host_ipc,
                caught: &[I::HostIpcNamespacePrivate],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-host-uts-refused",
                row: "private-uts-namespace",
                weaken: host_uts,
                changed: &["HostConfig.UTSMode"],
                recorded: recorded_host_uts,
                caught: &[I::HostUtsNamespacePrivate],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-mutable-image-tag-refused",
                row: "digest-pinned-image",
                weaken: mutable_tag,
                changed: &["Image"],
                recorded: recorded_mutable_tag,
                caught: &[I::HostImagePinned],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-extra-device-refused",
                row: "no-additional-devices",
                weaken: extra_device,
                changed: &["HostConfig.Devices"],
                recorded: recorded_extra_device,
                caught: &[I::HostNoDevices, I::ContainerDevicesMinimal],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-resource-limits-dropped-refused",
                row: "resource-limits",
                weaken: limits_dropped,
                changed: &["HostConfig.MemorySwap", "HostConfig.PidsLimit"],
                recorded: recorded_limits_dropped,
                caught: &[I::HostResourceLimits, I::ContainerCgroupLimits],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-task-backstop-at-256-refused",
                row: "resource-limits",
                weaken: backstop_at_256,
                changed: &["HostConfig.Ulimits"],
                recorded: recorded_backstop_at_256,
                caught: &[I::HostResourceLimits, I::ContainerRlimits],
                on_host_network: false,
            },
            Row {
                case: "e6-weakened-host-network-refused",
                row: "isolated-network",
                weaken: host_network,
                changed: &["HostConfig.NetworkMode"],
                recorded: recorded_host_network,
                caught: &[
                    I::HostNetworkIsolated,
                    I::ContainerNetworkIsolated,
                    I::ContainerDirectEgressRefused,
                    I::ContainerDirectDnsRefused,
                ],
                on_host_network: true,
            },
        ];

        // ---- the faulty runtime -------------------------------------------

        /// A runtime that does not do what the plan asks: the real daemon
        /// behind a socket that forwards every request and every answer byte
        /// for byte, except the one `create` its fault names, and keeps a copy
        /// of what the evidence must show. Test code only.
        mod faulty {
            use std::collections::BTreeMap;
            use std::io::{BufRead as _, BufReader, Read as _, Write as _};
            use std::net::Shutdown;
            use std::os::unix::net::{UnixListener, UnixStream};
            use std::path::{Path, PathBuf};
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::{Arc, Mutex};

            use dwk_proto::json::{Object, Value, to_canonical_bytes};
            use dwk_sandbox_profile as profile;

            use super::{Facts, Weaken, try_object};

            /// The longest request or answer head read.
            const HEAD: usize = 64 * 1024;
            /// The most bytes of one kept body or stream.
            const KEPT: usize = 8 * 1024 * 1024;

            /// The one `create` to weaken, and how.
            #[derive(Clone)]
            pub(super) struct Fault {
                pub(super) weaken: Weaken,
                pub(super) facts: Facts,
                /// The environment whose container is weakened.
                pub(super) environment: String,
            }

            /// One container's creation, as it crossed the socket.
            #[derive(Clone, Debug)]
            pub(super) struct Created {
                pub(super) role: String,
                pub(super) environment: String,
                /// The body as the client sent it.
                pub(super) sent: Vec<u8>,
                /// The body as the daemon received it.
                pub(super) received: Vec<u8>,
                /// The id the daemon answered, if it created one.
                pub(super) id: Option<String>,
            }

            /// What crossed the socket that the evidence must show.
            #[derive(Clone, Debug, Default)]
            pub(super) struct Seen {
                pub(super) created: Vec<Created>,
                /// Every inspection of a container: the id asked, the
                /// daemon's status, its body (decoded), as it sent it.
                pub(super) inspected: Vec<(String, u16, Vec<u8>)>,
                /// Every exec the client made: its id, the container, the command.
                pub(super) execs: BTreeMap<String, (String, Vec<String>)>,
                /// Every exec started: its id and the stream the daemon sent.
                pub(super) streams: Vec<(String, Vec<u8>)>,
                /// Every request, `METHOD path status` (and a create's role).
                pub(super) requests: Vec<String>,
                /// How many bodies were changed.
                pub(super) rewritten: usize,
                /// What could not be forwarded or kept.
                pub(super) failures: Vec<String>,
                /// Connections the client closed before its answer was
                /// written: its own choice, never a failure of the socket --
                /// a step the broker needed and did not get fails that step,
                /// which its measurement shows.
                pub(super) hangups: Vec<String>,
            }

            /// What marks a write the client had already hung up on.
            const HANGUP: &str = "the client hung up: ";

            /// A write to the client that failed: a hang-up, or a failure.
            fn client_error(e: &std::io::Error) -> String {
                match e.kind() {
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                        format!("{HANGUP}{e}")
                    }
                    _ => format!("to the client: {e}"),
                }
            }

            /// The faulty runtime's socket, removed when dropped.
            pub(super) struct FaultyRuntime {
                path: PathBuf,
                seen: Arc<Mutex<Seen>>,
                stop: Arc<AtomicBool>,
                accept: Option<std::thread::JoinHandle<()>>,
            }

            impl FaultyRuntime {
                /// Listen at `path`, forwarding to the daemon at `daemon`.
                pub(super) fn start(path: PathBuf, daemon: PathBuf, fault: Option<Fault>) -> Self {
                    let _ = std::fs::remove_file(&path);
                    let listener = UnixListener::bind(&path).unwrap();
                    let seen = Arc::new(Mutex::new(Seen::default()));
                    let stop = Arc::new(AtomicBool::new(false));
                    let (keep, halt) = (Arc::clone(&seen), Arc::clone(&stop));
                    let accept = std::thread::spawn(move || {
                        for stream in listener.incoming() {
                            if halt.load(Ordering::SeqCst) {
                                return;
                            }
                            let Ok(client) = stream else { continue };
                            let (daemon, fault, keep) =
                                (daemon.clone(), fault.clone(), Arc::clone(&keep));
                            std::thread::spawn(move || {
                                if let Err(why) = serve(client, &daemon, fault.as_ref(), &keep) {
                                    let mut seen = keep.lock().unwrap();
                                    if why.contains(HANGUP) {
                                        seen.hangups.push(why);
                                    } else {
                                        seen.failures.push(why);
                                    }
                                }
                            });
                        }
                    });
                    Self {
                        path,
                        seen,
                        stop,
                        accept: Some(accept),
                    }
                }

                pub(super) fn path(&self) -> &Path {
                    &self.path
                }

                /// What it has seen so far.
                pub(super) fn seen(&self) -> Seen {
                    self.seen.lock().unwrap().clone()
                }
            }

            impl Drop for FaultyRuntime {
                fn drop(&mut self) {
                    self.stop.store(true, Ordering::SeqCst);
                    let _ = UnixStream::connect(&self.path);
                    if let Some(accept) = self.accept.take() {
                        let _ = accept.join();
                    }
                    let _ = std::fs::remove_file(&self.path);
                }
            }

            /// A request's or an answer's head: its bytes, start line and headers.
            pub(super) struct Head {
                pub(super) raw: Vec<u8>,
                pub(super) start: String,
                headers: Vec<(String, String)>,
            }

            impl Head {
                fn parse(raw: Vec<u8>) -> Result<Self, String> {
                    let text = String::from_utf8(raw.clone()).map_err(|_| "a head not in UTF-8")?;
                    let mut lines = text.split("\r\n");
                    let start = lines.next().unwrap_or_default().to_owned();
                    let mut headers = Vec::new();
                    for line in lines.filter(|l| !l.is_empty()) {
                        let (name, value) = line.split_once(':').ok_or("a header without ':'")?;
                        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
                    }
                    Ok(Self {
                        raw,
                        start,
                        headers,
                    })
                }

                fn header(&self, name: &str) -> Option<&str> {
                    self.headers
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, v)| v.as_str())
                }

                fn chunked(&self) -> bool {
                    self.header("transfer-encoding")
                        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
                }

                fn length(&self) -> Result<Option<usize>, String> {
                    self.header("content-length")
                        .map(|v| v.parse::<usize>().map_err(|_| format!("a length {v:?}")))
                        .transpose()
                }

                fn method(&self) -> &str {
                    self.start.split(' ').next().unwrap_or_default()
                }

                /// The request's path, its API version and query left off.
                fn path(&self) -> String {
                    let target = self.start.split(' ').nth(1).unwrap_or_default();
                    let path = target.split('?').next().unwrap_or_default();
                    match path.strip_prefix("/v") {
                        Some(rest)
                            if rest.split('/').next().is_some_and(|v| {
                                !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.')
                            }) =>
                        {
                            rest.split_once('/')
                                .map_or("/".to_owned(), |(_, p)| format!("/{p}"))
                        }
                        _ => path.to_owned(),
                    }
                }

                fn status(&self) -> Result<u16, String> {
                    self.start
                        .split(' ')
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| format!("no status in {:?}", self.start))
                }

                /// The head with its body's length set to `length`, unchunked.
                fn with_length(&self, length: usize) -> Vec<u8> {
                    let mut out = self.start.clone().into_bytes();
                    out.extend_from_slice(b"\r\n");
                    let text = String::from_utf8_lossy(&self.raw).into_owned();
                    for line in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
                        let name = line.split(':').next().unwrap_or_default().trim();
                        if name.eq_ignore_ascii_case("content-length")
                            || name.eq_ignore_ascii_case("transfer-encoding")
                        {
                            continue;
                        }
                        out.extend_from_slice(line.as_bytes());
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(format!("Content-Length: {length}\r\n\r\n").as_bytes());
                    out
                }
            }

            /// What a request is, for what the evidence keeps of it.
            #[derive(Clone, Debug, PartialEq, Eq)]
            enum Kind {
                Create,
                ExecCreate(String),
                ExecStart(String),
                Inspect(String),
                Other,
            }

            fn kind(head: &Head) -> Kind {
                let path = head.path();
                let words: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                match (head.method(), words.as_slice()) {
                    ("POST", ["containers", "create"]) => Kind::Create,
                    ("POST", ["containers", id, "exec"]) => Kind::ExecCreate((*id).to_owned()),
                    ("POST", ["exec", id, "start"]) => Kind::ExecStart((*id).to_owned()),
                    ("GET", ["containers", id, "json"]) => Kind::Inspect((*id).to_owned()),
                    _ => Kind::Other,
                }
            }

            /// One head, through its blank line; `None` at a clean end.
            fn read_head(from: &mut BufReader<UnixStream>) -> Result<Option<Vec<u8>>, String> {
                let mut raw = Vec::new();
                loop {
                    let mut line = Vec::new();
                    let n = from
                        .read_until(b'\n', &mut line)
                        .map_err(|e| format!("reading a head: {e}"))?;
                    if n == 0 {
                        return if raw.is_empty() {
                            Ok(None)
                        } else {
                            Err("a head cut short".to_owned())
                        };
                    }
                    raw.extend_from_slice(&line);
                    if raw.len() > HEAD {
                        return Err("a head past its bound".to_owned());
                    }
                    if line == b"\r\n" {
                        return Ok(Some(raw));
                    }
                }
            }

            /// A body: its bytes as they crossed (`raw`), and its content.
            pub(super) struct Body {
                pub(super) raw: Vec<u8>,
                pub(super) content: Vec<u8>,
                /// It ran to the connection's end.
                pub(super) to_end: bool,
            }

            fn read_exact(from: &mut BufReader<UnixStream>, n: usize) -> Result<Vec<u8>, String> {
                let mut bytes = vec![0u8; n];
                from.read_exact(&mut bytes)
                    .map_err(|e| format!("a body cut short: {e}"))?;
                Ok(bytes)
            }

            /// Read a body whole. An answer with neither a length nor chunks
            /// runs to the connection's end; a request with neither has none.
            fn read_body(
                from: &mut BufReader<UnixStream>,
                head: &Head,
                answer: bool,
            ) -> Result<Body, String> {
                let mut body = Body {
                    raw: Vec::new(),
                    content: Vec::new(),
                    to_end: false,
                };
                if head.chunked() {
                    loop {
                        let mut line = Vec::new();
                        from.read_until(b'\n', &mut line)
                            .map_err(|e| format!("a chunk: {e}"))?;
                        body.raw.extend_from_slice(&line);
                        let size = String::from_utf8_lossy(&line);
                        let size = size.split(';').next().unwrap_or_default().trim();
                        let size = usize::from_str_radix(size, 16)
                            .map_err(|_| format!("a chunk size {size:?}"))?;
                        if size == 0 {
                            loop {
                                let mut trailer = Vec::new();
                                from.read_until(b'\n', &mut trailer)
                                    .map_err(|e| format!("a trailer: {e}"))?;
                                body.raw.extend_from_slice(&trailer);
                                if trailer == b"\r\n" || trailer.is_empty() {
                                    return Ok(body);
                                }
                            }
                        }
                        let data = read_exact(from, size)?;
                        body.content.extend_from_slice(&data);
                        body.raw.extend_from_slice(&data);
                        body.raw.extend_from_slice(&read_exact(from, 2)?);
                        if body.content.len() > KEPT {
                            return Err("a kept body past its bound".to_owned());
                        }
                    }
                }
                if let Some(n) = head.length()? {
                    if n > KEPT {
                        return Err("a kept body past its bound".to_owned());
                    }
                    body.raw = read_exact(from, n)?;
                    body.content.clone_from(&body.raw);
                    return Ok(body);
                }
                if answer {
                    from.take(u64::try_from(KEPT).unwrap())
                        .read_to_end(&mut body.raw)
                        .map_err(|e| format!("a body to the end: {e}"))?;
                    body.content.clone_from(&body.raw);
                    body.to_end = true;
                }
                Ok(body)
            }

            /// Forward an answer's body as it arrives; whether it ran to the end.
            fn stream_body(
                from: &mut BufReader<UnixStream>,
                to: &mut UnixStream,
                head: &Head,
            ) -> Result<bool, String> {
                let send = |to: &mut UnixStream, bytes: &[u8]| {
                    to.write_all(bytes).map_err(|e| client_error(&e))
                };
                if head.chunked() {
                    loop {
                        let mut line = Vec::new();
                        from.read_until(b'\n', &mut line)
                            .map_err(|e| format!("a chunk: {e}"))?;
                        send(to, &line)?;
                        let size = String::from_utf8_lossy(&line);
                        let size = size.split(';').next().unwrap_or_default().trim();
                        let size = usize::from_str_radix(size, 16)
                            .map_err(|_| format!("a chunk size {size:?}"))?;
                        if size == 0 {
                            loop {
                                let mut trailer = Vec::new();
                                from.read_until(b'\n', &mut trailer)
                                    .map_err(|e| format!("a trailer: {e}"))?;
                                send(to, &trailer)?;
                                if trailer == b"\r\n" || trailer.is_empty() {
                                    return Ok(false);
                                }
                            }
                        }
                        let mut left = size + 2;
                        let mut buffer = [0u8; 16 * 1024];
                        while left > 0 {
                            let want = left.min(buffer.len());
                            let n = from
                                .read(&mut buffer[..want])
                                .map_err(|e| format!("a chunk's data: {e}"))?;
                            if n == 0 {
                                return Err("a chunk cut short".to_owned());
                            }
                            send(to, &buffer[..n])?;
                            left -= n;
                        }
                    }
                }
                if let Some(mut left) = head.length()? {
                    let mut buffer = [0u8; 16 * 1024];
                    while left > 0 {
                        let want = left.min(buffer.len());
                        let n = from
                            .read(&mut buffer[..want])
                            .map_err(|e| format!("a body's data: {e}"))?;
                        if n == 0 {
                            return Err("a body cut short".to_owned());
                        }
                        send(to, &buffer[..n])?;
                        left -= n;
                    }
                    return Ok(false);
                }
                std::io::copy(from, to).map_err(|e| client_error(&e))?;
                Ok(true)
            }

            fn label<'a>(create: &'a Object, name: &str) -> &'a str {
                match super::at(create, &["Labels", name]) {
                    Some(Value::String(s)) => s,
                    _ => "",
                }
            }

            fn answered_id(content: &[u8]) -> Option<String> {
                match super::at(&try_object(content)?, &["Id"]) {
                    Some(Value::String(id)) => Some(id.clone()),
                    _ => None,
                }
            }

            /// One client connection, request by request, to its end; a
            /// failure names the request it happened in.
            fn serve(
                client: UnixStream,
                daemon: &Path,
                fault: Option<&Fault>,
                seen: &Mutex<Seen>,
            ) -> Result<(), String> {
                let mut last = String::from("before any request");
                forward(client, daemon, fault, seen, &mut last).map_err(|e| format!("{last}: {e}"))
            }

            fn forward(
                client: UnixStream,
                daemon: &Path,
                fault: Option<&Fault>,
                seen: &Mutex<Seen>,
                last: &mut String,
            ) -> Result<(), String> {
                let upstream =
                    UnixStream::connect(daemon).map_err(|e| format!("the daemon: {e}"))?;
                let mut from_client =
                    BufReader::new(client.try_clone().map_err(|e| e.to_string())?);
                let mut to_client = client;
                let mut from_daemon =
                    BufReader::new(upstream.try_clone().map_err(|e| e.to_string())?);
                let mut to_daemon = upstream;
                let send = |to: &mut UnixStream, bytes: &[u8], whom: &str| {
                    to.write_all(bytes).map_err(|e| {
                        if whom == "client" {
                            client_error(&e)
                        } else {
                            format!("to the {whom}: {e}")
                        }
                    })
                };
                loop {
                    let Some(raw) = read_head(&mut from_client)? else {
                        let _ = to_daemon.shutdown(Shutdown::Write);
                        return Ok(());
                    };
                    let request = Head::parse(raw)?;
                    request.start.clone_into(last);
                    let body = read_body(&mut from_client, &request, false)?;
                    let request_content = body.content.clone();
                    let what = kind(&request);
                    let mut note = String::new();
                    let mut created = None;
                    // The one place a byte is changed: the faulted
                    // environment's create, re-encoded with its length.
                    let (head, sent) = if what == Kind::Create {
                        let mut create = try_object(&body.content)
                            .ok_or("a create whose body is not one JSON object")?;
                        let (role, environment) = (
                            label(&create, profile::LABEL_ROLE).to_owned(),
                            label(&create, profile::LABEL_ENVIRONMENT).to_owned(),
                        );
                        note = format!(" role={role}");
                        let weakened =
                            fault.filter(|f| role == "environment" && environment == f.environment);
                        let (head, sent) = if let Some(f) = weakened {
                            (f.weaken)(&mut create, &f.facts);
                            let bytes = to_canonical_bytes(&Value::Object(create));
                            seen.lock().unwrap().rewritten += 1;
                            (request.with_length(bytes.len()), bytes)
                        } else {
                            (request.raw.clone(), body.raw.clone())
                        };
                        let received = if weakened.is_some() {
                            sent.clone()
                        } else {
                            body.content.clone()
                        };
                        created = Some(Created {
                            role,
                            environment,
                            sent: body.content.clone(),
                            received,
                            id: None,
                        });
                        (head, sent)
                    } else {
                        (request.raw.clone(), body.raw.clone())
                    };
                    send(&mut to_daemon, &head, "daemon")?;
                    send(&mut to_daemon, &sent, "daemon")?;
                    let upgrade = request.header("upgrade").is_some();
                    let Some(raw) = read_head(&mut from_daemon)? else {
                        return Err(format!(
                            "the daemon closed before answering {}",
                            request.start
                        ));
                    };
                    let answer = Head::parse(raw)?;
                    let status = answer.status()?;
                    seen.lock().unwrap().requests.push(format!(
                        "{} {} {status}{note}",
                        request.method(),
                        request.path()
                    ));
                    if upgrade || status == 101 {
                        // A hijacked stream: raw both ways from here.
                        send(&mut to_client, &answer.raw, "client")?;
                        let mut back = to_daemon.try_clone().map_err(|e| e.to_string())?;
                        std::thread::spawn(move || {
                            let _ = std::io::copy(&mut from_client, &mut back);
                            let _ = back.shutdown(Shutdown::Write);
                        });
                        let mut stream = Vec::new();
                        let mut buffer = [0u8; 16 * 1024];
                        loop {
                            let n = from_daemon
                                .read(&mut buffer)
                                .map_err(|e| format!("a stream: {e}"))?;
                            if n == 0 {
                                break;
                            }
                            if stream.len() < KEPT {
                                stream.extend_from_slice(&buffer[..n]);
                            }
                            send(&mut to_client, &buffer[..n], "client")?;
                        }
                        if let Kind::ExecStart(id) = what {
                            seen.lock().unwrap().streams.push((id, stream));
                        }
                        let _ = to_client.shutdown(Shutdown::Write);
                        return Ok(());
                    }
                    let bodiless = request.method() == "HEAD"
                        || status == 204
                        || status == 304
                        || (100..200).contains(&status);
                    let keep = !matches!(what, Kind::Other | Kind::ExecStart(_));
                    if bodiless {
                        send(&mut to_client, &answer.raw, "client")?;
                    } else if keep {
                        // Kept whole, recorded, then forwarded: the client
                        // never has an answer the evidence has not.
                        let body = read_body(&mut from_daemon, &answer, true)?;
                        {
                            let mut seen = seen.lock().unwrap();
                            match &what {
                                Kind::Create => {
                                    if let Some(mut c) = created.take() {
                                        c.id = (status == 201)
                                            .then(|| answered_id(&body.content))
                                            .flatten();
                                        seen.created.push(c);
                                    }
                                }
                                Kind::ExecCreate(container) if status == 201 => {
                                    let command = try_object(&request_content)
                                        .map(|o| super::strings(&o, &["Cmd"]))
                                        .unwrap_or_default();
                                    if let Some(id) = answered_id(&body.content) {
                                        seen.execs.insert(id, (container.clone(), command));
                                    }
                                }
                                Kind::Inspect(container) => {
                                    seen.inspected.push((
                                        container.clone(),
                                        status,
                                        body.content.clone(),
                                    ));
                                }
                                _ => {}
                            }
                        }
                        send(&mut to_client, &answer.raw, "client")?;
                        send(&mut to_client, &body.raw, "client")?;
                        if body.to_end {
                            let _ = to_client.shutdown(Shutdown::Write);
                            return Ok(());
                        }
                    } else {
                        send(&mut to_client, &answer.raw, "client")?;
                        if stream_body(&mut from_daemon, &mut to_client, &answer)? {
                            let _ = to_client.shutdown(Shutdown::Write);
                            return Ok(());
                        }
                    }
                    let closing = |h: &Head| {
                        h.header("connection")
                            .is_some_and(|v| v.eq_ignore_ascii_case("close"))
                    };
                    if closing(&request) || closing(&answer) {
                        return Ok(());
                    }
                }
            }

            /// The stdout and stderr of a multiplexed exec stream (8-byte frame
            /// headers: stream, three zeros, a big-endian length); `None` if it
            /// is not one.
            pub(super) fn demux(raw: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let mut rest = raw;
                while !rest.is_empty() {
                    let header = rest.get(..8)?;
                    let size = u32::from_be_bytes(header.get(4..8)?.try_into().ok()?);
                    let size = usize::try_from(size).ok()?;
                    let payload = rest.get(8..8 + size)?;
                    match header.first()? {
                        1 => out.extend_from_slice(payload),
                        2 => err.extend_from_slice(payload),
                        _ => return None,
                    }
                    rest = rest.get(8 + size..)?;
                }
                Some((out, err))
            }
        }

        use faulty::{Created, Fault, FaultyRuntime, Seen, demux};

        // ---- the cases -------------------------------------------------------

        /// Where this is, for the one case that touches the host: a disposable
        /// GitHub-hosted runner whose engine is not Docker Desktop.
        fn disposable_runner(ev: &Evidence) -> Result<(), String> {
            let env = |name: &str| std::env::var(name).unwrap_or_default();
            if env("GITHUB_ACTIONS") != "true" || env("RUNNER_ENVIRONMENT") != "github-hosted" {
                return Err("this is not a disposable GitHub-hosted runner".to_owned());
            }
            let system = ev.docker_ok(&["info", "--format", "{{.OperatingSystem}}"]);
            if system.contains("Docker Desktop") {
                return Err(format!("the runtime is {}", system.trim()));
            }
            Ok(())
        }

        /// The host's own IPv4 loopback addresses, as `ip` lists them.
        fn host_loopback() -> Option<Vec<String>> {
            let out = Command::new("ip")
                .args(["-o", "-4", "addr", "show", "dev", "lo"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let text = String::from_utf8(out.stdout).ok()?;
            let mut found: Vec<String> = text
                .lines()
                .filter_map(|line| {
                    let mut words = line.split_whitespace();
                    words.position(|w| w == "inet")?;
                    words.next().map(str::to_owned)
                })
                .collect();
            found.sort();
            Some(found)
        }

        struct Lab<'a> {
            ev: &'a Evidence,
            socket: &'a Path,
            dir: &'a Scratch,
            workspace: &'a Path,
            broker: &'a Broker,
            facts: Facts,
            raw: PathBuf,
        }

        /// A preparation through a faulty runtime.
        struct Through {
            e: EnvironmentId,
            r: RunId,
            runtime: FaultyRuntime,
            through: Evidence,
            container: Option<ContainerRef>,
            retained: bool,
            measurement: Option<EnvironmentMeasurement>,
            events: String,
        }

        fn prepare_through(lab: &Lab<'_>, fault: Option<Weaken>) -> Through {
            let (e, r) = (environment(), run());
            let s = spec(
                (&e, &r),
                lab.workspace,
                &lab.ev.image,
                &lab.ev.relay_sha256,
                grant(vec![target(ORIGIN, 443)], 4, 1 << 20, 1 << 20),
                lab.ev,
            );
            let fault = fault.map(|weaken| Fault {
                weaken,
                facts: lab.facts.clone(),
                environment: e.as_str().to_owned(),
            });
            let runtime = FaultyRuntime::start(
                lab.dir.0.join(format!("runtime-{}.sock", next())),
                PathBuf::from(&lab.ev.socket),
                fault,
            );
            let mut through = lab.ev.clone();
            through.socket = runtime.path().display().to_string();
            let before = lab.broker.stderr().len();
            let prepared = done(prepare(lab.socket, &through, &s))
                .environment_prepare
                .unwrap();
            let events = lab
                .broker
                .stderr()
                .get(before..)
                .unwrap_or_default()
                .to_owned();
            Through {
                e,
                r,
                runtime,
                through,
                container: prepared.container,
                retained: prepared.retained,
                measurement: prepared.measurement,
                events,
            }
        }

        /// The one environment create the socket saw, and every other create
        /// forwarded byte for byte; the setup and the relay among them when
        /// `peer`, and neither when not -- never one, for an environment
        /// whose namespace is not its own (ADR-0059).
        fn environment_create<'a>(
            case: &str,
            seen: &'a Seen,
            e: &EnvironmentId,
            peer: bool,
        ) -> &'a Created {
            let ours: Vec<&Created> = seen
                .created
                .iter()
                .filter(|c| c.role == "environment")
                .collect();
            assert_eq!(ours.len(), 1, "{case}: environment creates {ours:?}");
            let created = ours[0];
            assert_eq!(created.environment, e.as_str(), "{case}");
            for other in seen.created.iter().filter(|c| c.role != "environment") {
                assert_eq!(
                    other.sent, other.received,
                    "{case}: the {} create changed",
                    other.role
                );
            }
            for role in ["setup", "relay"] {
                let made = seen
                    .created
                    .iter()
                    .any(|c| c.role == role && c.environment == e.as_str());
                assert_eq!(
                    made,
                    peer,
                    "{case}: the broker {} {role}: {:?}",
                    if peer { "made no" } else { "made a" },
                    seen.requests
                );
            }
            created
        }

        /// The record the measurement judged -- the daemon's first answer of
        /// the environment's own after the measurement's version check; the
        /// peer's gate (ADR-0059) read one before it, and the client's
        /// `exec` reads one after -- and the probe report it read, each
        /// checked against the broker's measurement.
        fn observed(
            case: &str,
            seen: &Seen,
            container: &ContainerRef,
            e: &EnvironmentId,
            measurement: &EnvironmentMeasurement,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let measure = vec![
                profile::PROBE_PATH.to_owned(),
                profile::PROBE_MEASURE.to_owned(),
                e.as_str().to_owned(),
                NetworkTopology::ProxyOnly.as_str().to_owned(),
            ];
            let execs: Vec<&String> = seen
                .execs
                .iter()
                .filter(|(_, (c, command))| c == container.as_str() && *command == measure)
                .map(|(id, _)| id)
                .collect();
            assert_eq!(execs.len(), 1, "{case}: probe measurements {execs:?}");
            // Where the measurement began: the last version check before the
            // probe ran. Every answer of the environment's record before it
            // is not the measurement's.
            let read = format!("GET /containers/{}/json 200", container.as_str());
            let ran = format!("POST /exec/{}/start ", execs[0]);
            let probe = seen
                .requests
                .iter()
                .position(|r| r.starts_with(&ran))
                .unwrap_or_else(|| panic!("{case}: the probe never ran: {:?}", seen.requests));
            let began = seen.requests[..probe]
                .iter()
                .rposition(|r| r == "GET /version 200")
                .unwrap_or_else(|| panic!("{case}: no measurement: {:?}", seen.requests));
            assert!(
                seen.requests[began..probe].contains(&read),
                "{case}: the measurement read no record: {:?}",
                seen.requests
            );
            let earlier = seen.requests[..began]
                .iter()
                .filter(|r| **r == read)
                .count();
            let record = seen
                .inspected
                .iter()
                .filter(|(id, status, _)| id == container.as_str() && *status == 200)
                .nth(earlier)
                .map(|(_, _, body)| body.clone())
                .unwrap_or_else(|| {
                    panic!("{case}: the broker read no record: {:?}", seen.requests)
                });
            let streams: Vec<&Vec<u8>> = seen
                .streams
                .iter()
                .filter(|(id, _)| id == execs[0])
                .map(|(_, s)| s)
                .collect();
            assert_eq!(streams.len(), 1, "{case}: the probe's stream");
            let stream = streams[0].clone();
            let (stdout, _stderr) =
                demux(&stream).unwrap_or_else(|| panic!("{case}: not a stream"));
            let report = ProbeReport::decode_bytes(&stdout)
                .unwrap_or_else(|e| panic!("{case}: the probe's report: {e:?}"));
            // Every inside verdict the broker answered is the probe's own.
            for check in report.checks.iter() {
                assert_eq!(
                    verdict(measurement, check.invariant),
                    check.verdict,
                    "{case}: {:?} is not what the probe reported",
                    check.invariant
                );
            }
            (record, stream, stdout)
        }

        fn joined(invariants: &[I]) -> String {
            invariants
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>()
                .join("+")
        }

        fn verdicts(pairs: &[(I, Verdict)]) -> String {
            if pairs.is_empty() {
                return "none".to_owned();
            }
            pairs
                .iter()
                .map(|(i, v)| format!("{}={}", i.as_str(), v.as_str()))
                .collect::<Vec<_>>()
                .join("+")
        }

        fn hex(digest: &[u8]) -> String {
            digest.iter().map(|b| format!("{b:02x}")).collect()
        }

        /// Write one raw observation of `case` and say its digest.
        fn keep(lab: &Lab<'_>, case: &str, file: &str, bytes: &[u8]) {
            let dir = lab.raw.join(case);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(file), bytes).unwrap();
            let mut fields = Object::new();
            for (key, value) in [
                ("case", case.to_owned()),
                ("file", file.to_owned()),
                ("sha256", hex(&Sha256::digest(bytes))),
            ] {
                fields.insert(key.to_owned(), Value::String(value)).unwrap();
            }
            fields
                .insert(
                    "bytes".to_owned(),
                    Value::Number(Number::from_i64(i64::try_from(bytes.len()).unwrap()).unwrap()),
                )
                .unwrap();
            println!("E6-RAW {}", to_canonical_string(&Value::Object(fields)));
        }

        fn kept_all(
            lab: &Lab<'_>,
            case: &str,
            t: &Through,
            created: &Created,
            (record, stream, report): (&[u8], &[u8], &[u8]),
        ) {
            let measurement = t.measurement.as_ref().unwrap();
            let mut answer = format!("retained={}\n", t.retained);
            for check in measurement.checks.iter() {
                answer.push_str(&format!(
                    "{} {}\n",
                    check.invariant.as_str(),
                    check.verdict.as_str()
                ));
            }
            let seen = t.runtime.seen();
            keep(lab, case, "create-sent.json", &created.sent);
            keep(lab, case, "create-received.json", &created.received);
            keep(lab, case, "record.json", record);
            keep(lab, case, "probe-stream.bin", stream);
            keep(lab, case, "probe-report.json", report);
            keep(lab, case, "measurement.txt", answer.as_bytes());
            // Every request the broker's client made, and every connection
            // its client closed before its answer was written.
            let mut requests = seen.requests.join("\n") + "\n";
            for hangup in &seen.hangups {
                requests.push_str(&format!("hung-up {hangup}\n"));
            }
            keep(lab, case, "requests.txt", requests.as_bytes());
            keep(lab, case, "broker-events.txt", t.events.as_bytes());
        }

        /// The conforming plan as the client sent it, its labels left out:
        /// every case's create must be this one before its weakening. Its
        /// environment is a set: Docker's CLI 29.9.2 orders the proxy
        /// variables differently from one invocation to the next (measured),
        /// and the broker's judgement counts each by name, in any order.
        fn plan_of(sent: &[u8]) -> Object {
            let mut plan = object(sent);
            let _ = plan.remove("Labels");
            let mut env = strings(&plan, &["Env"]);
            env.sort();
            set(&mut plan, &["Env"], string_array(env));
            plan
        }

        fn the_control(lab: &Lab<'_>) -> Object {
            let case = "e6-faulty-runtime-forwards-a-conforming-environment-kept";
            let t = prepare_through(lab, None);
            let seen = t.runtime.seen();
            assert!(seen.failures.is_empty(), "{case}: {:?}", seen.failures);
            assert_eq!(seen.rewritten, 0);
            let created = environment_create(case, &seen, &t.e, true);
            assert_eq!(
                created.sent, created.received,
                "{case}: forwarded byte for byte"
            );
            assert!(
                !t.events.contains("relay_withheld"),
                "{case}: the peer was withheld: {}",
                t.events
            );
            let measurement = t.measurement.clone().expect("measured");
            assert!(
                t.retained,
                "{case}: a conforming environment through the faulty runtime was not kept: {:?}\n{}",
                not_passing(&measurement),
                t.events
            );
            assert!(not_passing(&measurement).is_empty(), "{case}");
            assert_eq!(measurement.checks.len(), I::ALL.len());
            let container = t.container.clone().unwrap();
            assert_eq!(created.id.as_deref(), Some(container.as_str()));
            let observed = observed(case, &seen, &container, &t.e, &measurement);
            kept_all(
                lab,
                case,
                &t,
                created,
                (&observed.0, &observed.1, &observed.2),
            );
            let destroyed = destroy(lab.socket, &t.through, (&t.e, &t.r), Some(&container));
            assert_eq!(destroyed.state, DestroyState::Removed, "{case}");
            assert!(
                lab.ev.labelled(&t.e, None).is_empty(),
                "{case}: left behind"
            );
            assert!(
                !egress_dir(lab.dir, &t.e).exists(),
                "{case}: the listener's directory"
            );
            let topology: Vec<(I, Verdict)> = TOPOLOGY
                .iter()
                .map(|i| (*i, verdict(&measurement, *i)))
                .collect();
            evidence_in(
                case,
                &format!(
                    "kept:every-required-invariant-pass;topology:{};forwarded-unchanged;destroyed:removed",
                    verdicts(&topology)
                ),
                "measured-both",
            );
            plan_of(&created.sent)
        }

        /// One row: prepared through the faulty runtime with its weakening,
        /// and refused. Its outcome line.
        fn refused(lab: &Lab<'_>, row: &Row, plan: &Object) -> String {
            let case = row.case;
            let observe = || {
                host_loopback()
                    .unwrap_or_else(|| panic!("{case}: the host's loopback is not observed"))
            };
            let host_before = row.on_host_network.then(observe);
            let t = prepare_through(lab, Some(row.weaken));
            let seen = t.runtime.seen();
            assert!(
                seen.failures.is_empty(),
                "{case}: the faulty runtime: {:?}",
                seen.failures
            );
            assert_eq!(seen.rewritten, 1, "{case}: one create weakened");
            // The peer: made for every weakening but the network's, where
            // the namespace is not the environment's own (ADR-0059).
            let created = environment_create(case, &seen, &t.e, !row.on_host_network);
            assert_eq!(
                t.events.contains("relay_withheld network=FAIL"),
                row.on_host_network,
                "{case}: the broker's gate: {}",
                t.events
            );
            assert_eq!(
                t.events.contains("relay_withheld"),
                row.on_host_network,
                "{case}: the peer withheld: {}",
                t.events
            );
            // The client asked for the strict plan the control measured
            // clean; the daemon received it with exactly the row's fields
            // changed.
            let differs = changed(plan, &plan_of(&created.sent));
            assert!(
                differs.is_empty(),
                "{case}: not the strict plan: {differs:?}\ncontrol {:?}\nthis    {:?}",
                at(plan, &["Env"]),
                at(&plan_of(&created.sent), &["Env"]).cloned()
            );
            let sent = object(&created.sent);
            let received = object(&created.received);
            assert_eq!(
                changed(&sent, &received),
                row.changed,
                "{case}: the weakening"
            );
            // The production decision: never kept.
            let measurement = t
                .measurement
                .clone()
                .unwrap_or_else(|| panic!("{case}: no measurement\n{}", t.events));
            assert!(
                !t.retained,
                "{case}: a weakened PROXY_ONLY environment was KEPT\n{}",
                t.events
            );
            assert!(
                t.events.contains("environment_prepared declared=")
                    && t.events.contains("retained=false"),
                "{case}: the broker's own event: {}",
                t.events
            );
            assert_ne!(
                verdict(&measurement, I::ContainerUidGid),
                Verdict::Unobservable,
                "{case}: the probe's report did not arrive; {:?}",
                not_passing(&measurement)
            );
            for invariant in row.caught {
                assert_eq!(
                    verdict(&measurement, *invariant),
                    Verdict::Fail,
                    "{case}: {invariant:?} not caught; {:?}",
                    not_passing(&measurement)
                );
            }
            let also: Vec<(I, Verdict)> = not_passing(&measurement)
                .into_iter()
                .filter(|(i, _)| !row.caught.contains(i) && !TOPOLOGY.contains(i))
                .collect();
            let topology: Vec<(I, Verdict)> = TOPOLOGY
                .iter()
                .map(|i| (*i, verdict(&measurement, *i)))
                .collect();
            // What the broker judged is what the daemon recorded and ran.
            let container = t
                .container
                .clone()
                .unwrap_or_else(|| panic!("{case}: no container"));
            assert_eq!(created.id.as_deref(), Some(container.as_str()), "{case}");
            let (record, stream, report) = observed(case, &seen, &container, &t.e, &measurement);
            assert!(
                (row.recorded)(&object(&record), &lab.facts),
                "{case}: the daemon's record does not show the weakening"
            );
            // Nothing left: every role, the listener's directory.
            assert!(
                lab.ev.labelled(&t.e, None).is_empty(),
                "{case}: left behind"
            );
            assert!(
                !egress_dir(lab.dir, &t.e).exists(),
                "{case}: the listener's directory"
            );
            kept_all(lab, case, &t, created, (&record, &stream, &report));
            // The host's network: the host's loopback before and after, kept
            // raw, and nothing gained. No peer was made, so nothing could
            // be; the measurement saw none.
            let residue = match host_before {
                Some(before) => {
                    let after = observe();
                    let mut kept = String::new();
                    for (when, addresses) in [("before", &before), ("after", &after)] {
                        for address in addresses {
                            kept.push_str(&format!("{when} {address}\n"));
                        }
                    }
                    keep(lab, case, "host-loopback.txt", kept.as_bytes());
                    assert!(
                        before.iter().any(|a| a == "127.0.0.1/8"),
                        "{case}: not the host's loopback: {before:?}"
                    );
                    assert!(
                        !before.iter().chain(&after).any(|a| a == PROXY_ADDRESS),
                        "{case}: the proxy address is on the host's loopback: {after:?}"
                    );
                    assert_eq!(after, before, "{case}: the host's loopback changed");
                    for invariant in [I::HostProxyRelay, I::HostRelayDigest] {
                        assert_eq!(
                            verdict(&measurement, invariant),
                            Verdict::Fail,
                            "{case}: {invariant:?} with no peer"
                        );
                    }
                    "none".to_owned()
                }
                None => "not-applicable".to_owned(),
            };
            format!(
                "refused:{};also:{};topology:{};weakened:{};host-loopback-added:{residue}",
                joined(row.caught),
                verdicts(&also),
                verdicts(&topology),
                row.changed.join("+"),
            )
        }

        /// A line of this evidence: the egress suite's shape, E6's suite.
        fn evidence_in(case: &str, outcome: &str, enforcement: &str) {
            let mut fields = Object::new();
            for (key, value) in [
                ("suite", "sandbox-proxy-weakened"),
                ("case", case),
                ("outcome", outcome),
                ("level", LEVEL),
                ("enforcement", enforcement),
            ] {
                fields
                    .insert(key.to_owned(), Value::String(value.to_owned()))
                    .unwrap();
            }
            println!(
                "SANDBOX-EVIDENCE {}",
                to_canonical_string(&Value::Object(fields))
            );
        }

        #[test]
        #[ignore = "needs a real OCI runtime; the qualifying run is hosted only: make sandbox-proxy-weakened-evidence"]
        fn every_hard_rule_weakened_in_a_real_proxy_only_environment_is_refused() {
            // Before anything is made: the evidence task's flag.
            assert_eq!(
                std::env::var("DW_E6_EVIDENCE").unwrap_or_default(),
                "1",
                "NOT EXERCISED: DW_E6_EVIDENCE is not 1; run `make sandbox-proxy-weakened-evidence`"
            );
            let ev = Evidence::load();
            let facts = Facts {
                tag: var("DW_E6_IMAGE_TAG"),
                runtime_socket: ev.socket.clone(),
            };
            let raw = PathBuf::from(var("DW_E6_RAW_DIR"));
            let runner = disposable_runner(&ev);
            let _reaper = Reaper(ev.clone());
            let dir = Scratch::new("e6");
            let socket = dir.socket();
            let broker = Broker::evidence(&socket, &dir.resolver_fixture());
            let workspace = dir.workspace("ws");
            let lab = Lab {
                ev: &ev,
                socket: &socket,
                dir: &dir,
                workspace: &workspace,
                broker: &broker,
                facts,
                raw,
            };
            let plan = the_control(&lab);
            let mut refused_cases = 0usize;
            let mut rows: Vec<&str> = Vec::new();
            for row in ROWS {
                if row.on_host_network
                    && let Err(why) = &runner
                {
                    evidence_in(row.case, &format!("not-exercised: {why}"), "measured-both");
                    continue;
                }
                let outcome = refused(&lab, row, &plan);
                evidence_in(row.case, &outcome, vantage(row.caught));
                refused_cases += 1;
                if !rows.contains(&row.row) {
                    rows.push(row.row);
                }
            }
            evidence_in(
                "e6-row-count",
                &format!(
                    "refused-{refused_cases}-of-{}-cases;rows-{}-of-15",
                    ROWS.len(),
                    rows.len()
                ),
                "measured-both",
            );
        }

        // ---- the faulty runtime's own tests: no runtime needed ---------------

        /// The strict plan's `create`, as Docker's CLI 29.9.2 sends it (its
        /// seccomp profile shortened): what each weakening is applied to.
        const PLAN: &str = concat!(
            r#"{"Hostname":"","Domainname":"","User":"10001:10001","AttachStdin":false,"#,
            r#""AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,"#,
            r#""StdinOnce":false,"Env":["HTTPS_PROXY=http://169.254.7.1:8080"],"Cmd":["hold"],"#,
            r#""Image":"sha256:aa0736be0177","Volumes":{},"WorkingDir":"/workspace","#,
            r#""Entrypoint":["/usr/libexec/direwolf/sandbox-probe"],"#,
            r#""Labels":{"io.direwolf.role":"environment","io.direwolf.environment":"env-1"},"#,
            r#""HostConfig":{"Binds":null,"NetworkMode":"none","CapAdd":null,"CapDrop":["ALL"],"#,
            r#""CgroupnsMode":"private","IpcMode":"private","PidMode":"","Privileged":false,"#,
            r#""ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges=true","seccomp={\"defaultAction\":\"SCMP_ACT_ERRNO\"}"],"#,
            r#""UTSMode":"","Memory":536870912,"MemorySwap":536870912,"PidsLimit":256,"#,
            r#""Devices":[],"Ulimits":[{"Name":"nofile","Hard":1024,"Soft":1024},"#,
            r#"{"Name":"nproc","Hard":8192,"Soft":8192}]},"NetworkingConfig":{"EndpointsConfig":{}}}"#
        );

        fn facts() -> Facts {
            Facts {
                tag: "direwolf-e6:product".to_owned(),
                runtime_socket: "/var/run/docker.sock".to_owned(),
            }
        }

        #[test]
        fn each_weakening_changes_exactly_its_fields() {
            let plan = object(PLAN.as_bytes());
            let mut rows = Vec::new();
            for row in ROWS {
                let mut weakened = plan.clone();
                (row.weaken)(&mut weakened, &facts());
                assert_eq!(changed(&plan, &weakened), row.changed, "{}", row.case);
                // A weakening is never one the judgement would wave through:
                // the rewritten field no longer holds the plan's value.
                assert_ne!(weakened, plan, "{}", row.case);
                assert!(!row.caught.is_empty(), "{}", row.case);
                if !rows.contains(&row.row) {
                    rows.push(row.row);
                }
            }
            // ADR-0057 §1a's fifteen rows, each once at least.
            assert_eq!(rows.len(), 15, "{rows:?}");
            let mut cases: Vec<&str> = ROWS.iter().map(|r| r.case).collect();
            cases.sort_unstable();
            cases.dedup();
            assert_eq!(cases.len(), ROWS.len());
        }

        #[test]
        fn the_differences_of_two_objects_are_found_member_by_member() {
            let a = object(br#"{"a":1,"b":{"c":[1,2],"d":"x"},"e":null}"#);
            let b = object(br#"{"a":1,"b":{"c":[2,1],"d":"x","f":true}}"#);
            assert_eq!(changed(&a, &b), ["b.c", "b.f", "e"]);
            assert!(changed(&a, &a).is_empty());
        }

        #[test]
        fn a_multiplexed_stream_is_read_frame_by_frame() {
            let mut raw = vec![1, 0, 0, 0, 0, 0, 0, 3];
            raw.extend_from_slice(b"out");
            raw.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 2]);
            raw.extend_from_slice(b"er");
            raw.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 1]);
            raw.extend_from_slice(b"!");
            assert_eq!(demux(&raw), Some((b"out!".to_vec(), b"er".to_vec())));
            assert_eq!(demux(&raw[..5]), None, "a frame cut short");
            assert_eq!(demux(&[3, 0, 0, 0, 0, 0, 0, 0]), None, "no such stream");
        }

        /// A daemon that answers each request in `script` in turn, and keeps
        /// every byte it received.
        struct FakeDaemon {
            path: PathBuf,
            received: Arc<Mutex<Vec<u8>>>,
        }

        impl FakeDaemon {
            fn start(dir: &Path, script: Vec<Vec<u8>>, close_after: bool) -> Self {
                let path = dir.join("daemon.sock");
                let listener = UnixListener::bind(&path).unwrap();
                let received = Arc::new(Mutex::new(Vec::new()));
                let keep = Arc::clone(&received);
                std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let mut buffer = [0u8; 4096];
                    for (answered, answer) in script.into_iter().enumerate() {
                        // One more request, whole: its head and its body.
                        while requests_in(&keep.lock().unwrap()) <= answered {
                            let n = stream.read(&mut buffer).unwrap();
                            if n == 0 {
                                return;
                            }
                            keep.lock().unwrap().extend_from_slice(&buffer[..n]);
                        }
                        stream.write_all(&answer).unwrap();
                    }
                    if close_after {
                        let _ = stream.shutdown(Shutdown::Write);
                    }
                    // Keep reading what follows (a hijacked stream's input).
                    while let Ok(n) = stream.read(&mut buffer) {
                        if n == 0 {
                            break;
                        }
                        keep.lock().unwrap().extend_from_slice(&buffer[..n]);
                    }
                });
                Self { path, received }
            }
        }

        /// How many whole requests `bytes` holds (heads, and bodies by length).
        fn requests_in(bytes: &[u8]) -> usize {
            let mut count = 0usize;
            let mut rest = bytes;
            while let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                if rest.len() < end + 4 + length {
                    break;
                }
                count += 1;
                rest = &rest[end + 4 + length..];
            }
            count
        }

        fn request(method: &str, path: &str, body: &[u8], extra: &str) -> Vec<u8> {
            let mut out = format!(
                "{method} {path} HTTP/1.1\r\nHost: api.moby.localhost\r\n{extra}Content-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(body);
            out
        }

        fn chunked_answer(status: &str, body: &[u8]) -> Vec<u8> {
            let mut out = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n0\r\n\r\n");
            out
        }

        fn exchange_with(runtime: &FaultyRuntime, bytes: &[u8], wanted: usize) -> Vec<u8> {
            let mut client = UnixStream::connect(runtime.path()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client.write_all(bytes).unwrap();
            let mut got = Vec::new();
            let mut buffer = [0u8; 4096];
            while got.len() < wanted {
                let n = client.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buffer[..n]);
            }
            got
        }

        fn create_body(role: &str, environment: &str) -> Vec<u8> {
            PLAN.replace(
                r#""io.direwolf.role":"environment""#,
                &format!(r#""io.direwolf.role":"{role}""#),
            )
            .replace("env-1", environment)
            .into_bytes()
        }

        #[test]
        fn without_a_fault_every_byte_crosses_unchanged_and_the_evidence_is_kept() {
            let dir = Scratch::new("e6-unit-a");
            let id = "a".repeat(64);
            let created = chunked_answer(
                "201 Created",
                format!(r#"{{"Id":"{id}","Warnings":[]}}"#).as_bytes(),
            );
            let record =
                chunked_answer("200 OK", br#"{"Id":"x","HostConfig":{"Privileged":false}}"#);
            let daemon = FakeDaemon::start(&dir.0, vec![created.clone(), record.clone()], false);
            let runtime =
                FaultyRuntime::start(dir.0.join("faulty.sock"), daemon.path.clone(), None);
            let mut sent = request(
                "POST",
                "/v1.56/containers/create?name=x",
                &create_body("environment", "env-1"),
                "",
            );
            sent.extend(request(
                "GET",
                &format!("/v1.56/containers/{id}/json"),
                b"",
                "",
            ));
            let answer = exchange_with(&runtime, &sent, created.len() + record.len());
            let mut expected = created.clone();
            expected.extend_from_slice(&record);
            assert_eq!(answer, expected, "the answers byte for byte");
            assert_eq!(
                *daemon.received.lock().unwrap(),
                sent,
                "the requests byte for byte"
            );
            let seen = runtime.seen();
            assert!(seen.failures.is_empty(), "{:?}", seen.failures);
            assert_eq!(seen.rewritten, 0);
            assert_eq!(seen.created.len(), 1);
            assert_eq!(seen.created[0].sent, seen.created[0].received);
            assert_eq!(seen.created[0].id.as_deref(), Some(id.as_str()));
            assert_eq!(seen.created[0].role, "environment");
            assert_eq!(seen.inspected.len(), 1);
            assert_eq!(seen.inspected[0].0, id);
            assert_eq!(
                seen.inspected[0].2,
                br#"{"Id":"x","HostConfig":{"Privileged":false}}"#
            );
            assert_eq!(
                seen.requests,
                vec![
                    "POST /containers/create 201 role=environment".to_owned(),
                    format!("GET /containers/{id}/json 200"),
                ]
            );
        }

        #[test]
        fn only_the_named_environments_create_is_weakened() {
            for (role, environment, weakened) in [
                ("environment", "env-1", true),
                ("relay", "env-1", false),
                ("setup", "env-1", false),
                ("environment", "env-2", false),
            ] {
                let dir = Scratch::new("e6-unit-b");
                let created = chunked_answer("201 Created", br#"{"Id":"b","Warnings":[]}"#);
                let daemon = FakeDaemon::start(&dir.0, vec![created.clone()], false);
                let fault = Fault {
                    weaken: privileged,
                    facts: facts(),
                    environment: "env-1".to_owned(),
                };
                let runtime = FaultyRuntime::start(
                    dir.0.join("faulty.sock"),
                    daemon.path.clone(),
                    Some(fault),
                );
                let body = create_body(role, environment);
                let sent = request("POST", "/v1.56/containers/create", &body, "");
                let answer = exchange_with(&runtime, &sent, created.len());
                assert_eq!(answer, created);
                let received = daemon.received.lock().unwrap().clone();
                let seen = runtime.seen();
                assert!(seen.failures.is_empty(), "{:?}", seen.failures);
                if weakened {
                    assert_eq!(seen.rewritten, 1);
                    let end = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let head = String::from_utf8_lossy(&received[..end]).into_owned();
                    let got = &received[end + 4..];
                    assert!(
                        head.contains(&format!("Content-Length: {}", got.len())),
                        "{head}"
                    );
                    assert_eq!(
                        changed(&object(&body), &object(got)),
                        ["HostConfig.Privileged"]
                    );
                    assert_eq!(seen.created[0].received, got);
                    assert_eq!(seen.created[0].sent, body);
                } else {
                    assert_eq!(seen.rewritten, 0, "{role} {environment}");
                    assert_eq!(received, sent, "{role} {environment}");
                }
            }
        }

        #[test]
        fn a_chunked_request_is_read_whole_and_weakened_with_its_length() {
            let dir = Scratch::new("e6-unit-c");
            let created = chunked_answer("201 Created", br#"{"Id":"c","Warnings":[]}"#);
            let daemon = FakeDaemon::start(&dir.0, vec![created.clone()], false);
            let fault = Fault {
                weaken: writable_root,
                facts: facts(),
                environment: "env-1".to_owned(),
            };
            let runtime =
                FaultyRuntime::start(dir.0.join("faulty.sock"), daemon.path.clone(), Some(fault));
            let body = create_body("environment", "env-1");
            let (first, second) = body.split_at(100);
            let mut sent = b"POST /v1.56/containers/create HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for part in [first, second] {
                sent.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                sent.extend_from_slice(part);
                sent.extend_from_slice(b"\r\n");
            }
            sent.extend_from_slice(b"0\r\n\r\n");
            assert_eq!(exchange_with(&runtime, &sent, created.len()), created);
            let received = daemon.received.lock().unwrap().clone();
            let end = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let head = String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
            assert!(!head.contains("transfer-encoding"), "{head}");
            assert_eq!(
                changed(&object(&body), &object(&received[end + 4..])),
                ["HostConfig.ReadonlyRootfs"]
            );
        }

        #[test]
        fn an_upgraded_stream_crosses_both_ways_and_is_kept_by_its_exec() {
            let dir = Scratch::new("e6-unit-d");
            let exec = "e".repeat(64);
            let made = chunked_answer("201 Created", format!(r#"{{"Id":"{exec}"}}"#).as_bytes());
            let mut upgraded = b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n".to_vec();
            let mut frames = vec![1, 0, 0, 0, 0, 0, 0, 6];
            frames.extend_from_slice(b"report");
            upgraded.extend_from_slice(&frames);
            let daemon = FakeDaemon::start(&dir.0, vec![made.clone(), upgraded.clone()], true);
            let runtime =
                FaultyRuntime::start(dir.0.join("faulty.sock"), daemon.path.clone(), None);
            let command = br#"{"AttachStdout":true,"Cmd":["/usr/libexec/direwolf/sandbox-probe","measure","env-1","PROXY_ONLY"]}"#;
            let mut sent = request("POST", "/v1.56/containers/abc/exec", command, "");
            sent.extend(request(
                "POST",
                &format!("/v1.56/exec/{exec}/start"),
                br#"{"Detach":false,"Tty":false}"#,
                "Connection: Upgrade\r\nUpgrade: tcp\r\n",
            ));
            let answer = exchange_with(&runtime, &sent, made.len() + upgraded.len());
            let mut expected = made.clone();
            expected.extend_from_slice(&upgraded);
            assert_eq!(answer, expected);
            // The stream is kept once the daemon ended it.
            let deadline = Instant::now() + Duration::from_secs(5);
            while runtime.seen().streams.is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let seen = runtime.seen();
            assert!(seen.failures.is_empty(), "{:?}", seen.failures);
            assert_eq!(seen.execs.get(&exec).map(|(c, _)| c.as_str()), Some("abc"));
            assert_eq!(seen.execs[&exec].1[1], "measure");
            assert_eq!(seen.streams, [(exec.clone(), frames.clone())]);
            assert_eq!(demux(&seen.streams[0].1).unwrap().0, b"report");
        }

        #[test]
        fn an_answer_without_a_length_runs_to_the_end_and_is_forwarded() {
            let dir = Scratch::new("e6-unit-e");
            let answer =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\n\r\nall of it".to_vec();
            let daemon = FakeDaemon::start(&dir.0, vec![answer.clone()], true);
            let runtime =
                FaultyRuntime::start(dir.0.join("faulty.sock"), daemon.path.clone(), None);
            let sent = request("GET", "/v1.56/containers/abc/archive?path=/x", b"", "");
            assert_eq!(exchange_with(&runtime, &sent, answer.len()), answer);
            assert!(runtime.seen().failures.is_empty());
        }
    }
}
