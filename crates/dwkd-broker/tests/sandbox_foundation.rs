//! M5a's real-container evidence at the broker (ADR-0047): the released
//! `dwkd-broker` driving a **real** OCI runtime through its **real** client,
//! with this test process playing the authority.
//!
//! Every test here is `#[ignore]`d: it needs a runtime, the evidence images
//! and the pinned digests, which `make sandbox-foundation-evidence` builds
//! and passes in (`DW_SANDBOX_*`). Run any other way, a test panics with
//! `NOT EXERCISED` rather than passing without having looked.
//!
//! The containers this suite makes itself — the weakened ones, the foreign
//! ones, the resource-pressure one — are made with the runtime's client
//! directly, by this test process: the broker never builds a weaker profile,
//! so a measurement of one can only be shown on a container someone else
//! made. **The weakening lives here and nowhere else**: the builder below is
//! test code, reading the profile's own constants, and no product path can
//! reach it. Every such container is removed before its test ends.

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
        ContainerRef, EnvironmentProfile, ImageId, NetworkTopology, SandboxInvariant as I,
        StoreInstance, Verdict,
    };
    use dwk_proto::brokerp::{
        Authorisation, BrokerDone, BrokerHello, BrokerOutcome, BrokerRefusal, Common,
        ContainerState, DestroyState, EnvironmentDestroyAuthorisation,
        EnvironmentListAuthorisation, EnvironmentMeasureAuthorisation, EnvironmentMeasurement,
        EnvironmentPrepareAuthorisation, EnvironmentSpec, OutcomeResult, RuntimeSpec,
    };
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
    use dwk_proto::wire::scalar::{ContentDigest, HostPath};
    use dwk_sandbox_profile as profile;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use sha2::{Digest as _, Sha256};

    const BIN: &str = env!("CARGO_BIN_EXE_dwkd-broker");
    const PROMPT: Duration = Duration::from_secs(10);
    /// Longer than the broker's own environment deadline.
    const PEER_WAIT: Duration = Duration::from_secs(150);
    const SUITE: &str = "sandbox-broker";

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn evidence(case: &str, outcome: &str) {
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
        image: String,
        tag: String,
        probe_sha256: String,
        fixture_sha256: String,
        tampered_byte: String,
        substituted: String,
        malformed: String,
        truncated: String,
        extra_field: String,
        flood: String,
        hang: String,
        fixture: String,
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-foundation-evidence`, which \
                 builds the evidence images and pins their digests"
            )
        })
    }

    impl Evidence {
        fn load() -> Self {
            Self {
                runtime: PathBuf::from(var("DW_SANDBOX_RUNTIME")),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_SANDBOX_IMAGE"),
                tag: var("DW_SANDBOX_IMAGE_TAG"),
                probe_sha256: var("DW_SANDBOX_PROBE_SHA256"),
                fixture_sha256: var("DW_SANDBOX_FIXTURE_SHA256"),
                tampered_byte: var("DW_SANDBOX_IMAGE_TAMPERED_BYTE"),
                substituted: var("DW_SANDBOX_IMAGE_SUBSTITUTED"),
                malformed: var("DW_SANDBOX_IMAGE_MALFORMED"),
                truncated: var("DW_SANDBOX_IMAGE_TRUNCATED"),
                extra_field: var("DW_SANDBOX_IMAGE_EXTRA_FIELD"),
                flood: var("DW_SANDBOX_IMAGE_FLOOD"),
                hang: var("DW_SANDBOX_IMAGE_HANG"),
                fixture: var("DW_SANDBOX_IMAGE_FIXTURE"),
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
    }

    /// Containers this test process made without its store's labels, by id.
    static CREATED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Every container a test made or had made, removed when the test ends —
    /// passing or failing: everything carrying this test process's store
    /// label, and the unlabelled ones it recorded. Nothing else is touched.
    struct Reaper(Evidence);

    impl Reaper {
        fn new(ev: &Evidence) -> Self {
            Self(ev.clone())
        }
    }

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
            let path = std::env::temp_dir().join(format!("dws-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("ipc").join("broker.sock")
        }

        /// A workspace the environment's user can write: the evidence's
        /// own. The production ownership model is M5d's.
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
        fn start(socket: &Path, evidence_topology: bool, crash: Option<&str>) -> Self {
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
            if evidence_topology {
                command.arg("--allow-evidence-topology");
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

    /// A UUIDv7 no other id of this run shares.
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
        StoreInstance::new(format!("{:08x}", std::process::id())).unwrap()
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

    /// What the authority would hand over: the client and `/`, each with its
    /// identity. The client's canonical path is its `argv[0]`.
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
        image: &str,
        probe: &str,
    ) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: environment.clone(),
            run_id: run.clone(),
            store: store(),
            profile: EnvironmentProfile::OciStrict,
            network: NetworkTopology::NoNetwork,
            image: ImageId::new(image.to_owned()).unwrap(),
            probe_sha256: ContentDigest::new(probe.to_owned()).unwrap(),
            workspace_path: HostPath::new(workspace.display().to_string()).unwrap(),
            workspace: identity(workspace),
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
    ) -> OutcomeResult {
        let (runtime, exe, cwd) = runtime(ev);
        let (spec, container) = (spec.clone(), container.clone());
        exchange(
            socket,
            move |common| {
                Authorisation::EnvironmentMeasure(EnvironmentMeasureAuthorisation::new(
                    common, spec, container, runtime,
                ))
            },
            (exe, cwd),
        )
    }

    fn destroy(
        socket: &Path,
        ev: &Evidence,
        (environment, run): (&EnvironmentId, &RunId),
        container: Option<&ContainerRef>,
    ) -> OutcomeResult {
        let (runtime, exe, cwd) = runtime(ev);
        let (environment, run, container) = (environment.clone(), run.clone(), container.cloned());
        exchange(
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
        )
    }

    fn list(socket: &Path, ev: &Evidence) -> Vec<dwk_proto::brokerp::OwnedEnvironment> {
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
        measurement
            .checks
            .iter()
            .filter(|c| c.verdict != Verdict::Pass)
            .map(|c| (c.invariant, c.verdict))
            .collect()
    }

    /// A clean preparation's container and measurement.
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

    // ---- the strict profile --------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn the_strict_profile_measures_clean_from_both_vantages_and_is_destroyed_exactly() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("strict");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
        let (container, measurement) = prepared_clean(&socket, &ev, &s, &broker);
        evidence(
            "prepare-clean",
            &format!("pass-{}", measurement.checks.len()),
        );
        let version = measurement.runtime_version.as_ref().unwrap();
        evidence(
            "runtime-version-reported",
            &format!("runtime-{}", version.as_str()),
        );

        // Each hard rule, measured: the invariants the evidence names one by
        // one, from the host and from inside.
        for (case, invariant) in [
            ("host-image-pinned", I::HostImagePinned),
            ("host-probe-digest", I::HostProbeDigest),
            ("host-not-privileged", I::HostNotPrivileged),
            ("host-user-non-root", I::HostUserNonRoot),
            ("host-root-read-only", I::HostRootReadOnly),
            ("host-capabilities-dropped", I::HostCapabilitiesDropped),
            ("host-no-new-privileges", I::HostNoNewPrivileges),
            ("host-seccomp-profile", I::HostSeccompProfile),
            ("host-pid-private", I::HostPidNamespacePrivate),
            ("host-ipc-private", I::HostIpcNamespacePrivate),
            ("host-uts-private", I::HostUtsNamespacePrivate),
            ("host-network-isolated", I::HostNetworkIsolated),
            ("host-mounts-exact", I::HostMountsExact),
            ("host-no-runtime-socket", I::HostNoRuntimeSocket),
            ("host-no-devices", I::HostNoDevices),
            ("host-resource-limits", I::HostResourceLimits),
            ("host-labels-exact", I::HostLabelsExact),
            ("host-workspace-identity", I::HostWorkspaceIdentity),
            ("container-uid-gid", I::ContainerUidGid),
            (
                "container-capabilities-empty",
                I::ContainerCapabilitiesEmpty,
            ),
            ("container-no-new-privileges", I::ContainerNoNewPrivileges),
            ("container-seccomp-filter", I::ContainerSeccompFilter),
            (
                "container-seccomp-profile-active",
                I::ContainerSeccompProfileActive,
            ),
            ("container-root-read-only", I::ContainerRootReadOnly),
            (
                "container-workspace-writable",
                I::ContainerWorkspaceWritable,
            ),
            ("container-tmp-writable", I::ContainerTmpWritable),
            ("container-no-runtime-socket", I::ContainerNoRuntimeSocket),
            ("container-devices-minimal", I::ContainerDevicesMinimal),
            ("container-pid-private", I::ContainerPidNamespacePrivate),
            ("container-network-isolated", I::ContainerNetworkIsolated),
            ("container-rlimits", I::ContainerRlimits),
            ("container-cgroup-limits", I::ContainerCgroupLimits),
            ("container-proc-restricted", I::ContainerProcRestricted),
            // The escape subset: each attempted from inside, each refused.
            ("escape-mount-blocked", I::ContainerMountBlocked),
            ("escape-unshare-blocked", I::ContainerUnshareBlocked),
            ("escape-setns-blocked", I::ContainerSetnsBlocked),
            ("escape-keyring-blocked", I::ContainerKeyringBlocked),
        ] {
            assert_eq!(verdict(&measurement, invariant), Verdict::Pass, "{case}");
            evidence(case, "pass");
        }

        // Measured again: still clean.
        let again = done(measure(&socket, &ev, &s, &container))
            .environment_measure
            .unwrap();
        assert_eq!(again.state, ContainerState::Running);
        assert!(not_passing(&again.measurement.unwrap()).is_empty());
        evidence("measure-clean-again", "pass");

        // Listed as this store's, with exact labels.
        let listed = list(&socket, &ev);
        let mine: Vec<_> = listed.iter().filter(|o| o.container == container).collect();
        assert_eq!(mine.len(), 1);
        assert!(mine[0].labels_exact);
        assert_eq!(mine[0].environment_id.as_ref(), Some(&e));
        evidence("list-owned-exact-labels", "listed");

        // Destroyed exactly, and a second destruction finds nothing.
        let destroyed = done(destroy(&socket, &ev, (&e, &r), Some(&container)))
            .environment_destroy
            .unwrap();
        assert_eq!(destroyed.state, DestroyState::Removed);
        assert_eq!(destroyed.container.as_ref(), Some(&container));
        assert!(!ev.exists(container.as_str()));
        evidence("destroy-removed", "removed");
        let again = done(destroy(&socket, &ev, (&e, &r), Some(&container)))
            .environment_destroy
            .unwrap();
        assert_eq!(again.state, DestroyState::AlreadyGone);
        evidence("destroy-already-gone", "already-gone");
    }

    // ---- the meta-tests: one weakening at a time ---------------------------

    /// The strict plan, spelled by this test from the profile's own values,
    /// for `(environment, run)` of this store, from `image`, with `mutate`
    /// applied. The baseline case proves the unmutated spelling measures
    /// clean, so each mutation is exactly one weakening of a conforming
    /// container. **Test code only**: no product path builds a weaker plan.
    fn test_only_plan(
        seccomp: &Path,
        workspace: &Path,
        (environment, run): (&EnvironmentId, &RunId),
        image: &str,
        mutate: &dyn Fn(&mut Vec<String>),
    ) -> Vec<String> {
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
        ] {
            argv.push("--label".into());
            argv.push(format!("{key}={value}"));
        }
        let words: Vec<String> = [
            "--name".to_owned(),
            format!("dw-test-{}", environment.as_str()),
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
            "none".to_owned(),
        ]
        .into_iter()
        .collect();
        argv.extend(words);
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
            image.to_owned(),
            profile::PROBE_HOLD.to_owned(),
        ] {
            argv.push(word);
        }
        mutate(&mut argv);
        argv
    }

    fn drop_word(argv: &mut Vec<String>, word: &str) {
        argv.retain(|w| w != word);
    }

    /// Remove `flag value`, wherever it is.
    fn drop_flag(argv: &mut Vec<String>, flag: &str, value: &str) {
        if let Some(at) = argv.windows(2).position(|w| w[0] == flag && w[1] == value) {
            argv.drain(at..at + 2);
        }
    }

    fn replace_value(argv: &mut [String], flag: &str, value: &str) {
        let at = argv.iter().position(|w| w == flag).unwrap();
        argv[at + 1] = value.to_owned();
    }

    /// Options go before the image: insert them before `--entrypoint`.
    fn add(argv: &mut Vec<String>, words: &[&str]) {
        let at = argv.iter().position(|w| w == "--entrypoint").unwrap();
        for (i, w) in words.iter().enumerate() {
            argv.insert(at + i, (*w).to_owned());
        }
    }

    /// Create and start a test-only container from `argv`; its id.
    fn started(ev: &Evidence, argv: &[String]) -> String {
        let words: Vec<&str> = argv.iter().map(String::as_str).collect();
        let id = ev.docker_ok(&words).trim().to_owned();
        CREATED.lock().unwrap().push(id.clone());
        ev.docker_ok(&["container", "start", &id]);
        id
    }

    fn seccomp_file(socket: &Path) -> PathBuf {
        // The broker's own profile file, which its listener wrote.
        std::fs::canonicalize(socket.parent().unwrap().join("oci-strict.seccomp.json")).unwrap()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn every_weakened_profile_is_detected() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("weakened");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let seccomp = seccomp_file(&socket);
        let docker_sock = ev.socket.clone();
        type Mutation = Box<dyn Fn(&mut Vec<String>)>;
        let cases: Vec<(&str, Mutation, &[I])> = vec![
            ("baseline-conforming", Box::new(|_| {}), &[]),
            (
                "weakened-writable-root",
                Box::new(|a| drop_word(a, "--read-only")),
                &[I::HostRootReadOnly, I::ContainerRootReadOnly],
            ),
            (
                "weakened-root-user",
                Box::new(|a| replace_value(a, "--user", "0:0")),
                &[I::HostUserNonRoot, I::ContainerUidGid],
            ),
            (
                "weakened-privileged",
                Box::new(|a| add(a, &["--privileged"])),
                // The runtime keeps an explicitly named seccomp profile even
                // when privileged; what privilege adds is seen from both sides.
                &[
                    I::HostNotPrivileged,
                    I::ContainerCapabilitiesEmpty,
                    I::ContainerDevicesMinimal,
                    I::ContainerProcRestricted,
                ],
            ),
            (
                "weakened-runtime-socket-mounted",
                Box::new(move |a| {
                    add(
                        a,
                        &["--volume", &format!("{docker_sock}:/var/run/docker.sock")],
                    );
                }),
                &[
                    I::HostNoRuntimeSocket,
                    I::HostMountsExact,
                    I::ContainerNoRuntimeSocket,
                ],
            ),
            (
                "weakened-capability-added",
                Box::new(|a| add(a, &["--cap-add", "NET_RAW"])),
                &[I::HostCapabilitiesDropped, I::ContainerCapabilitiesEmpty],
            ),
            (
                "weakened-no-new-privileges-disabled",
                Box::new(|a| drop_flag(a, "--security-opt", "no-new-privileges=true")),
                &[I::HostNoNewPrivileges, I::ContainerNoNewPrivileges],
            ),
            (
                "weakened-seccomp-unconfined",
                Box::new(|a| {
                    let at = a.iter().position(|w| w.starts_with("seccomp=")).unwrap();
                    a[at] = "seccomp=unconfined".to_owned();
                }),
                // A runtime may stack a filter of its own (Docker Desktop does),
                // so "a filter is on" is not enough: the host sees the profile
                // gone, and the canaries inside are no longer refused.
                &[I::HostSeccompProfile, I::ContainerSeccompProfileActive],
            ),
            (
                // A filter is present — the runtime's default — but it is
                // not DireWolf's: the host sees another profile, and the
                // canaries inside (ptrace of its own child, a read of its own
                // memory, both of which the default admits) are not refused.
                "weakened-seccomp-default-profile",
                Box::new(|a| {
                    let at = a.iter().position(|w| w.starts_with("seccomp=")).unwrap();
                    a.drain(at - 1..=at);
                }),
                &[I::HostSeccompProfile, I::ContainerSeccompProfileActive],
            ),
            (
                "weakened-host-pid",
                Box::new(|a| add(a, &["--pid", "host"])),
                &[I::HostPidNamespacePrivate, I::ContainerPidNamespacePrivate],
            ),
            (
                "weakened-host-ipc",
                Box::new(|a| replace_value(a, "--ipc", "host")),
                &[I::HostIpcNamespacePrivate],
            ),
            (
                "weakened-host-network",
                Box::new(|a| replace_value(a, "--network", "host")),
                &[I::HostNetworkIsolated, I::ContainerNetworkIsolated],
            ),
            (
                "weakened-mutable-image-tag",
                Box::new({
                    let (image, tag) = (ev.image.clone(), ev.tag.clone());
                    move |a| {
                        let at = a.iter().position(|w| *w == image).unwrap();
                        a[at].clone_from(&tag);
                    }
                }),
                &[I::HostImagePinned],
            ),
            (
                "weakened-extra-device",
                Box::new(|a| add(a, &["--device", "/dev/zero:/dev/extra"])),
                &[I::HostNoDevices, I::ContainerDevicesMinimal],
            ),
            (
                "weakened-resource-limits-dropped",
                Box::new(|a| {
                    replace_value(a, "--pids-limit", "-1");
                    replace_value(a, "--memory-swap", "-1");
                }),
                &[I::HostResourceLimits, I::ContainerCgroupLimits],
            ),
        ];
        let mut weakened = 0usize;
        for (case, mutate, caught) in cases {
            let (e, r) = (environment(), run());
            let argv = test_only_plan(&seccomp, &workspace, (&e, &r), &ev.image, &*mutate);
            let id = started(&ev, &argv);
            let container = ContainerRef::new(id.clone()).unwrap();
            let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
            let measured = done(measure(&socket, &ev, &s, &container))
                .environment_measure
                .unwrap();
            ev.remove(&id);
            let measurement = measured.measurement.unwrap();
            let found = not_passing(&measurement);
            if caught.is_empty() {
                assert!(found.is_empty(), "{case}: {found:?}");
                evidence(case, "clean");
                continue;
            }
            for invariant in caught {
                assert_eq!(
                    verdict(&measurement, *invariant),
                    Verdict::Fail,
                    "{case}: {invariant:?} not caught; found {found:?}"
                );
            }
            weakened += 1;
            evidence(
                case,
                &format!(
                    "detected:{}",
                    caught
                        .iter()
                        .map(|i| i.as_str())
                        .collect::<Vec<_>>()
                        .join("+")
                ),
            );
        }
        evidence(
            "weakened-count",
            &format!("detected-{weakened}-of-{weakened}"),
        );
    }

    // ---- the probe cannot be tampered with ---------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn a_tampered_probe_is_never_believed_and_never_leaves_a_container() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("tamper");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        for (case, image, pinned, digest) in [
            // The authority pins the real probe; the image carries other
            // bytes: the digest fails and the probe is never run.
            (
                "tamper-changed-byte",
                &ev.tampered_byte,
                &ev.probe_sha256,
                Verdict::Fail,
            ),
            (
                "tamper-substituted-probe",
                &ev.substituted,
                &ev.probe_sha256,
                Verdict::Fail,
            ),
            // A probe the authority did pin — the fixture — whose output is
            // not a report: nothing it says is believed.
            (
                "tamper-malformed-output",
                &ev.malformed,
                &ev.fixture_sha256,
                Verdict::Pass,
            ),
            (
                "tamper-truncated-output",
                &ev.truncated,
                &ev.fixture_sha256,
                Verdict::Pass,
            ),
            (
                "tamper-extra-field",
                &ev.extra_field,
                &ev.fixture_sha256,
                Verdict::Pass,
            ),
            (
                "tamper-flood-output",
                &ev.flood,
                &ev.fixture_sha256,
                Verdict::Pass,
            ),
            (
                "tamper-hang-timeout",
                &ev.hang,
                &ev.fixture_sha256,
                Verdict::Pass,
            ),
        ] {
            let (e, r) = (environment(), run());
            let s = spec(&e, &r, &workspace, image, pinned);
            let since = Instant::now();
            let prepared = done(prepare(&socket, &ev, &s)).environment_prepare.unwrap();
            let took = since.elapsed();
            assert!(!prepared.retained, "{case}: {}", broker.stderr());
            let measurement = prepared.measurement.unwrap();
            assert_eq!(verdict(&measurement, I::HostProbeDigest), digest, "{case}");
            for invariant in I::ALL
                .iter()
                .filter(|i| i.as_str().starts_with("CONTAINER_"))
            {
                assert_eq!(
                    verdict(&measurement, *invariant),
                    Verdict::Unobservable,
                    "{case}: {invariant:?}"
                );
            }
            // Removed before the answer: nothing of it is left.
            if let Some(container) = prepared.container {
                assert!(!ev.exists(container.as_str()), "{case}: left behind");
            }
            if case == "tamper-hang-timeout" {
                // Bounded by the probe step, well inside the exchange.
                assert!(took < Duration::from_secs(100), "{took:?}");
                evidence(case, &format!("refused-after-{}s", took.as_secs()));
            } else {
                evidence(case, "refused-unobservable-removed");
            }
        }
    }

    // ---- foreign containers ------------------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn foreign_containers_survive_listing_measurement_and_destruction() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("foreign");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, true, None);
        let prefix = format!("dw-foreign-{}", std::process::id());
        let (e, r) = (environment(), run());
        let create = |name: &str, labels: &[String]| {
            let mut argv = vec!["create".to_owned(), "--name".to_owned(), name.to_owned()];
            for label in labels {
                argv.push("--label".to_owned());
                argv.push(label.clone());
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
        let label = |key: &str, value: &str| format!("{key}={value}");
        let foreign = [
            // An ordinary container, nobody's labels.
            create(&format!("{prefix}-unrelated"), &[]),
            // DireWolf's name, and no label at all.
            create(
                &format!("direwolf-{}-{}", store().as_str(), e.as_str()),
                &[],
            ),
            // Some of DireWolf's labels: not the owner's.
            create(
                &format!("{prefix}-partial"),
                &[
                    label(profile::LABEL_STORE, store().as_str()),
                    label(profile::LABEL_ENVIRONMENT, e.as_str()),
                ],
            ),
            // Another DireWolf store's environment, same environment id.
            create(
                &format!("{prefix}-other-store"),
                &[
                    label(profile::LABEL_OWNER, profile::LABEL_OWNER_VALUE),
                    label(profile::LABEL_STORE, "ffffffff"),
                    label(profile::LABEL_ENVIRONMENT, e.as_str()),
                    label(profile::LABEL_RUN, r.as_str()),
                ],
            ),
            // This store's name, another owner.
            create(
                &format!("{prefix}-other-owner"),
                &[
                    label(profile::LABEL_OWNER, "someone-else"),
                    label(profile::LABEL_STORE, store().as_str()),
                    label(profile::LABEL_ENVIRONMENT, e.as_str()),
                ],
            ),
        ];
        let listed = list(&socket, &ev);
        for id in &foreign {
            assert!(
                !listed.iter().any(|o| o.container.as_str() == id),
                "listed {id}"
            );
        }
        evidence("foreign-not-listed", "absent-5");
        // Destroying the environment those labels name touches none of them:
        // nothing is labelled as it in this store.
        let destroyed = done(destroy(&socket, &ev, (&e, &r), None))
            .environment_destroy
            .unwrap();
        assert_eq!(destroyed.state, DestroyState::AlreadyGone);
        // And naming one of them as the recorded container is refused, as is
        // measuring it.
        let named = ContainerRef::new(foreign[3].clone()).unwrap();
        assert_eq!(
            refusal(destroy(&socket, &ev, (&e, &r), Some(&named))),
            BrokerRefusal::ForeignEnvironment
        );
        evidence("foreign-destroy-refused", "foreign-environment");
        let s = spec(&e, &r, &dir.workspace("ws"), &ev.image, &ev.probe_sha256);
        assert_eq!(
            refusal(measure(&socket, &ev, &s, &named)),
            BrokerRefusal::ForeignEnvironment
        );
        evidence("foreign-measure-refused", "foreign-environment");

        // A container carrying exactly this store's labels for one
        // environment is destroyed by those labels, exactly — the broker's
        // primitive. Whether it is reaped is the authority's decision, from
        // its records (the authority suite shows copied labels are spared).
        let (le, lr) = (environment(), run());
        let labelled = create(
            &format!("{prefix}-labelled"),
            &[
                label(profile::LABEL_OWNER, profile::LABEL_OWNER_VALUE),
                label(profile::LABEL_SCHEMA, profile::LABEL_SCHEMA_VALUE),
                label(profile::LABEL_STORE, store().as_str()),
                label(profile::LABEL_ENVIRONMENT, le.as_str()),
                label(profile::LABEL_RUN, lr.as_str()),
                label(
                    profile::LABEL_PROFILE,
                    EnvironmentProfile::OciStrict.label(),
                ),
            ],
        );
        let listed = list(&socket, &ev);
        let found: Vec<_> = listed
            .iter()
            .filter(|o| o.container.as_str() == labelled)
            .collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].labels_exact);
        let removed = done(destroy(&socket, &ev, (&le, &lr), None))
            .environment_destroy
            .unwrap();
        assert_eq!(removed.state, DestroyState::Removed);
        assert!(!ev.exists(&labelled));
        evidence("destroy-by-label-exact", "removed");
        for id in &foreign {
            assert!(ev.exists(id), "{id} was touched");
            ev.remove(id);
        }
        evidence("foreign-survive", "5-present");
    }

    // ---- drift, persistence, isolation -------------------------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn drift_is_measured_from_both_vantages() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("drift");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);
        // The runtime changes a running environment under DireWolf.
        ev.docker_ok(&[
            "container",
            "update",
            "--pids-limit",
            "4096",
            container.as_str(),
        ]);
        let measured = done(measure(&socket, &ev, &s, &container))
            .environment_measure
            .unwrap()
            .measurement
            .unwrap();
        assert_eq!(verdict(&measured, I::HostResourceLimits), Verdict::Fail);
        assert_eq!(verdict(&measured, I::ContainerCgroupLimits), Verdict::Fail);
        evidence("drift-pids-limit-raised", "detected-host-and-inside");
        ev.remove(container.as_str());
    }

    /// The names `dir` holds inside a fixture container, as the fixture
    /// itself lists them (the runtime's copy does not see into a `tmpfs`).
    fn names_in(ev: &Evidence, container: &str, dir: &str) -> Vec<String> {
        let (code, out) = fixture(ev, container, &["list", dir]);
        assert_eq!(code, Some(0), "{out}");
        out.lines().map(str::to_owned).collect()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn temporary_state_does_not_persist_and_two_runs_are_isolated() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("persist");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let (run_a, run_b) = (run(), run());
        let (ea, eb) = (environment(), environment());
        let wa = dir.workspace("wa");
        let wb = dir.workspace("wb");
        let sa = spec(&ea, &run_a, &wa, &ev.image, &ev.probe_sha256);
        let sb = spec(&eb, &run_b, &wb, &ev.image, &ev.probe_sha256);
        // Each probe leaves its environment's marker in /tmp and /var/tmp
        // (TMP_WRITABLE), and finds nothing there but its own (TMP_FRESH).
        let (ca, ma) = prepared_clean(&socket, &ev, &sa, &broker);
        let (cb, mb) = prepared_clean(&socket, &ev, &sb, &broker);
        assert_ne!(ea, eb);
        assert_ne!(ca, cb);
        evidence(
            "run-isolation-distinct-environments",
            "distinct-ids-and-containers",
        );
        for measured in [&ma, &mb] {
            assert_eq!(verdict(measured, I::ContainerTmpWritable), Verdict::Pass);
            assert_eq!(verdict(measured, I::ContainerTmpFresh), Verdict::Pass);
        }
        evidence("run-isolation-tmp", "each-fresh-with-own-marker");
        // Each is labelled as itself only.
        let listed = list(&socket, &ev);
        for (container, e, r) in [(&ca, &ea, &run_a), (&cb, &eb, &run_b)] {
            let found: Vec<_> = listed
                .iter()
                .filter(|o| &o.container == container)
                .collect();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].environment_id.as_ref(), Some(e));
            assert_eq!(found[0].run_id.as_ref(), Some(r));
        }
        // Environment A goes; B is untouched and still clean — and still
        // holds only its own marker.
        let _ = done(destroy(&socket, &ev, (&ea, &run_a), Some(&ca)));
        let still = done(measure(&socket, &ev, &sb, &cb))
            .environment_measure
            .unwrap();
        assert_eq!(still.state, ContainerState::Running);
        assert!(not_passing(&still.measurement.unwrap()).is_empty());
        evidence("run-isolation-destroy-one-leaves-other", "other-clean");
        // Run A's next environment starts from nothing.
        let ec = environment();
        let sc = spec(&ec, &run_a, &wa, &ev.image, &ev.probe_sha256);
        let (cc, measured) = prepared_clean(&socket, &ev, &sc, &broker);
        assert_ne!(cc, ca);
        assert_ne!(ec, ea);
        assert_eq!(verdict(&measured, I::ContainerTmpFresh), Verdict::Pass);
        let _ = done(destroy(&socket, &ev, (&ec, &run_a), Some(&cc)));
        let _ = done(destroy(&socket, &ev, (&eb, &run_b), Some(&cb)));

        // The same, observed directly: a marker written into one strict
        // environment's /tmp — not the workspace — is seen there, and in no
        // environment made after it.
        let seccomp = seccomp_file(&socket);
        let strict = |workspace: &Path| {
            let (e, r) = (environment(), run());
            started(
                &ev,
                &test_only_plan(&seccomp, workspace, (&e, &r), &ev.fixture, &|_| {}),
            )
        };
        let first = strict(&wa);
        let (code, out) = fixture(&ev, &first, &["mark", "/tmp/direwolf-marker-a"]);
        assert_eq!(code, Some(0), "{out}");
        assert!(names_in(&ev, &first, "/tmp").contains(&"direwolf-marker-a".to_owned()));
        let other = strict(&wb);
        assert!(!names_in(&ev, &other, "/tmp").contains(&"direwolf-marker-a".to_owned()));
        ev.remove(&first);
        let next = strict(&wa);
        let listed_next = names_in(&ev, &next, "/tmp");
        assert!(
            !listed_next.contains(&"direwolf-marker-a".to_owned()),
            "{listed_next:?}"
        );
        assert!(!wa.join("direwolf-marker-a").exists(), "not the workspace");
        ev.remove(&other);
        ev.remove(&next);
        evidence(
            "persistence-tmp-marker-not-inherited",
            "absent-after-destroy",
        );
    }

    // ---- what the lifecycle says when things go wrong ----------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn exit_semantics_distinguish_stopped_gone_unreachable_and_unavailable() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("exits");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
        let (container, _) = prepared_clean(&socket, &ev, &s, &broker);

        // Stopped: its state says so, nothing inside is believed.
        ev.docker_ok(&["container", "kill", container.as_str()]);
        let measured = done(measure(&socket, &ev, &s, &container))
            .environment_measure
            .unwrap();
        assert_eq!(measured.state, ContainerState::Exited);
        let measurement = measured.measurement.unwrap();
        assert_eq!(verdict(&measurement, I::HostRunning), Verdict::Fail);
        assert_eq!(
            verdict(&measurement, I::ContainerUidGid),
            Verdict::Unobservable
        );
        evidence("exit-stopped-unobservable-inside", "exited");

        // Gone: not found, never mistaken for a clean exit.
        ev.remove(container.as_str());
        assert_eq!(
            refusal(measure(&socket, &ev, &s, &container)),
            BrokerRefusal::EnvironmentNotFound
        );
        evidence("exit-gone-not-found", "environment-not-found");

        // A runtime that cannot be reached: refused, nothing created.
        let (e2, r2) = (environment(), run());
        let s2 = spec(&e2, &r2, &workspace, &ev.image, &ev.probe_sha256);
        let mut bad = ev.clone();
        bad.socket = "/nonexistent/docker.sock".to_owned();
        assert_eq!(
            refusal(prepare(&socket, &bad, &s2)),
            BrokerRefusal::RuntimeUnavailable
        );
        evidence("exit-runtime-unavailable", "runtime-unavailable");

        // An image that is not present: never pulled, refused.
        let absent = format!("sha256:{}", "0".repeat(64));
        let s3 = spec(&e2, &r2, &workspace, &absent, &ev.probe_sha256);
        assert_eq!(
            refusal(prepare(&socket, &ev, &s3)),
            BrokerRefusal::ImageMissing
        );
        evidence("exit-image-missing-never-pulled", "image-missing");

        // PROXY_ONLY does not exist yet; NO_NETWORK only with the evidence
        // acknowledgement.
        let mut proxy = s2.clone();
        proxy.network = NetworkTopology::ProxyOnly;
        assert_eq!(
            refusal(prepare(&socket, &ev, &proxy)),
            BrokerRefusal::TopologyUnavailable
        );
        evidence("topology-proxy-only-unavailable", "topology-unavailable");
        drop(broker);
        let plain = Scratch::new("exits-plain");
        let _production = Broker::start(&plain.socket(), false, None);
        assert_eq!(
            refusal(prepare(&plain.socket(), &ev, &s2)),
            BrokerRefusal::TopologyUnavailable
        );
        evidence(
            "topology-no-network-needs-evidence-flag",
            "topology-unavailable",
        );
        // Nothing was created by any of these.
        let listed = list(&plain.socket(), &ev);
        assert!(
            !listed
                .iter()
                .any(|o| o.environment_id.as_ref() == Some(&e2)),
            "a refused preparation left a container"
        );
        evidence("refusals-create-nothing", "none-listed");
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn a_broker_crash_after_creation_leaves_only_a_labelled_reapable_container() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("crash");
        let socket = dir.socket();
        let mut crashing = Broker::start(&socket, true, Some("environment_created"));
        let workspace = dir.workspace("ws");
        let (e, r) = (environment(), run());
        let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
        // The broker aborts after the runtime created the container: the
        // authority gets no answer.
        let (runtime, exe, cwd) = runtime(&ev);
        let spec = s.clone();
        let answer = try_exchange(
            &socket,
            move |common| {
                Authorisation::EnvironmentPrepare(EnvironmentPrepareAuthorisation::new(
                    common, spec, runtime,
                ))
            },
            (exe, cwd),
        );
        assert!(answer.is_none(), "no answer after a crash: {answer:?}");
        let deadline = Instant::now() + PROMPT;
        while !crashing.exited() {
            assert!(Instant::now() < deadline, "the broker did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(crashing);
        // A fresh broker finds it by label, and removes exactly it.
        let _broker = Broker::start(&socket, true, None);
        let listed = list(&socket, &ev);
        let found: Vec<_> = listed
            .iter()
            .filter(|o| o.environment_id.as_ref() == Some(&e))
            .collect();
        assert_eq!(found.len(), 1, "exactly one labelled container");
        assert!(found[0].labels_exact);
        evidence("crash-w3-broker-after-create-labelled", "found-by-label");
        let reaped = done(destroy(&socket, &ev, (&e, &r), None))
            .environment_destroy
            .unwrap();
        assert_eq!(reaped.state, DestroyState::Removed);
        assert!(!ev.exists(found[0].container.as_str()));
        evidence("crash-w3-reaped-by-label", "removed");
    }

    // ---- resources, under bounded pressure ---------------------------------

    /// Run the fixture's `mode` inside `container`; exit code and stdout.
    fn fixture(ev: &Evidence, container: &str, mode: &[&str]) -> (Option<i32>, String) {
        let mut args = vec!["container", "exec", container, profile::PROBE_PATH];
        args.extend_from_slice(mode);
        let out = ev.docker(&args);
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn field(text: &str, key: &str) -> Option<u64> {
        text.split_whitespace()
            .filter_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .next_back()?
            .parse()
            .ok()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn resource_limits_hold_under_bounded_pressure() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("pressure");
        let socket = dir.socket();
        let _broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let seccomp = seccomp_file(&socket);
        let (e, r) = (environment(), run());
        // The strict profile, with the fixture where the probe would be: the
        // pressure is applied from inside a conforming environment.
        let argv = test_only_plan(&seccomp, &workspace, (&e, &r), &ev.fixture, &|_| {});
        let id = started(&ev, &argv);

        // Ordinary child processes and threads still work: `clone` without a
        // namespace flag is admitted, and `clone3`'s ENOSYS makes the C
        // library fall back to it.
        let (code, out) = fixture(&ev, &id, &["spawn"]);
        assert_eq!(code, Some(0), "{out}");
        assert!(
            out.contains("child=exit status: 0") && out.contains("thread=7"),
            "{out}"
        );
        evidence(
            "subprocess-and-thread-creation",
            "child-exit-0-thread-joined",
        );

        // PIDs: the environment refuses the task past its limit.
        let (code, out) = fixture(&ev, &id, &["pids"]);
        assert_eq!(code, Some(0), "{out}");
        let threads = field(&out, "threads").unwrap();
        assert!(threads < profile::PIDS_LIMIT, "{out}");
        assert!(!out.contains("refused=none"), "{out}");
        evidence(
            "resource-pids-bounded",
            &format!("threads-{threads}-refused"),
        );

        // Descriptors: RLIMIT_NOFILE.
        let (code, out) = fixture(&ev, &id, &["fds"]);
        assert_eq!(code, Some(0), "{out}");
        let opened = field(&out, "opened").unwrap();
        assert!(opened < profile::RLIMIT_NOFILE, "{out}");
        assert!(out.contains("refused=Some(24)"), "EMFILE: {out}");
        evidence("resource-fds-bounded", &format!("opened-{opened}-emfile"));

        // Memory: the ceiling ends the allocation — the kernel's OOM killer,
        // counted in the cgroup's own events — long before 4 GiB.
        let (code, out) = fixture(&ev, &id, &["memory"]);
        assert!(!out.contains("memory=unbounded"), "{out}");
        assert_eq!(code, Some(137), "killed by SIGKILL: {out}");
        let reached = field(&out, "allocated_mib").unwrap_or(0);
        assert!(reached <= profile::MEMORY_BYTES >> 20, "{out}");
        let (_, events) = fixture(&ev, &id, &["events"]);
        let kills = events
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        assert!(kills >= 1, "{events}");
        evidence(
            "resource-memory-oom-killed",
            &format!("killed-at-{reached}mib-oom_kill-{kills}"),
        );

        // File size: RLIMIT_FSIZE stops the file at exactly its bound.
        let (code, out) = fixture(&ev, &id, &["fsize", "/workspace/big"]);
        let size = std::fs::metadata(workspace.join("big")).unwrap().len();
        assert_eq!(size, profile::RLIMIT_FSIZE, "{code:?} {out}");
        let _ = std::fs::remove_file(workspace.join("big"));
        evidence(
            "resource-file-size-bounded",
            &format!("stopped-at-{size}-exit-{}", code.unwrap_or(-1)),
        );
        ev.remove(&id);
    }

    // ---- latency ---------------------------------------------------------------

    fn percentile(sorted: &[u32], p: usize) -> u32 {
        let at = (sorted.len() * p).div_ceil(100).saturating_sub(1);
        sorted[at.min(sorted.len() - 1)]
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn latency_of_prepare_measure_and_destroy() {
        let ev = Evidence::load();
        let _reaper = Reaper::new(&ev);
        let dir = Scratch::new("latency");
        let socket = dir.socket();
        let broker = Broker::start(&socket, true, None);
        let workspace = dir.workspace("ws");
        let rounds: usize = std::env::var("DW_SANDBOX_LATENCY_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let (mut prepare_ms, mut measure_ms, mut destroy_ms) = (vec![], vec![], vec![]);
        for _ in 0..rounds {
            let (e, r) = (environment(), run());
            let s = spec(&e, &r, &workspace, &ev.image, &ev.probe_sha256);
            let prepared = done(prepare(&socket, &ev, &s)).environment_prepare.unwrap();
            assert!(prepared.retained, "{}", broker.stderr());
            prepare_ms.push(prepared.prepare_ms.get());
            let container = prepared.container.unwrap();
            let measured = done(measure(&socket, &ev, &s, &container))
                .environment_measure
                .unwrap()
                .measurement
                .unwrap();
            measure_ms.push(measured.measure_ms.get());
            let destroyed = done(destroy(&socket, &ev, (&e, &r), Some(&container)))
                .environment_destroy
                .unwrap();
            destroy_ms.push(destroyed.destroy_ms.get());
        }
        for list in [&mut prepare_ms, &mut measure_ms, &mut destroy_ms] {
            list.sort_unstable();
        }
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"latency\",\"outcome\":\"measured\",\
             \"rounds\":{rounds},\
             \"prepare_ms_median\":{},\"prepare_ms_p95\":{},\
             \"measure_ms_median\":{},\"measure_ms_p95\":{},\
             \"destroy_ms_median\":{},\"destroy_ms_p95\":{}}}",
            percentile(&prepare_ms, 50),
            percentile(&prepare_ms, 95),
            percentile(&measure_ms, 50),
            percentile(&measure_ms, 95),
            percentile(&destroy_ms, 50),
            percentile(&destroy_ms, 95),
        );
    }
}
