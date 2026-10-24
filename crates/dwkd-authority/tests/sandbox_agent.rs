//! M5d.5's agent evidence (ADR-0052 §§11, 13, 17; the M5d.5 handoff,
//! `docs/M5D5_IMPLEMENTATION_HANDOFF.md`): an **agent-shaped** workload run
//! the way a runtime runs one -- a real DWKP client on the **released**
//! `dwkd-authority serve --sandbox-config`, the **released** `dwkd-broker`,
//! a **real** OCI runtime -- in a measured `oci-strict` environment whose
//! network is `PROXY_ONLY`, reaching **exactly** the run's granted HTTPS
//! origins through the real relay and the broker's real CONNECT proxy.
//!
//! What is a fixture here, and what is not:
//!
//! * The **origins** are fixtures: local HTTPS servers
//!   (`tests/net_http/origin.py`) presenting certificates of a PKI made for
//!   this run (`tests/net_http/make-pki.sh`), named through the broker's
//!   evidence-only resolver file (`--allow-evidence-egress`), which also
//!   holds the loopback exception the address guard otherwise refuses. No
//!   public network is touched, and the production resolver has no
//!   exception (M5b's `a_production_broker_has_no_exception_and_no_fixture`).
//! * The **workload** is a fixture: `sandbox-fixture`'s `workload-agent-net`
//!   (a plan, two long-lived workers and a daemonised helper) and the agent's
//!   own network tool (`tests/sandbox/agent_net.py`) run by the image's
//!   Python -- a stock HTTPS client that **verifies** each origin against the
//!   run's test anchor, which sits in the workspace as an agent's own trust
//!   would. The broker terminates no TLS and is given no trust anchor.
//! * The **boundary** is not: the authority's gates and ledger, the
//!   operator's file, the environment's measurement and judgement, the
//!   namespace, the relay, the proxy's grant, guard, server-name check and
//!   budgets, the wall clock, `reap`, the crash windows -- all the product's.
//!
//! Every denial is attributed to the component that made it (`enforcement`
//! in each evidence line): the CONNECT proxy, by the decision it sent
//! (`X-DireWolf-Egress`); the environment's network namespace, by the errno a
//! direct attempt got; the workload's **own** TLS verification, which is the
//! agent's and not DireWolf's; the authority's peer policy, the broker's peer
//! check, the file modes, the kernel. The audit records each environment's
//! egress as counts by disposition when it is destroyed -- never one event
//! per refused attempt, and none is claimed.
//!
//! Two kinds of test:
//!
//! * **One identity** (`an_agent_*`, `budgets_*`, `an_agent_that_*`): every
//!   process is this test's uid, the daemons acknowledging it
//!   (`--allow-shared-*`), the workspace the evidence's scratch directory
//!   under the unverified-evidence waiver. Any Linux host with a runtime
//!   runs them.
//! * **Three identities** (`three_identities_*`): the authority as this
//!   process's uid (A), the broker as `DW_BROKER_AS` (B) started through
//!   `sudo -n -u`, the runtime as `DW_PEER_AS` (C) -- its DWKP connection a
//!   relay (`tests/authority/agent_runtime_client.py`) running as C, so the
//!   kernel reports C to the authority -- and a workspace the operator
//!   provisioned: a bounded filesystem of its own, group 10001, root mode
//!   `2770`. Only a disposable hosted runner provides those
//!   (`DW_AGENT_PRIVILEGED=1`, the `sandbox-agent` job); anywhere else they
//!   panic NOT EXERCISED, which fails `make sandbox-agent-evidence`.
//!
//! Every test is `#[ignore]`d: it needs a runtime, the evidence image and the
//! pinned digests, which `make sandbox-agent-evidence` provides
//! (`DW_SANDBOX_*`, `DW_AGENT_*`). Run any other way it panics NOT EXERCISED.

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
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;
// M4e's secret crates (ADR-0046), reached only through the library.
use age as _;
use getrandom as _;
use hmac as _;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
use zeroize as _;

#[cfg(target_os = "linux")]
mod broker_support;
#[cfg(target_os = "linux")]
mod net_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::{ChannelNonce, FsReadAuthorisation};
    use dwk_proto::dwkp::sandboxops::{
        ExecutionAssurance, ResidueVerdict, SandboxEnding, SandboxedExecResult,
    };
    use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::json::{self, Number, ParseOptions, Value};
    use dwk_proto::wire::id::{AnyId, InvocationId, RunId, SessionId};
    use dwk_proto::wire::scalar::{Epoch, ReadLimit};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::state::{
        DEFAULT_LEASE_TTL_MS, ManualClock, Mode, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, broker_bin};
    use super::net_support::Origin;
    use super::state_support::{
        START_MS, TempDir, acquire_msg, admit_msg, audit_records, ceiling, decode, id,
        install_fixtures, policy, profile, raw, release_run_msg, session,
    };
    use super::transport_support::{Client, PROMPT, Received, Server, handshake, own_uid};

    const SUITE: &str = "sandbox-agent";
    const IDENTITY_SUITE: &str = "sandbox-agent-identity";
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    /// The agent's tool and the run's trust anchor, where the workspace holds
    /// them inside the environment.
    const TOOL: &str = "/workspace/tools/agent_net.py";
    const ANCHOR: &str = "/workspace/tools/ca.pem";
    /// The evidence's names: the granted origin and its second name; a name
    /// that resolves to the origin but is not granted; a granted name the
    /// address guard refuses; the upload sink.
    const ORIGIN: &str = "origin.test";
    const ALT: &str = "alt.origin.test";
    const SECOND: &str = "second.test";
    const BLOCKED: &str = "blocked.test";
    const SINK: &str = "sink.test";
    /// The operator's egress budgets for every environment.
    const MAX_TUNNELS: usize = 4;
    const MAX_UPLOAD: usize = 64 * 1024;
    const MAX_DOWNLOAD: usize = 256 * 1024;
    /// The wall clock every workload of the evidence asks for: the run's
    /// seconds budget is charged it whole (ADR-0052 §10).
    const WALL: u32 = 30;
    /// The workspace group (ADR-0052 §6).
    const WORKSPACE_GID: u32 = 10001;

    // What each line of evidence is (the handoff's §5 precision rule).
    const E2E: &str = "dwkp-end-to-end";
    const OCI: &str = "measured-oci";
    const HOSTED: &str = "hosted-three-identity";

    fn evidence(suite: &str, case: &str, outcome: &str, level: &str, enforcement: &str) {
        let clean = |text: &str| text.replace(['"', '\\', '\n'], "'");
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{}\",\
             \"level\":\"{level}\",\"enforcement\":\"{}\"}}",
            clean(outcome),
            clean(enforcement)
        );
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-agent-evidence`, which \
                 builds the agent image and pins its digests"
            )
        })
    }

    fn mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn next() -> u64 {
        NEXT.fetch_add(1, Ordering::SeqCst)
    }

    // ---- what the evidence task built --------------------------------------

    /// The image and the digests `make sandbox-agent-evidence` pinned.
    #[derive(Clone)]
    struct Pins {
        runtime: String,
        socket: String,
        /// The agent image: the probe, the relay, the fixture, the host's
        /// Python with its standard library, built offline `FROM scratch`.
        image: String,
        probe: String,
        relay: String,
        fixture: String,
        python: String,
        python_sha: String,
    }

    impl Pins {
        fn load() -> Self {
            Self {
                runtime: var("DW_SANDBOX_RUNTIME"),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_AGENT_IMAGE"),
                probe: var("DW_SANDBOX_PROBE_SHA256"),
                relay: var("DW_EGRESS_RELAY_SHA256"),
                fixture: var("DW_SANDBOX_FIXTURE_SHA256"),
                python: var("DW_SANDBOX_PYTHON"),
                python_sha: var("DW_SANDBOX_PYTHON_SHA256"),
            }
        }
    }

    /// The runtime client, as this test uses it directly: to look, never to
    /// run a workload.
    #[derive(Clone)]
    struct Runtime {
        client: PathBuf,
        socket: String,
    }

    impl Runtime {
        fn docker(&self, args: &[&str]) -> Output {
            super::state_support::output(
                Command::new(&self.client)
                    .env_clear()
                    .env("HOME", std::env::temp_dir())
                    .arg("--host")
                    .arg(format!("unix://{}", self.socket))
                    .args(args),
            )
            .unwrap()
        }

        fn ok(&self, args: &[&str]) -> String {
            let out = self.docker(args);
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        }

        fn exists(&self, id: &str) -> bool {
            self.docker(&["container", "inspect", "--format", "{{.Id}}", id])
                .status
                .success()
        }

        fn label(&self, id: &str, key: &str) -> String {
            self.ok(&[
                "container",
                "inspect",
                "--format",
                &format!("{{{{index .Config.Labels \"{key}\"}}}}"),
                id,
            ])
            .trim()
            .to_owned()
        }

        /// Every process the container holds besides init and the census:
        /// `uid=<n> argv=<words>`, as the fixture inside it reads `/proc`.
        fn procs(&self, container: &str) -> Vec<String> {
            self.ok(&["container", "exec", container, FIXTURE, "workload-procs"])
                .lines()
                .filter_map(|l| l.strip_prefix("proc "))
                .map(str::to_owned)
                .collect()
        }

        /// Wait, bounded, until the container holds every one of `lines`;
        /// then every process it held.
        fn awaited(&self, container: &str, lines: &[&str]) -> Vec<String> {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let procs = self.procs(container);
                if lines.iter().all(|line| procs.iter().any(|p| p == line)) {
                    return procs;
                }
                assert!(
                    Instant::now() < deadline,
                    "{lines:?} never ran; the container held {procs:?}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        /// The containers of `environment` with the role `role`.
        fn role(&self, environment: &str, role: &str) -> Vec<String> {
            self.ok(&[
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                &format!("label=io.direwolf.environment={environment}"),
                "--filter",
                &format!("label=io.direwolf.role={role}"),
            ])
            .lines()
            .map(str::to_owned)
            .collect()
        }

        /// The (uid, gid) of every process of `container`, as the host's
        /// kernel reports them (`docker top`, which runs `ps` where the
        /// runtime runs and keeps the container's pids -- so the `pid`
        /// column is required): not what the container says of itself.
        fn host_ids(&self, container: &str) -> Vec<(u32, u32)> {
            self.ok(&["container", "top", container, "-eo", "pid,uid,gid"])
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let mut words = line.split_whitespace().skip(1);
                    Some((words.next()?.parse().ok()?, words.next()?.parse().ok()?))
                })
                .collect()
        }
    }

    /// Every container a test had made, removed when it ends: whatever
    /// carries a store label it noted. Nothing else is touched.
    struct Reaper {
        runtime: Runtime,
        stores: Mutex<BTreeSet<String>>,
    }

    impl Reaper {
        fn note(&self, container: &str) {
            let store = self.runtime.label(container, "io.direwolf.store");
            self.stores.lock().unwrap().insert(store);
        }
    }

    impl Drop for Reaper {
        fn drop(&mut self) {
            let stores = std::mem::take(&mut *self.stores.lock().unwrap());
            for store in stores {
                let out = self.runtime.docker(&[
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    &format!("label=io.direwolf.store={store}"),
                ]);
                for id in String::from_utf8_lossy(&out.stdout).lines() {
                    let _ = self
                        .runtime
                        .docker(&["container", "rm", "--force", "--volumes", id]);
                }
            }
        }
    }

    /// A plain TCP origin for the upload budget: counts connections and the
    /// bytes it receives, and never answers.
    struct Sink {
        port: u16,
        accepted: Arc<AtomicUsize>,
        received: Arc<AtomicUsize>,
    }

    impl Sink {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepted = Arc::new(AtomicUsize::new(0));
            let received = Arc::new(AtomicUsize::new(0));
            let (count, total) = (Arc::clone(&accepted), Arc::clone(&received));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    count.fetch_add(1, Ordering::SeqCst);
                    let total = Arc::clone(&total);
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                        let mut buffer = [0u8; 16 * 1024];
                        while let Ok(n) = stream.read(&mut buffer) {
                            if n == 0 {
                                break;
                            }
                            total.fetch_add(n, Ordering::SeqCst);
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

        fn received(&self) -> usize {
            self.received.load(Ordering::SeqCst)
        }
    }

    // ---- the three identities ------------------------------------------------

    /// The separated deployment's users, each proven by the uid a process
    /// started as it reports: never a name alone.
    struct Identities {
        broker_user: String,
        broker_uid: u32,
        runtime_user: String,
        runtime_uid: u32,
        outsider_user: String,
        outsider_uid: u32,
    }

    /// The user `variable` names, the uid it runs as, distinct from this
    /// process's, root's and `others`.
    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user `sudo -n -u` can switch to (the hosted \
             `sandbox-agent` job creates it)"
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
        assert_ne!(uid, own_uid(), "{variable}={user} is this process's uid");
        assert_ne!(uid, 0, "{variable}={user} is root");
        assert!(!others.contains(&uid), "{variable}={user} shares a uid");
        for sandbox in [10001, 10002] {
            assert_ne!(uid, sandbox, "{variable}={user} is a sandbox identity");
        }
        (user, uid)
    }

    fn identities() -> Identities {
        assert_eq!(
            std::env::var("DW_AGENT_PRIVILEGED").unwrap_or_default(),
            "1",
            "NOT EXERCISED: the three-identity agent evidence needs a disposable host that \
             provisions three users, the workspace group and a bounded workspace \
             (DW_AGENT_PRIVILEGED=1, the hosted `sandbox-agent` job)"
        );
        let (broker_user, broker_uid) = identity("DW_BROKER_AS", &[]);
        let (runtime_user, runtime_uid) = identity("DW_PEER_AS", &[broker_uid]);
        let (outsider_user, outsider_uid) =
            identity("DW_AGENT_OUTSIDER", &[broker_uid, runtime_uid]);
        Identities {
            broker_user,
            broker_uid,
            runtime_user,
            runtime_uid,
            outsider_user,
            outsider_uid,
        }
    }

    /// `(uid, gid, groups)` of a running process, from its
    /// `/proc/<pid>/status`: the kernel's own account, readable by anyone.
    fn kernel_ids(pid: u32) -> (u32, u32, BTreeSet<u32>) {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |key: &str| -> Vec<u32> {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect()
        };
        let uid = field("Uid:");
        let gid = field("Gid:");
        // Real, effective, saved and filesystem ids all agree: no daemon
        // keeps a second identity in reserve.
        assert!(uid.iter().all(|u| *u == uid[0]), "{pid}: {uid:?}");
        assert!(gid.iter().all(|g| *g == gid[0]), "{pid}: {gid:?}");
        (uid[0], gid[0], field("Groups:").into_iter().collect())
    }

    // ---- a DWKP connection: this process's, or the runtime user's -----------

    /// A DWKP client running as another user: `agent_runtime_client.py
    /// relay`, started through `sudo -n -u`, copying bytes between the
    /// authority's socket and its standard streams. The protocol is this
    /// test's; the peer credential the kernel reports is the relay's.
    struct Relay {
        child: Child,
        stdin: Option<ChildStdin>,
        chunks: mpsc::Receiver<Vec<u8>>,
        decoder: FrameDecoder,
        pending: Vec<u8>,
        /// The relay's own `RELAY {...}` line: its uid, gid and groups.
        identity: json::Object,
    }

    impl Relay {
        fn start(user: &str, script: &Path, socket: &Path) -> Self {
            let mut child = super::state_support::spawn(
                Command::new("sudo")
                    .args(["-n", "-u", user, "/usr/bin/python3"])
                    .arg(script)
                    .arg("relay")
                    .arg(socket)
                    .current_dir(script.parent().unwrap())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
            )
            .expect("sudo starts the relay");
            let stdin = child.stdin.take();
            let mut stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let (lines, line) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                for text in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let _ = lines.send(text);
                }
            });
            let identity = loop {
                let text = line
                    .recv_timeout(Duration::from_secs(20))
                    .expect("the relay says who it is");
                if let Some(rest) = text.strip_prefix("RELAY ") {
                    break object(rest);
                }
            };
            let (sink, chunks) = mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    match stdout.read(&mut buffer) {
                        Ok(0) | Err(_) => {
                            let _ = sink.send(Vec::new());
                            return;
                        }
                        Ok(n) => {
                            if sink.send(buffer[..n].to_vec()).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
            Self {
                child,
                stdin,
                chunks,
                decoder: FrameDecoder::new(),
                pending: Vec::new(),
                identity,
            }
        }

        fn send(&mut self, message: &DwkpMessage) {
            let frame = message.to_frame().expect("the message encodes");
            let stdin = self.stdin.as_mut().expect("the relay is open");
            stdin.write_all(&frame).unwrap();
            stdin.flush().unwrap();
        }

        fn recv(&mut self, timeout: Duration) -> Received {
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
                match self.chunks.recv_timeout(deadline - now) {
                    Ok(chunk) if chunk.is_empty() => return Received::Closed,
                    Ok(chunk) => self.pending.extend_from_slice(&chunk),
                    Err(mpsc::RecvTimeoutError::Timeout) => return Received::TimedOut,
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Received::Closed,
                }
            }
        }
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            // End of input ends the relay; sudo then exits with it.
            drop(self.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// One DWKP connection.
    enum Wire {
        /// This process's own: one identity.
        Own(Client),
        /// The runtime user's, through a relay: three identities.
        Relayed(Relay),
    }

    impl Wire {
        fn send(&mut self, message: &DwkpMessage) {
            match self {
                Self::Own(client) => client.send(message),
                Self::Relayed(relay) => relay.send(message),
            }
        }

        fn recv(&mut self, timeout: Duration) -> Received {
            match self {
                Self::Own(client) => client.recv(timeout),
                Self::Relayed(relay) => relay.recv(timeout),
            }
        }

        fn call(&mut self, message: &DwkpMessage) -> DwkpMessage {
            self.send(message);
            self.recv(PROMPT).message()
        }

        fn handshake(&mut self) {
            let answer = self.call(&handshake(1, 1, 1));
            assert!(
                matches!(answer.body, DwkpBody::HandshakeAccepted(_)),
                "{answer:?}"
            );
        }
    }

    // ---- JSON the workload printed ---------------------------------------

    fn object(text: &str) -> json::Object {
        match json::parse(text.trim().as_bytes(), ParseOptions::dwkp()) {
            Ok(Value::Object(object)) => object,
            other => panic!("not a JSON object: {other:?}\n{text}"),
        }
    }

    fn text(object: &json::Object, key: &str) -> String {
        match object.get(key) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    }

    fn int(object: &json::Object, key: &str) -> i64 {
        match object.get(key) {
            Some(Value::Number(Number::Int(n))) => *n,
            _ => -1,
        }
    }

    fn flag(object: &json::Object, key: &str) -> bool {
        matches!(object.get(key), Some(Value::Bool(true)))
    }

    fn ints(object: &json::Object, key: &str) -> BTreeSet<i64> {
        match object.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Number(Number::Int(n)) => Some(*n),
                    _ => None,
                })
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// The line `key=…` of a fixture's output.
    fn field<'a>(output: &'a str, key: &str) -> &'a str {
        output
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or("")
    }

    /// The `name=` of a fixture's `errno=<n> name=<NAME>` line.
    fn errno_name(line: &str) -> &str {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix("name="))
            .unwrap_or("")
    }

    /// An audit record's list member, as text.
    fn texts(record: &json::Object, key: &str) -> Vec<String> {
        match record.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    // ---- the lab ---------------------------------------------------------

    /// The released daemons, the origins, the operator's files, a
    /// workspace with the agent's tools, and the store, set up as an
    /// operator would before the server starts.
    struct Lab {
        dir: TempDir,
        pins: Pins,
        runtime: Runtime,
        reaper: Reaper,
        ids: Option<Identities>,
        stage: PathBuf,
        good: Origin,
        wrong: Origin,
        rogue: Origin,
        sink: Sink,
        broker_socket: PathBuf,
        broker_flags: Vec<String>,
        broker: Option<Broker>,
        config: PathBuf,
        policy: PathBuf,
        socket: PathBuf,
        workspace: PathBuf,
        server: Option<Server>,
    }

    /// Where a lab's workspace is: the evidence's scratch directory under
    /// the unverified-evidence waiver, or an operator-provisioned root of a
    /// bounded filesystem and its quota.
    enum Workspace {
        Waiver,
        Bounded(PathBuf, u64),
    }

    /// The operator's policy: the fixture and the image's Python in a
    /// sandbox, by path and digest; reads in the workspace; nothing on the
    /// host; everything else denied.
    fn policy_text(pins: &Pins) -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5d5"

[[rule]]
id = "the-agent-in-a-sandbox"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{FIXTURE}@{fixture}", "{python}@{python_sha}"]
obligations = ["max_output_bytes=65536"]

[[rule]]
id = "read-the-workspace"
effect = "ALLOW"
when.verb = "fs.read"
when.path_under = "${{WORKSPACE}}"
when.max_bytes = 65536

[[rule]]
id = "never-on-the-host"
effect = "DENY"
reason = "HOST_EXECUTION_DISABLED"
when.verb = "process.exec"
when.environment = "host"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#,
            fixture = pins.fixture,
            python = pins.python,
            python_sha = pins.python_sha,
        )
    }

    impl Lab {
        fn new(tag: &str, ids: Option<Identities>, workspace: &Workspace) -> Self {
            let pins = Pins::load();
            let runtime = Runtime {
                client: PathBuf::from(&pins.runtime),
                socket: pins.socket.clone(),
            };
            let reaper = Reaper {
                runtime: runtime.clone(),
                stores: Mutex::new(BTreeSet::new()),
            };
            let dir = TempDir::new(tag);
            if ids.is_some() {
                // The runtime's user reaches the authority's socket and the
                // staged scripts by name, and lists nothing.
                mode(dir.path(), 0o711);
                for ancestor in dir.path().ancestors().skip(1) {
                    let bits = std::fs::metadata(ancestor).unwrap().permissions().mode();
                    assert!(bits & 0o001 != 0, "{} is closed", ancestor.display());
                }
            }
            let stage = dir.path().join("stage");
            std::fs::create_dir(&stage).unwrap();
            mode(&stage, 0o755);
            for (name, source) in [
                (
                    "agent_runtime_client.py",
                    "tests/authority/agent_runtime_client.py",
                ),
                (
                    "broker_foreign_client.py",
                    "tests/authority/broker_foreign_client.py",
                ),
            ] {
                let staged = stage.join(name);
                std::fs::copy(repo().join(source), &staged).unwrap();
                mode(&staged, 0o644);
            }
            let pki = super::net_support::pki(dir.path());
            let good = Origin::start(&pki, "origin");
            let wrong = Origin::start(&pki, "other");
            let rogue = Origin::start(&pki, "rogue-origin");
            let sink = Sink::start();
            let fixture = stage.join("egress.fixture");
            std::fs::write(
                &fixture,
                format!(
                    "# The M5d.5 agent evidence's names.\n\
                     resolve {ORIGIN} 127.0.0.1\n\
                     resolve {ALT} 127.0.0.1\n\
                     resolve {SECOND} 127.0.0.1\n\
                     resolve {SINK} 127.0.0.1\n\
                     resolve {BLOCKED} 10.0.0.1\n\
                     allow 127.0.0.1\n"
                ),
            )
            .unwrap();
            mode(&fixture, 0o644);

            let (root, contract) = match workspace {
                Workspace::Waiver => {
                    let root = dir.path().join("workspace");
                    std::fs::create_dir(&root).unwrap();
                    mode(&root, 0o777);
                    (root, "unverified_evidence = true".to_owned())
                }
                Workspace::Bounded(root, quota) => {
                    for entry in std::fs::read_dir(root).unwrap() {
                        let path = entry.unwrap().path();
                        if path.is_dir() {
                            std::fs::remove_dir_all(&path).unwrap();
                        } else {
                            std::fs::remove_file(&path).unwrap();
                        }
                    }
                    (root.clone(), format!("quota_bytes = {quota}"))
                }
            };
            // The agent's tools, as its repository would carry them: its
            // network tool and the trust anchor it verifies origins with.
            let tools = root.join("tools");
            std::fs::create_dir(&tools).unwrap();
            let keep_setgid = std::fs::metadata(&tools).unwrap().mode() & 0o2000;
            mode(&tools, 0o755 | keep_setgid);
            for (name, source) in [
                ("agent_net.py", repo().join("tests/sandbox/agent_net.py")),
                ("ca.pem", pki.join("ca.pem")),
            ] {
                std::fs::copy(source, tools.join(name)).unwrap();
                mode(&tools.join(name), 0o644);
            }

            // The store, as the operator's own tooling prepares it.
            let state = dir.state();
            let text = policy_text(&pins);
            {
                let config = StartupConfig::new(policy("m5d5", &text), Mode::Balanced, {
                    let mut ceiling = ceiling();
                    ceiling.push("process.exec:*".to_owned());
                    ceiling
                });
                let clock = Arc::new(ManualClock::new(START_MS));
                let (mut authority, _) = super::state_support::start(&state, &config, &clock, None)
                    .expect("the store starts");
                install_fixtures(&mut authority);
                let mut operator = authority.operator();
                operator
                    .install_agent_profile(&profile(
                        "agent",
                        &["process.exec:*", "fs.read:*", "network.https:*"],
                        &[],
                        PrivacyClass::Any,
                    ))
                    .unwrap();
                let ws = WorkspaceId::new("ws").unwrap();
                operator
                    .install_workspace(&ws, WorkspaceSensitivity::Private)
                    .unwrap();
                operator
                    .install_workspace_root(&ws, root.to_str().unwrap())
                    .unwrap();
                for n in 1..=16 {
                    operator.bind_session_workspace(&session(n), &ws).unwrap();
                }
            }
            let policy_file = dir.path().join("m5d5.toml");
            std::fs::write(&policy_file, &text).unwrap();
            mode(&policy_file, 0o600);
            let config = dir.path().join("sandbox.toml");
            std::fs::write(
                &config,
                format!(
                    "schema_version = 1\nruntime = \"{runtime}\"\nsocket = \"{socket}\"\n\
                     image = \"{image}\"\nprobe_sha256 = \"{probe}\"\nnetwork = \"PROXY_ONLY\"\n\
                     [egress]\nrelay_sha256 = \"{relay}\"\nmax_tunnels = {MAX_TUNNELS}\n\
                     max_upload_bytes = {MAX_UPLOAD}\nmax_download_bytes = {MAX_DOWNLOAD}\n\
                     [budget]\nworkloads = 60\nseconds = 3600\n\
                     [executables]\n\"{FIXTURE}\" = \"{fixture}\"\n\"{python}\" = \"{python_sha}\"\n\
                     [workspace]\n{contract}\n",
                    runtime = pins.runtime,
                    socket = pins.socket,
                    image = pins.image,
                    probe = pins.probe,
                    relay = pins.relay,
                    fixture = pins.fixture,
                    python = pins.python,
                    python_sha = pins.python_sha,
                ),
            )
            .unwrap();
            mode(&config, 0o600);

            let mut broker_flags = vec![
                "--allow-evidence-egress".to_owned(),
                fixture.display().to_string(),
            ];
            if matches!(workspace, Workspace::Waiver) {
                broker_flags.push("--allow-unverified-workspace".to_owned());
            }
            let broker_socket = if ids.is_some() {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() % 1_000_000_000_000);
                PathBuf::from(format!("/tmp/dwa-{}-{nanos}", std::process::id()))
                    .join("broker.sock")
            } else {
                broker_flags.push("--allow-shared-authority-uid".to_owned());
                dir.path().join("broker").join("broker.sock")
            };
            let socket = dir.path().join("ipc").join("kernel.sock");
            let mut lab = Self {
                dir,
                pins,
                runtime,
                reaper,
                ids,
                stage,
                good,
                wrong,
                rogue,
                sink,
                broker_socket,
                broker_flags,
                broker: None,
                config,
                policy: policy_file,
                socket,
                workspace: root,
                server: None,
            };
            lab.start_broker();
            lab.start_server();
            lab
        }

        fn broker(&self) -> &Broker {
            self.broker.as_ref().unwrap()
        }

        fn start_broker(&mut self) {
            let flags: Vec<&str> = self.broker_flags.iter().map(String::as_str).collect();
            self.broker = Some(match &self.ids {
                None => Broker::start(&self.broker_socket, own_uid(), &flags),
                Some(ids) => {
                    let binary = self.stage.join("dwkd-broker");
                    if !binary.exists() {
                        std::fs::copy(broker_bin(), &binary).unwrap();
                        mode(&binary, 0o755);
                    }
                    Broker::start_as_with(
                        &ids.broker_user,
                        &binary,
                        &self.broker_socket,
                        own_uid(),
                        &flags,
                    )
                }
            });
        }

        fn kill_broker(&mut self) {
            if let Some(mut broker) = self.broker.take() {
                broker.kill();
            }
        }

        fn serve_args(&self) -> Vec<String> {
            let mut args: Vec<String> = [
                "serve",
                "--state-dir",
                self.dir.state().to_str().unwrap(),
                "--socket",
                self.socket.to_str().unwrap(),
                "--policy-file",
                self.policy.to_str().unwrap(),
                "--policy-profile",
                "m5d5",
                "--mode",
                "balanced",
                "--broker-socket",
                self.broker_socket.to_str().unwrap(),
                "--sandbox-config",
                self.config.to_str().unwrap(),
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            match &self.ids {
                None => {
                    for a in [
                        "--allow-uid".to_owned(),
                        own_uid().to_string(),
                        "--allow-authority-uid".to_owned(),
                        "--broker-uid".to_owned(),
                        own_uid().to_string(),
                        "--allow-shared-broker-uid".to_owned(),
                    ] {
                        args.push(a);
                    }
                }
                Some(ids) => {
                    // Only the runtime's user is a client; the broker is its
                    // own user, and this process's uid is no client at all.
                    for a in [
                        "--allow-uid".to_owned(),
                        ids.runtime_uid.to_string(),
                        "--broker-uid".to_owned(),
                        ids.broker_uid.to_string(),
                    ] {
                        args.push(a);
                    }
                }
            }
            let mut ceiling = ceiling();
            ceiling.push("process.exec:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            args
        }

        fn start_server(&mut self) {
            let server = Server::start(&self.serve_args());
            assert!(
                server
                    .stderr()
                    .contains("execution environment attached from"),
                "{}",
                server.stderr()
            );
            self.server = Some(server);
        }

        fn kill_server(&mut self) {
            if let Some(mut server) = self.server.take() {
                server.kill();
            }
        }

        fn server_pid(&self) -> u32 {
            self.server.as_ref().unwrap().pid
        }

        /// A DWKP connection as the runtime: this process, or the runtime's
        /// own user through the relay.
        fn wire(&self) -> Wire {
            match &self.ids {
                None => Wire::Own(Client::connect(&self.socket)),
                Some(ids) => Wire::Relayed(Relay::start(
                    &ids.runtime_user,
                    &self.stage.join("agent_runtime_client.py"),
                    &self.socket,
                )),
            }
        }

        /// Every capability an agent's run asks for: workloads, workspace
        /// reads, and exactly the evidence's HTTPS destinations.
        fn grants(&self) -> Vec<String> {
            vec![
                "process.exec:*".to_owned(),
                "fs.read:/workspace".to_owned(),
                format!("network.https:{ORIGIN}:{}", self.good.port),
                format!("network.https:{ALT}:{}", self.wrong.port),
                format!("network.https:{ORIGIN}:{}", self.rogue.port),
                format!("network.https:{BLOCKED}:{}", self.good.port),
                format!("network.https:{SINK}:{}", self.sink.port),
            ]
        }

        fn peer(&self, n: u64) -> Peer {
            let grants = self.grants();
            let refs: Vec<&str> = grants.iter().map(String::as_str).collect();
            Peer::admit(self.wire(), n, &refs)
        }

        /// The run's live environment's container, once its first launch
        /// has prepared it (bounded by the environment deadline).
        fn container(&self, run: &RunId) -> String {
            let deadline = Instant::now() + Duration::from_secs(150);
            loop {
                let found: Option<String> = raw(&self.dir.state())
                    .query_row(
                        "SELECT container FROM environment WHERE run_id = ?1 \
                         AND state = 'READY' AND container IS NOT NULL",
                        [run.as_str()],
                        |row| row.get(0),
                    )
                    .ok();
                if let Some(container) = found {
                    self.reaper.note(&container);
                    return container;
                }
                assert!(
                    Instant::now() < deadline,
                    "the run never had an environment"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        fn environment_of(&self, container: &str) -> String {
            raw(&self.dir.state())
                .query_row(
                    "SELECT environment_id FROM environment WHERE container = ?1",
                    [container],
                    |row| row.get(0),
                )
                .unwrap()
        }

        fn rows(&self, sql: &str) -> i64 {
            raw(&self.dir.state())
                .query_row(sql, [], |row| row.get(0))
                .unwrap()
        }

        /// A workload of the agent's tool, run by the image's Python: its
        /// one JSON line.
        fn tool(&self, peer: &mut Peer, args: &[&str]) -> json::Object {
            let mut words = vec!["-I", "-B", TOOL];
            words.extend_from_slice(args);
            let body = peer.exec(&format!("t-{}", next()), &self.pins.python, &words, WALL);
            let out = sandboxed(&body);
            assert_eq!(out.residue, ResidueVerdict::Pass, "{out:?}");
            object(&String::from_utf8(out.stdout.content.to_bytes()).unwrap())
        }

        /// A workload of the fixture: what it printed.
        fn fixture(&self, peer: &mut Peer, args: &[&str]) -> String {
            let body = peer.exec(&format!("f-{}", next()), FIXTURE, args, WALL);
            let out = sandboxed(&body);
            assert_eq!(out.residue, ResidueVerdict::Pass, "{out:?}");
            String::from_utf8(out.stdout.content.to_bytes())
                .unwrap()
                .trim_end()
                .to_owned()
        }

        /// The agent-shaped workload's arguments.
        fn agent_args(&self, seconds: u32) -> Vec<String> {
            vec![
                "workload-agent-net".to_owned(),
                self.pins.python.clone(),
                TOOL.to_owned(),
                ANCHOR.to_owned(),
                seconds.to_string(),
                format!("https://{ORIGIN}:{}/ok", self.good.port),
                format!("https://{SECOND}:{}/ok", self.good.port),
            ]
        }

        /// The processes the agent leaves running, as `workload-procs` names
        /// them.
        fn agent_children() -> [&'static str; 3] {
            [
                "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-agent-worker 1",
                "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-agent-worker 2",
                "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-sleep 600",
            ]
        }

        /// End the run and have its environment destroyed the way an ended
        /// run's is before M5d.6: by the authority reclaiming it before its
        /// next preparation (ADR-0052 §2a). The destruction's audit record.
        fn reclaim(&self, peer: &mut Peer, container: &str, next_session: u64) -> json::Object {
            let environment = self.environment_of(container);
            peer.release();
            let mut other = self.peer(next_session);
            let body = other.exec(
                &format!("r-{}", next()),
                FIXTURE,
                &["workload-identity"],
                WALL,
            );
            self.reaper.note(&self.container(&other.run));
            assert_eq!(sandboxed(&body).residue, ResidueVerdict::Pass);
            assert!(
                !self.runtime.exists(container),
                "the ended run's environment was reclaimed"
            );
            audit_records(&self.dir.state(), "environment.destroyed")
                .into_iter()
                .find(|r| {
                    super::state_support::text(r, "environment_id") == Some(environment.as_str())
                })
                .expect("the destruction was audited")
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            self.kill_server();
            self.kill_broker();
            // A separated broker's socket directory is its own user's: that
            // user removes it (C04, the evidence leaves nothing behind).
            if let Some(ids) = &self.ids {
                remove_as(&ids.broker_user, self.broker_socket.parent().unwrap());
            }
        }
    }

    /// Remove `dir` -- one of the evidence's own `/tmp/dw[ar]-*` socket
    /// directories, and nothing else -- as `user`, who made it.
    fn remove_as(user: &str, dir: &Path) {
        let name = dir.to_str().unwrap();
        assert!(
            name.starts_with("/tmp/dwa-") || name.starts_with("/tmp/dwr-"),
            "{name} is not the evidence's"
        );
        if dir.exists() {
            let _ = super::state_support::status(
                Command::new("sudo").args(["-n", "-u", user, "rm", "-rf", "--", name]),
            );
        }
    }

    /// The repository's root.
    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    // ---- a runtime's run ---------------------------------------------------

    /// A runtime: one DWKP connection, its session's lease, and one run.
    ///
    /// The lease is the runtime's to keep (ADR-0011): every epoch-carrying
    /// request is fenced -- `STALE_EPOCH` unless the lease is live -- and
    /// only a `Heartbeat` moves its expiry; a tool call renews nothing. So
    /// this runtime heartbeats at its own epoch before every epoch-carrying
    /// request and accepts nothing but the `Ack` to that heartbeat. It never
    /// acquires again: that would rotate the epoch and reap the run.
    ///
    /// The server answers a connection's requests one at a time, in order
    /// (`server/connection.rs` reads the next frame only once it answered
    /// the last), so a heartbeat queued behind an outstanding launch would
    /// renew nothing until that launch was answered. Nothing is therefore
    /// sent while a request is outstanding, and every answer must name the
    /// request it answers (`causation_id`).
    struct Peer {
        wire: Wire,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
        /// When the lease was last renewed -- acquired or heartbeated -- as
        /// the moment that request was sent: never later than the server's.
        renewed: Instant,
        /// The id of the request awaiting its answer, if one is.
        outstanding: Option<String>,
    }

    /// A `Heartbeat` for `session` at `epoch`, with an id of its own.
    fn heartbeat(session: &SessionId, epoch: Epoch) -> DwkpMessage {
        decode(&format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-10-24T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
            id = id("msg", 950_000 + next()),
            session = session.as_str(),
            epoch = epoch.get(),
        ))
    }

    impl Peer {
        fn admit(mut wire: Wire, n: u64, capabilities: &[&str]) -> Self {
            let session = session(n);
            wire.handshake();
            let asked = Instant::now();
            let granted = wire.call(&acquire_msg(&session));
            let DwkpBody::LeaseGrant(lease) = granted.body else {
                panic!("a lease: {granted:?}")
            };
            let epoch = lease.epoch;
            let message = next();
            let admitted = wire.call(&admit_msg(
                &session,
                epoch,
                &format!("admit-{n}-{message}"),
                "agent",
                &[],
                capabilities,
                message,
            ));
            let DwkpBody::RunGrant(grant) = admitted.body else {
                panic!("a run: {admitted:?}")
            };
            Self {
                wire,
                session,
                epoch,
                run: grant.run_id,
                renewed: asked,
                outstanding: None,
            }
        }

        /// Send one request; `answer` reads its answer.
        fn send(&mut self, message: &DwkpMessage) {
            assert!(
                self.outstanding.is_none(),
                "a request is already outstanding: {:?}",
                self.outstanding
            );
            self.outstanding = Some(message.header.id.as_str().to_owned());
            self.wire.send(message);
        }

        /// The outstanding request's answer, within `wait`: the connection's
        /// next message, which must name that request as its cause.
        fn answer(&mut self, wait: Duration) -> DwkpBody {
            let asked = self.outstanding.take().expect("no request is outstanding");
            let answer = self.wire.recv(wait).message();
            assert_eq!(
                answer.header.causation_id.as_ref().map(AnyId::as_str),
                Some(asked.as_str()),
                "an answer to another request: {answer:?}"
            );
            answer.body
        }

        /// Renew the lease before an epoch-carrying request: a `Heartbeat`
        /// at this lease's epoch, answered `Ack`. A lease that lapsed is
        /// refused `STALE_EPOCH`, which fails the test saying how long it
        /// went unrenewed -- it is never acquired again to get past the fence.
        fn renew(&mut self) {
            let unrenewed = self.renewed.elapsed();
            let asked = Instant::now();
            let message = heartbeat(&self.session, self.epoch);
            self.send(&message);
            match self.answer(PROMPT) {
                DwkpBody::Ack(_) => self.renewed = asked,
                other => panic!(
                    "the lease was not renewed after {unrenewed:?} unrenewed (the server's TTL \
                     is {:?}): {other:?}",
                    Duration::from_millis(DEFAULT_LEASE_TTL_MS)
                ),
            }
        }

        /// End the run (`ReleaseRun`, fenced like any request): `Ack`.
        fn release(&mut self) {
            self.renew();
            let message = release_run_msg(&self.session, &self.run, self.epoch);
            self.send(&message);
            let released = self.answer(PROMPT);
            assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
        }

        fn tool_message(&self, schema: &str, key: Option<&str>, payload: &str) -> DwkpMessage {
            decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":5,"ts":"2026-10-23T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
                id = id("msg", 900_000 + next()),
                session = self.session.as_str(),
                run = self.run.as_str(),
                epoch = self.epoch.get(),
                key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#)),
            ))
        }

        fn send_exec(&mut self, key: &str, executable: &str, args: &[&str], timeout: u32) {
            self.renew();
            let message = self.tool_message(
                "direwolf.tool.invoke",
                Some(key),
                &format!(
                    r#"{{"process_exec":{}}}"#,
                    call(executable, args, Some(timeout))
                ),
            );
            self.send(&message);
        }

        fn exec(&mut self, key: &str, executable: &str, args: &[&str], timeout: u32) -> DwkpBody {
            self.send_exec(key, executable, args, timeout);
            self.answer(Duration::from_secs(u64::from(timeout) + 240))
        }

        /// A brokered `fs.read` of a workspace path: the bytes.
        fn read(&mut self, path: &str) -> Vec<u8> {
            self.renew();
            let key = format!("read-{}", next());
            let message = self.tool_message(
                "direwolf.tool.invoke",
                Some(&key),
                &format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":65536}}}}"#),
            );
            self.send(&message);
            match self.answer(PROMPT) {
                DwkpBody::ToolResultV5(result) => {
                    result.output.fs_read.as_ref().unwrap().content.to_bytes()
                }
                other => panic!("not read: {other:?}"),
            }
        }
    }

    fn call(executable: &str, args: &[&str], timeout: Option<u32>) -> String {
        let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
        format!(
            r#"{{"executable":{},"args":[{}]{}}}"#,
            quote(executable),
            args.join(","),
            timeout.map_or_else(String::new, |t| format!(r#","timeout_seconds":{t}"#)),
        )
    }

    fn sandboxed(body: &DwkpBody) -> &SandboxedExecResult {
        match body {
            DwkpBody::ToolResultV5(result) => {
                result.output.process_exec_sandboxed.as_ref().unwrap()
            }
            other => panic!("not a sandboxed result: {other:?}"),
        }
    }

    fn refusal(body: &DwkpBody) -> &'static str {
        match body {
            DwkpBody::ToolRefusedV5(r) => r.reason.as_str(),
            other => panic!("not refused: {other:?}"),
        }
    }

    // ---- one identity: the agent, its network, its ending --------------------

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-agent-evidence"]
    fn an_agent_runs_through_the_production_route_and_reaches_only_its_origin() {
        let lab = Lab::new("m5d5a", None, &Workspace::Waiver);
        let ok_sha = sha256_hex(b"ok");
        let mut a = lab.peer(1);

        // A01, A02, A03: the agent, through DWKP, in the run's environment.
        let args = lab.agent_args(8);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        a.send_exec("agent-1", FIXTURE, &words, 120);
        let container = lab.container(&a.run);
        let procs = lab.runtime.awaited(&container, &Lab::agent_children());
        assert!(procs.len() >= 4, "{procs:?}");
        assert!(
            procs.iter().all(|p| p.starts_with("uid=10001 ")),
            "every process of the agent is the environment's user: {procs:?}"
        );
        evidence(
            SUITE,
            "a02-agent-processes-within-the-environment",
            &format!("{}-processes-all-uid-10001", procs.len()),
            OCI,
            "environment-pid-namespace-and-cgroup",
        );
        // The same, as the runtime's host sees them: every process of the
        // environment is 10001:10001, every process of its relay 10002.
        let seen = lab.runtime.host_ids(&container);
        assert!(seen.len() >= 5, "{seen:?}");
        assert!(seen.iter().all(|ids| *ids == (10001, 10001)), "{seen:?}");
        evidence(
            SUITE,
            "a02-agent-identity-measured-from-the-host",
            &format!("{}-processes-10001:10001", seen.len()),
            OCI,
            "oci-user-measured-from-the-host",
        );
        let environment = lab.environment_of(&container);
        let relays = lab.runtime.role(&environment, "relay");
        assert_eq!(relays.len(), 1, "{relays:?}");
        let relay = lab.runtime.host_ids(&relays[0]);
        assert!(
            !relay.is_empty() && relay.iter().all(|(uid, _)| *uid == 10002),
            "{relay:?}"
        );
        evidence(
            SUITE,
            "a03-relay-identity-measured-from-the-host",
            "10002",
            OCI,
            "oci-user-measured-from-the-host",
        );
        let body = a.answer(Duration::from_secs(180));
        let out = sandboxed(&body);
        let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert_eq!(out.ending, SandboxEnding::Exited, "{text}");
        assert_eq!(out.exit_code.map(|c| c.get()), Some(0), "{text}");
        assert_eq!(out.assurance, ExecutionAssurance::ContainerIsolation);
        assert_eq!(out.executable.image.as_str(), lab.pins.image);
        assert_eq!(out.executable.sha256.as_str(), lab.pins.fixture);
        let network: String = raw(&lab.dir.state())
            .query_row(
                "SELECT network FROM environment WHERE environment_id = ?1",
                [out.environment_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(network, "PROXY_ONLY");
        let intent = audit_records(&lab.dir.state(), "workload.intent_recorded");
        assert_eq!(
            super::state_support::text(intent.last().unwrap(), "subject"),
            Some(format!("uid:{}", own_uid()).as_str())
        );
        evidence(
            SUITE,
            "a01-production-route-dwkp-to-measured-proxy-only-sandbox",
            "container-isolation-proxy-only",
            E2E,
            "authority-gates-and-environment-judgement",
        );
        assert_eq!(lab.broker().count("process_start"), 0, "a host launch");
        evidence(
            SUITE,
            "a01-no-host-fallback",
            "no-host-launch",
            E2E,
            "authority-environment-decision",
        );
        assert_eq!(field(&text, "made"), "true", "{text}");
        assert_eq!(field(&text, "workers"), "2", "{text}");
        assert_eq!(field(&text, "helper"), "true", "{text}");
        assert!(field(&text, "files").parse::<u32>().unwrap() >= 3, "{text}");
        assert_eq!(field(&text, "read"), "true", "{text}");
        evidence(
            SUITE,
            "a02-agent-plan-workers-and-helper",
            "plan-2-workers-helper",
            E2E,
            "-",
        );
        let granted = object(field(&text, "granted"));
        assert_eq!(int(&granted, "status"), 200, "{text}");
        assert_eq!(text_of(&granted, "sha256"), ok_sha, "{text}");
        assert!(flag(&granted, "verified"), "{text}");
        assert_eq!(
            text_of(&granted, "proxy"),
            "http://169.254.7.1:8080",
            "the environment's own proxy variable"
        );
        assert_eq!(
            lab.good.to("/ok").len(),
            1,
            "the origin served the agent once"
        );
        evidence(
            SUITE,
            "a03-https-granted-origin-stock-client",
            "200-verified-body-ok",
            E2E,
            "relay-and-connect-proxy-grant",
        );
        let denied = object(field(&text, "denied"));
        assert_eq!(text_of(&denied, "refused_by"), "proxy", "{text}");
        assert!(text_of(&denied, "error").contains("403"), "{text}");
        assert_eq!(
            lab.good.to("/ok").len(),
            1,
            "the denied name reached the origin"
        );
        evidence(
            SUITE,
            "a04-agent-ungranted-origin-refused",
            &text_of(&denied, "error"),
            E2E,
            "connect-proxy:TARGET_NOT_GRANTED",
        );
        for (case, line) in [
            ("a06-agent-direct-tcp-no-route", field(&text, "tcp")),
            ("a06-agent-direct-udp-no-route", field(&text, "udp")),
        ] {
            assert_eq!(line, "errno=101", "{case}: {text}");
            evidence(
                SUITE,
                case,
                "ENETUNREACH",
                E2E,
                "network-namespace-no-route",
            );
        }

        // A11: what the agent left, ended by the environment's init.
        assert_eq!(out.residue, ResidueVerdict::Pass);
        assert!(out.ended_processes.get() >= 3, "{out:?}");
        assert!(!out.environment_destroyed);
        assert!(
            lab.runtime.procs(&container).is_empty(),
            "nothing survived the invocation"
        );
        evidence(
            SUITE,
            "a11-descendants-reaped",
            &format!("residue-pass-{}-ended", out.ended_processes.get()),
            E2E,
            "environment-init-reap",
        );
        evidence(
            SUITE,
            "a11-census-empty-after-the-invocation",
            "init-alone",
            OCI,
            "environment-init-reap",
        );

        // A03 again, through the tool's own CONNECT: the decision the proxy
        // sent and a verified TLS session to the granted origin.
        let tls = lab.tool(
            &mut a,
            &[
                "tls",
                ORIGIN,
                &lab.good.port.to_string(),
                ORIGIN,
                ANCHOR,
                "/ok",
            ],
        );
        assert!(
            text_of(&tls, "connect").starts_with("HTTP/1.1 200"),
            "{tls:?}"
        );
        assert_eq!(int(&tls, "status"), 200, "{tls:?}");
        assert_eq!(text_of(&tls, "sha256"), ok_sha);
        evidence(
            SUITE,
            "a03-https-granted-origin-tls-verified",
            &text_of(&tls, "connect"),
            E2E,
            "relay-and-connect-proxy-grant",
        );

        // A04: what is not granted is refused before anything is dialled.
        let served = lab.good.to("/ok").len();
        for (case, host, port, decision, enforcement) in [
            (
                "a04-origin-host-not-granted",
                SECOND,
                lab.good.port,
                "TARGET_NOT_GRANTED",
                "connect-proxy:grant",
            ),
            (
                "a04-origin-port-not-granted",
                ORIGIN,
                lab.wrong.port,
                "TARGET_NOT_GRANTED",
                "connect-proxy:grant",
            ),
            (
                "a04-granted-name-blocked-by-the-address-guard",
                BLOCKED,
                lab.good.port,
                "ADDRESS_BLOCKED",
                "connect-proxy:address-guard",
            ),
        ] {
            let report = lab.tool(
                &mut a,
                &["tls", host, &port.to_string(), host, ANCHOR, "/ok"],
            );
            assert_eq!(
                text_of(&report, "refused_by"),
                "proxy",
                "{case}: {report:?}"
            );
            assert_eq!(text_of(&report, "decision"), decision, "{case}: {report:?}");
            assert!(
                text_of(&report, "connect").starts_with("HTTP/1.1 403"),
                "{case}"
            );
            evidence(SUITE, case, decision, E2E, enforcement);
        }
        assert_eq!(
            lab.good.to("/ok").len(),
            served,
            "a refused tunnel reached the origin"
        );
        assert!(
            lab.wrong.requests().is_empty(),
            "the ungranted port was dialled"
        );

        // A05: a CONNECT in any other form than the one strict one.
        let p = lab.good.port;
        for (case, request, decisions) in [
            (
                "a05-connect-absolute-form-refused",
                format!("CONNECT https://{ORIGIN}:{p}/ HTTP/1.1\r\n\r\n"),
                &["TARGET_NOT_CANONICAL", "MALFORMED"][..],
            ),
            (
                "a05-connect-address-literal-refused",
                format!("CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n"),
                &["TARGET_NOT_CANONICAL"][..],
            ),
            (
                "a05-connect-host-not-canonical-refused",
                format!("CONNECT ORIGIN.TEST:{p} HTTP/1.1\r\n\r\n"),
                &["TARGET_NOT_CANONICAL"][..],
            ),
            (
                "a05-connect-another-method-refused",
                format!("GET https://{ORIGIN}:{p}/ok HTTP/1.1\r\nHost: {ORIGIN}\r\n\r\n"),
                &["NOT_CONNECT"][..],
            ),
            (
                "a05-connect-smuggled-body-refused",
                format!(
                    "CONNECT {ORIGIN}:{p} HTTP/1.1\r\nHost: {ORIGIN}:{p}\r\n\
                     Content-Length: 5\r\n\r\nhello"
                ),
                &["MALFORMED"][..],
            ),
            (
                "a05-connect-host-header-disagrees-refused",
                format!("CONNECT {ORIGIN}:{p} HTTP/1.1\r\nHost: {SECOND}:{p}\r\n\r\n"),
                &["MALFORMED"][..],
            ),
        ] {
            let report = lab.tool(&mut a, &["raw", &hex(request.as_bytes())]);
            let decision = text_of(&report, "decision");
            assert_eq!(
                text_of(&report, "refused_by"),
                "proxy",
                "{case}: {report:?}"
            );
            assert!(decisions.contains(&decision.as_str()), "{case}: {report:?}");
            assert!(
                text_of(&report, "connect").starts_with("HTTP/1.1 4"),
                "{case}"
            );
            evidence(SUITE, case, &decision, E2E, "connect-proxy:parser");
        }
        // The server name must be the CONNECT host before anything is dialled.
        for (case, sni) in [
            ("a05-tls-sni-mismatch-closed", ALT),
            ("a05-tls-sni-missing-closed", "-"),
        ] {
            let report = lab.tool(&mut a, &["tls", ORIGIN, &p.to_string(), sni, ANCHOR, "/ok"]);
            assert!(
                text_of(&report, "connect").starts_with("HTTP/1.1 200"),
                "{report:?}"
            );
            assert_eq!(
                text_of(&report, "refused_by"),
                "tunnel-closed",
                "{case}: {report:?}"
            );
            evidence(
                SUITE,
                case,
                &text_of(&report, "error"),
                E2E,
                "connect-proxy:server-name",
            );
        }
        assert_eq!(
            lab.good.to("/ok").len(),
            served,
            "a mismatched name reached the origin"
        );
        // A certificate the agent must refuse: the proxy carries a granted
        // name's tunnel, and the agent's own verification ends it -- the
        // workload's guarantee, not DireWolf's.
        for (case, host, port, origin) in [
            (
                "a05-tls-certificate-for-another-name-refused-by-the-client",
                ALT,
                lab.wrong.port,
                &lab.wrong,
            ),
            (
                "a05-tls-untrusted-issuer-refused-by-the-client",
                ORIGIN,
                lab.rogue.port,
                &lab.rogue,
            ),
        ] {
            let report = lab.tool(
                &mut a,
                &["tls", host, &port.to_string(), host, ANCHOR, "/ok"],
            );
            assert!(
                text_of(&report, "connect").starts_with("HTTP/1.1 200"),
                "{report:?}"
            );
            assert_eq!(
                text_of(&report, "refused_by"),
                "tls-client",
                "{case}: {report:?}"
            );
            assert_eq!(text_of(&report, "error"), "certificate-verify-failed");
            assert!(origin.requests().is_empty(), "{case}: a request was sent");
            evidence(
                SUITE,
                case,
                &text_of(&report, "verify"),
                E2E,
                "workload-tls-verification",
            );
        }

        // A06: nothing that ignores the proxy has a path.
        let port = lab.good.port.to_string();
        for (case, args, expected, enforcement) in [
            (
                "a06-direct-tcp-public-no-route",
                vec!["egress-direct", "tcp", "1.1.1.1", "443"],
                "ENETUNREACH",
                "network-namespace-no-route",
            ),
            (
                "a06-direct-udp-public-no-route",
                vec!["egress-direct", "udp", "8.8.8.8", "53"],
                "ENETUNREACH",
                "network-namespace-no-route",
            ),
            (
                "a06-direct-tcp-bridge-gateway-no-route",
                vec!["egress-direct", "tcp", "172.17.0.1", &port],
                "ENETUNREACH",
                "network-namespace-no-route",
            ),
            (
                "a06-host-loopback-origin-is-not-the-environments",
                vec!["egress-direct", "tcp", "127.0.0.1", &port],
                "ECONNREFUSED",
                "network-namespace-own-loopback",
            ),
        ] {
            let line = lab.fixture(&mut a, &args);
            assert_eq!(errno_name(&line), expected, "{case}: {line}");
            evidence(SUITE, case, expected, E2E, enforcement);
        }
        let dns = lab.fixture(&mut a, &["egress-dns", "8.8.8.8"]);
        assert!(dns.contains("udp-send errno=101"), "{dns}");
        assert!(dns.contains("tcp errno=101"), "{dns}");
        evidence(
            SUITE,
            "a06-direct-dns-no-route",
            "ENETUNREACH",
            E2E,
            "network-namespace-no-route",
        );
        let resolved = lab.fixture(&mut a, &["egress-resolve", ORIGIN]);
        assert!(resolved.starts_with("unresolved"), "{resolved}");
        evidence(
            SUITE,
            "a06-no-resolver-answers",
            &resolved,
            E2E,
            "network-namespace-no-resolver",
        );
        let raw_sockets = lab.fixture(&mut a, &["egress-raw"]);
        for kind in ["raw4", "raw6", "packet"] {
            assert!(
                !raw_sockets.contains(&format!("{kind}: created")),
                "{kind}: {raw_sockets}"
            );
        }
        evidence(
            SUITE,
            "a06-raw-and-packet-sockets-refused",
            &raw_sockets,
            E2E,
            "capabilities-and-seccomp",
        );
        assert_eq!(
            lab.good.to("/ok").len(),
            served,
            "a direct attempt reached the origin"
        );

        // A07: the workload rewriting its own proxy variables finds no other
        // path; what the environment set is exactly the relay.
        let env = lab.fixture(&mut a, &["egress-env"]);
        let mut names: Vec<&str> = env.lines().filter(|l| !l.is_empty()).collect();
        names.sort_unstable();
        assert_eq!(names.len(), 8, "{env}");
        for line in &names {
            let (name, value) = line.split_once('=').unwrap();
            if name.eq_ignore_ascii_case("no_proxy") {
                continue;
            }
            assert_eq!(value, "http://169.254.7.1:8080", "{line}");
        }
        evidence(
            SUITE,
            "a07-proxy-variables-name-only-the-relay",
            "8-variables",
            OCI,
            "environment-specification",
        );
        let url = format!("https://{ORIGIN}:{}/ok", lab.good.port);
        for (case, proxy, refused, enforcement) in [
            (
                "a07-proxy-variable-redirected-to-another-host",
                "http://1.1.1.1:3128",
                "ENETUNREACH",
                "network-namespace-no-route",
            ),
            (
                "a07-proxy-variable-redirected-to-another-port",
                "http://169.254.7.1:9",
                "ECONNREFUSED",
                "network-namespace-only-the-relay-listens",
            ),
            (
                "a07-proxy-variables-removed",
                "none",
                "name-not-resolved",
                "network-namespace-no-resolver",
            ),
        ] {
            let report = lab.tool(&mut a, &["fetch-via", proxy, &url, ANCHOR]);
            assert_eq!(
                text_of(&report, "refused_by"),
                "network",
                "{case}: {report:?}"
            );
            assert_eq!(text_of(&report, "error"), refused, "{case}: {report:?}");
            evidence(SUITE, case, refused, E2E, enforcement);
        }
        assert_eq!(
            lab.good.to("/ok").len(),
            served,
            "a rewritten proxy reached the origin"
        );

        // A10: nothing outside the workspace, and none of the daemons' state.
        let host_paths = [
            lab.dir.state().display().to_string(),
            lab.socket.display().to_string(),
            lab.broker_socket.display().to_string(),
            lab.config.display().to_string(),
            lab.policy.display().to_string(),
            lab.pins.socket.clone(),
        ];
        let mut args = vec!["workload-escape"];
        args.extend(host_paths.iter().map(String::as_str));
        let escape = lab.fixture(&mut a, &args);
        for (key, expected) in [
            ("root", "errno=30"),
            ("usr", "errno=30"),
            ("etc", "errno=30"),
            ("workspace", "written"),
        ] {
            assert_eq!(field(&escape, key), expected, "{key}: {escape}");
        }
        assert!(field(&escape, "dotdot").starts_with("errno="), "{escape}");
        evidence(
            SUITE,
            "a10-writes-outside-the-workspace-refused",
            "EROFS",
            E2E,
            "read-only-root-and-mount-namespace",
        );
        assert_eq!(field(&escape, "runtime_sockets"), "0", "{escape}");
        for path in &host_paths {
            assert!(
                escape.contains(&format!("host_path={path} exists=false")),
                "{path}: {escape}"
            );
        }
        evidence(
            SUITE,
            "a10-no-runtime-socket-or-daemon-state-in-the-environment",
            "absent",
            E2E,
            "mount-namespace",
        );

        // A09 -- the authority and the broker sharing what the agent wrote --
        // is the three-identity test's: the agent's files are the group
        // 10001's, mode 0660 (OD-12's umask), which only the provisioned
        // workspace's members read; the evidence waiver proves no group.

        // What the audit says: the grant at the intent, and the egress by
        // disposition at the destruction -- counts, never one event per
        // refused attempt.
        let intents = audit_records(&lab.dir.state(), "environment.intent_recorded");
        let targets = texts(intents.last().unwrap(), "egress_targets");
        assert!(
            targets.contains(&format!("{ORIGIN}:{}", lab.good.port)),
            "{targets:?}"
        );
        assert_eq!(targets.len(), 5, "{targets:?}");
        evidence(
            SUITE,
            "audit-environment-intent-names-the-grant",
            &targets.join(","),
            E2E,
            "authority-audit",
        );
        let destroyed = lab.reclaim(&mut a, &container, 2);
        let dispositions = texts(&destroyed, "egress_dispositions");
        for (disposition, at_least) in [
            ("TARGET_NOT_GRANTED", 3),
            ("ADDRESS_BLOCKED", 1),
            ("TARGET_NOT_CANONICAL", 2),
            ("NOT_CONNECT", 1),
            ("MALFORMED", 2),
            ("SNI_MISMATCH", 1),
            ("SNI_MISSING", 1),
        ] {
            let count = dispositions
                .iter()
                .find_map(|d| d.strip_prefix(&format!("{disposition}=")))
                .map_or(0, |n| n.parse::<u64>().unwrap());
            assert!(count >= at_least, "{disposition}: {dispositions:?}");
        }
        evidence(
            SUITE,
            "audit-egress-counted-by-disposition-not-per-attempt",
            &dispositions.join(","),
            E2E,
            "authority-audit-at-destruction",
        );
    }

    fn text_of(object: &json::Object, key: &str) -> String {
        text(object, key)
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-agent-evidence"]
    fn budgets_and_the_wall_clock_bound_an_agent() {
        let lab = Lab::new("m5d5b", None, &Workspace::Waiver);

        // A08: at most MAX_TUNNELS tunnels at once.
        let mut a = lab.peer(1);
        let report = lab.tool(
            &mut a,
            &["tunnels", ORIGIN, &lab.good.port.to_string(), "6"],
        );
        let container = lab.container(&a.run);
        assert_eq!(int(&report, "established"), 4, "{report:?}");
        assert_eq!(int(&report, "refused"), 2, "{report:?}");
        let Some(Value::Object(decisions)) = report.get("decisions") else {
            panic!("{report:?}")
        };
        assert_eq!(int(decisions, "TUNNEL_LIMIT"), 2, "{report:?}");
        evidence(
            SUITE,
            "a08-tunnel-limit",
            "4-of-6-then-TUNNEL_LIMIT",
            E2E,
            "connect-proxy:tunnel-limit",
        );
        // A08: the upload budget, environment-wide, at the socket.
        let before = lab.sink.accepted();
        let line = lab.fixture(
            &mut a,
            &[
                "egress-connect",
                SINK,
                &lab.sink.port.to_string(),
                SINK,
                "200000",
            ],
        );
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(lab.sink.accepted(), before + 1, "{line}");
        assert!(lab.sink.received() <= MAX_UPLOAD, "{}", lab.sink.received());
        let next = lab.fixture(
            &mut a,
            &[
                "egress-connect",
                SINK,
                &lab.sink.port.to_string(),
                SINK,
                "10",
            ],
        );
        assert_eq!(lab.sink.accepted(), before + 1, "spent stays spent: {next}");
        evidence(
            SUITE,
            "a08-upload-budget",
            &format!("{}-of-{MAX_UPLOAD}", lab.sink.received()),
            E2E,
            "connect-proxy:upload-budget",
        );
        let _ = container;

        // A08: the download budget, in a run of its own.
        let mut b = lab.peer(2);
        let report = lab.tool(
            &mut b,
            &[
                "download",
                ORIGIN,
                &lab.good.port.to_string(),
                &(4 * MAX_DOWNLOAD).to_string(),
                ANCHOR,
            ],
        );
        let received = usize::try_from(int(&report, "bytes")).unwrap_or(usize::MAX);
        assert!(received < MAX_DOWNLOAD, "{report:?}");
        assert_eq!(lab.good.to("/big").len(), 1, "{report:?}");
        evidence(
            SUITE,
            "a08-download-budget",
            &format!("{received}-of-{}", 4 * MAX_DOWNLOAD),
            E2E,
            "connect-proxy:download-budget",
        );

        // A08, A12: the wall clock ends a long agent and its descendants;
        // the environment keeps running, clean.
        let container = lab.container(&b.run);
        let args = lab.agent_args(600);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        let since = Instant::now();
        let body = b.exec("long-agent", FIXTURE, &words, 10);
        let out = sandboxed(&body);
        assert_eq!(out.ending, SandboxEnding::TimedOut, "{out:?}");
        // Its own ten seconds, then `reap` and the collection: never a
        // bound several times its own.
        let elapsed = since.elapsed();
        assert!(elapsed >= Duration::from_secs(10), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(35), "{elapsed:?}");
        assert_eq!(out.residue, ResidueVerdict::Pass);
        assert!(out.ended_processes.get() >= 3, "{out:?}");
        assert!(!out.environment_destroyed);
        assert!(lab.runtime.procs(&container).is_empty());
        evidence(
            SUITE,
            "a08-wall-clock-ends-the-agent",
            "TIMED_OUT",
            E2E,
            "broker-wall-clock",
        );
        evidence(
            SUITE,
            "a12-timeout-reaped-environment-kept-clean",
            "residue-pass",
            E2E,
            "environment-init-reap",
        );

        // A08: the run's workload budget, charged at the intent: six
        // ten-minute bounds spend the hour, the seventh is refused before
        // anything is recorded.
        let mut c = lab.peer(3);
        for n in 0..6 {
            let body = c.exec(&format!("budget-{n}"), FIXTURE, &["workload-identity"], 600);
            assert_eq!(sandboxed(&body).ending, SandboxEnding::Exited);
        }
        let rows = lab.rows("SELECT count(*) FROM workload");
        let body = c.exec("budget-6", FIXTURE, &["workload-identity"], 600);
        assert_eq!(refusal(&body), "BUDGET_EXHAUSTED");
        assert_eq!(
            lab.rows("SELECT count(*) FROM workload"),
            rows,
            "nothing recorded"
        );
        evidence(
            SUITE,
            "a08-workload-budget-refused",
            "BUDGET_EXHAUSTED",
            E2E,
            "authority-run-budget",
        );
        lab.reaper.note(&lab.container(&c.run));
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-agent-evidence"]
    fn an_agent_that_outlives_its_daemons_is_destroyed_and_never_run_again() {
        let mut lab = Lab::new("m5d5c", None, &Workspace::Waiver);
        let mut a = lab.peer(1);
        let args = lab.agent_args(300);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();

        // A12: the broker dies while the agent runs.
        a.send_exec("lost-broker", FIXTURE, &words, 120);
        let container = lab.container(&a.run);
        lab.runtime.awaited(&container, &Lab::agent_children());
        lab.kill_broker();
        let body = a.answer(Duration::from_secs(120));
        let DwkpBody::ToolFailedV5(failure) = &body else {
            panic!("not failed: {body:?}")
        };
        assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN");
        assert_eq!(failure.environment_destroyed, Some(true));
        assert!(
            lab.runtime.exists(&container),
            "the agent outlived its broker"
        );
        lab.start_broker();
        lab.kill_server();
        lab.start_server();
        assert!(!lab.runtime.exists(&container), "the restart destroyed it");
        let state: String = raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'lost-broker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        evidence(
            SUITE,
            "a12-broker-lost-outcome-unknown-environment-destroyed",
            "OUTCOME_UNKNOWN",
            E2E,
            "authority-ledger-and-reconciliation",
        );

        // A12: the authority dies while the agent runs (W9, released binary).
        let mut b = lab.peer(1);
        std::fs::remove_dir_all(lab.workspace.join("agent")).unwrap();
        b.send_exec("lost-authority", FIXTURE, &words, 120);
        let container = lab.container(&b.run);
        lab.runtime.awaited(&container, &Lab::agent_children());
        lab.kill_server();
        assert!(
            lab.runtime.exists(&container),
            "the runtime keeps an exec'd agent"
        );
        lab.start_server();
        let state: String = raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'lost-authority'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        assert!(
            !lab.runtime.exists(&container),
            "the restart destroyed the environment"
        );
        evidence(
            SUITE,
            "a12-authority-crash-unknown-environment-destroyed",
            "UNKNOWN",
            E2E,
            "authority-ledger-and-reconciliation",
        );

        // Never again: the same keys, from a new connection, run nothing.
        std::fs::remove_dir_all(lab.workspace.join("agent")).unwrap();
        let workloads = lab.rows("SELECT count(*) FROM workload");
        let environments = lab.rows("SELECT count(*) FROM environment");
        let mut c = lab.peer(1);
        for key in ["lost-broker", "lost-authority"] {
            let body = c.exec(key, FIXTURE, &words, 120);
            assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED", "{key}");
        }
        assert_eq!(lab.rows("SELECT count(*) FROM workload"), workloads);
        assert_eq!(lab.rows("SELECT count(*) FROM environment"), environments);
        assert!(!lab.workspace.join("agent").exists(), "an agent ran again");
        evidence(
            SUITE,
            "a12-uncertain-agent-never-replayed",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-shared-idempotency-namespace",
        );
    }

    // ---- three identities --------------------------------------------------

    #[test]
    #[ignore = "needs three host identities and a provisioned workspace: make sandbox-agent-evidence (hosted)"]
    fn three_identities_run_an_agent_and_none_reaches_anothers_state() {
        let ids = identities();
        let (broker_user, runtime_user, outsider_user) = (
            ids.broker_user.clone(),
            ids.runtime_user.clone(),
            ids.outsider_user.clone(),
        );
        let uids = format!(
            "authority={} broker={} runtime={} outsider={}",
            own_uid(),
            ids.broker_uid,
            ids.runtime_uid,
            ids.outsider_uid
        );
        let (broker_uid, runtime_uid) = (ids.broker_uid, ids.runtime_uid);
        let quota: u64 = var("DW_WORKSPACE_QUOTA").parse().unwrap();
        let root = PathBuf::from(var("DW_WORKSPACE_TMPFS"));
        let mut lab = Lab::new("m5d5i", Some(ids), &Workspace::Bounded(root.clone(), quota));
        let client = lab.stage.join("agent_runtime_client.py");
        let foreign = lab.stage.join("broker_foreign_client.py");
        let run_as = |user: &str, script: &Path, args: &[&str]| -> json::Object {
            let out = super::state_support::output(
                Command::new("sudo")
                    .args(["-n", "-u", user, "/usr/bin/python3"])
                    .arg(script)
                    .args(args)
                    .current_dir(script.parent().unwrap()),
            )
            .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            object(&String::from_utf8(out.stdout).unwrap())
        };

        // I01: three host identities, from the kernel.
        let (a_uid, _, a_groups) = kernel_ids(lab.server_pid());
        let (b_uid, _, b_groups) = kernel_ids(lab.broker().pid);
        assert_eq!(a_uid, own_uid());
        assert_eq!(b_uid, broker_uid);
        let mut peer = lab.peer(1);
        let Wire::Relayed(relay) = &peer.wire else {
            panic!("the runtime speaks through its own user")
        };
        let c_uid = u32::try_from(int(&relay.identity, "euid")).unwrap();
        let c_groups = ints(&relay.identity, "groups");
        assert_eq!(c_uid, runtime_uid);
        let distinct: BTreeSet<u32> = [a_uid, b_uid, c_uid].into_iter().collect();
        assert_eq!(distinct.len(), 3, "{uids}");
        assert!(!distinct.contains(&0) && !distinct.contains(&10001) && !distinct.contains(&10002));
        evidence(
            IDENTITY_SUITE,
            "i01-three-distinct-host-identities",
            &uids,
            HOSTED,
            "kernel-process-credentials",
        );

        // I02: the kernel's word for the runtime's connection, in the audit;
        // every other identity refused before a byte is read.
        let intent_subject = || {
            audit_records(&lab.dir.state(), "run.admitted")
                .last()
                .and_then(|r| super::state_support::text(r, "subject").map(str::to_owned))
        };
        assert_eq!(intent_subject(), Some(format!("uid:{c_uid}")));
        evidence(
            IDENTITY_SUITE,
            "i02-configured-runtime-admitted",
            &format!("uid:{c_uid}"),
            HOSTED,
            "authority-peer-policy",
        );
        let refused_before = audit_records(&lab.dir.state(), "transport.peer_refused").len();
        // The peer gate closes before it reads a byte: nothing is sent.
        let mut own = Client::connect(&lab.socket);
        assert!(
            own.recv(PROMPT).is_closed(),
            "the authority's own uid is no client"
        );
        evidence(
            IDENTITY_SUITE,
            "i02-authority-own-uid-refused",
            "closed",
            HOSTED,
            "authority-peer-policy",
        );
        for (case, user) in [
            ("i02-broker-uid-refused", broker_user.as_str()),
            ("i02-another-uid-refused", outsider_user.as_str()),
        ] {
            let report = run_as(user, &client, &["connect", lab.socket.to_str().unwrap()]);
            assert!(flag(&report, "connected"), "{report:?}");
            assert_eq!(int(&report, "received"), 0, "{case}: {report:?}");
            evidence(
                IDENTITY_SUITE,
                case,
                "0-bytes",
                HOSTED,
                "authority-peer-policy",
            );
        }
        let deadline = Instant::now() + PROMPT;
        while audit_records(&lab.dir.state(), "transport.peer_refused").len() < refused_before + 3 {
            assert!(Instant::now() < deadline, "three refusals audited");
            std::thread::sleep(Duration::from_millis(50));
        }
        // The runtime keeps its lease while the other identities are probed,
        // each probe a process started through `sudo`.
        peer.renew();

        // I03: the broker's private channel reads nothing from the runtime.
        let forged = FsReadAuthorisation::new(
            ChannelNonce::new("0".repeat(32)).unwrap(),
            InvocationId::parse("inv_01M24BB8G4E87TVJX9GX248ADD").unwrap(),
            1,
            1,
            ReadLimit::new(64).unwrap(),
        );
        let frame = hex(&dwk_proto::brokerp::encode_frame(&forged).unwrap());
        let broker_socket = lab.broker_socket.display().to_string();
        let forgery = run_as(
            &runtime_user,
            &foreign,
            &["authorise", &broker_socket, &frame],
        );
        assert_eq!(int(&forgery, "received"), 0, "{forgery:?}");
        let hello = run_as(&runtime_user, &client, &["connect", &broker_socket]);
        assert_eq!(int(&hello, "received"), 0, "{hello:?}");
        lab.broker().wait_for("peer_refused", 2);
        assert!(
            lab.broker()
                .stderr()
                .lines()
                .filter(|l| l.contains("peer_refused"))
                .all(|l| l.ends_with(&format!("peer_uid={c_uid}"))),
            "{}",
            lab.broker().stderr()
        );
        evidence(
            IDENTITY_SUITE,
            "i03-runtime-cannot-use-the-broker-channel",
            "0-bytes-peer-refused",
            HOSTED,
            "broker-peer-check",
        );
        peer.renew();

        // I04: the authority's state, policy, operator file and a secret
        // fixture: closed to the runtime.
        let secret = lab.dir.path().join("secrets.toml");
        std::fs::write(&secret, b"# a synthetic secret fixture\n").unwrap();
        mode(&secret, 0o600);
        let state = lab.dir.state();
        for (what, path) in [
            ("kernel.db", state.join("kernel.db")),
            ("audit.log", state.join("audit.log")),
            ("policy", lab.policy.clone()),
            ("sandbox.toml", lab.config.clone()),
            ("secrets", secret.clone()),
        ] {
            let p = path.display().to_string();
            let read = run_as(&runtime_user, &client, &["read", &p]);
            let write = run_as(&runtime_user, &client, &["write", &p]);
            assert!(
                flag(&read, "refused") && flag(&write, "refused"),
                "{what}: {read:?} {write:?}"
            );
            assert_eq!(text(&read, "errno"), "EACCES", "{what}");
        }
        for (what, args) in [
            ("list the state", vec!["list", state.to_str().unwrap()]),
            (
                "plant in the state",
                vec!["create", state.to_str().unwrap()],
            ),
        ] {
            let report = run_as(&runtime_user, &client, &args);
            assert!(flag(&report, "refused"), "{what}: {report:?}");
        }
        evidence(
            IDENTITY_SUITE,
            "i04-runtime-cannot-read-or-change-authority-state",
            "EACCES",
            HOSTED,
            "file-modes",
        );
        evidence(
            IDENTITY_SUITE,
            "i04-runtime-cannot-read-policy-operator-file-or-secret",
            "EACCES",
            HOSTED,
            "file-modes",
        );
        peer.renew();

        // I05: the runtime's socket is the broker's alone.
        let docker = run_as(&runtime_user, &client, &["connect", &lab.pins.socket]);
        assert!(!flag(&docker, "connected"), "{docker:?}");
        assert_eq!(text(&docker, "errno"), "EACCES", "{docker:?}");
        evidence(
            IDENTITY_SUITE,
            "i05-runtime-cannot-reach-the-oci-socket",
            "EACCES",
            HOSTED,
            "socket-mode-and-group",
        );

        // I07: who is in the workspace's group, and the root as measured.
        assert!(a_groups.contains(&WORKSPACE_GID), "{a_groups:?}");
        assert!(b_groups.contains(&WORKSPACE_GID), "{b_groups:?}");
        assert!(
            !c_groups.contains(&i64::from(WORKSPACE_GID)),
            "{c_groups:?}"
        );
        evidence(
            IDENTITY_SUITE,
            "i07-workspace-group-membership",
            "authority-and-broker-in-10001-runtime-not",
            HOSTED,
            "host-group-database",
        );
        let meta = std::fs::metadata(&root).unwrap();
        assert_eq!(meta.gid(), WORKSPACE_GID);
        assert_eq!(meta.uid(), own_uid());
        assert_eq!(meta.mode() & 0o7777, 0o2770);
        let stat = capacity(&root);
        // At most the quota and no more than a quarter below it
        // (`capacity_within_quota`, ADR-0052 §10).
        assert!(
            stat <= quota && stat >= quota - (quota >> 2),
            "{stat} of {quota}"
        );
        evidence(
            IDENTITY_SUITE,
            "i07-workspace-root-contract-measured",
            &format!("2770-gid-10001-{stat}-bytes"),
            HOSTED,
            "operator-provisioning-measured",
        );
        let anchor = root.join("tools/ca.pem").display().to_string();
        for (case, args) in [
            ("list", vec!["list", root.to_str().unwrap()]),
            ("create", vec!["create", root.to_str().unwrap()]),
            ("read", vec!["read", anchor.as_str()]),
        ] {
            let report = run_as(&runtime_user, &client, &args);
            assert!(flag(&report, "refused"), "{case}: {report:?}");
        }
        evidence(
            IDENTITY_SUITE,
            "i07-runtime-excluded-from-the-workspace",
            "EACCES",
            HOSTED,
            "workspace-root-2770",
        );

        // The agent, as the runtime's user, in the bounded workspace.
        let args = lab.agent_args(20);
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        peer.send_exec("agent-3id", FIXTURE, &words, 120);
        let container = lab.container(&peer.run);
        lab.runtime.awaited(&container, &Lab::agent_children());
        // I01: the workload's and the relay's identities, from the host.
        // Init, the agent, its two workers and the helper's sleeper.
        let workload_ids = lab.runtime.host_ids(&container);
        assert!(workload_ids.len() >= 5, "{workload_ids:?}");
        assert!(
            workload_ids.iter().all(|ids| *ids == (10001, 10001)),
            "{workload_ids:?}"
        );
        assert!(
            workload_ids
                .iter()
                .all(|(uid, _)| *uid != b_uid && *uid != a_uid && *uid != c_uid)
        );
        evidence(
            IDENTITY_SUITE,
            "i01-workload-runs-as-10001",
            &format!("{} processes", workload_ids.len()),
            HOSTED,
            "oci-user-measured-from-the-host",
        );
        evidence(
            IDENTITY_SUITE,
            "i06-workload-is-not-the-brokers-identity",
            &format!("10001-not-{b_uid}"),
            HOSTED,
            "oci-user-measured-from-the-host",
        );
        let environment = lab.environment_of(&container);
        let relays = lab.runtime.role(&environment, "relay");
        assert_eq!(relays.len(), 1, "{relays:?}");
        let relay_ids = lab.runtime.host_ids(&relays[0]);
        assert!(
            !relay_ids.is_empty() && relay_ids.iter().all(|(uid, _)| *uid == 10002),
            "{relay_ids:?}"
        );
        evidence(
            IDENTITY_SUITE,
            "i01-relay-runs-as-10002",
            "10002",
            HOSTED,
            "oci-user-measured-from-the-host",
        );
        // I06: no other identity looks into a daemon.
        for pid in [lab.broker().pid, lab.server_pid()] {
            let seen = run_as(&runtime_user, &client, &["inspect", &pid.to_string()]);
            for key in ["environ", "mem", "fds", "signal"] {
                let Some(Value::Object(attempt)) = seen.get(key) else {
                    panic!("{seen:?}")
                };
                assert!(flag(attempt, "refused"), "{pid} {key}: {seen:?}");
            }
        }
        evidence(
            IDENTITY_SUITE,
            "i06-runtime-cannot-inspect-a-daemon",
            "EACCES-EPERM",
            HOSTED,
            "kernel-ptrace-access-mode",
        );
        let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let posture = lab
            .broker()
            .stderr()
            .lines()
            .find(|l| l.contains("deployment_posture"))
            .unwrap_or_default()
            .to_owned();
        assert!(!posture.is_empty(), "{}", lab.broker().stderr());
        for acknowledgement in ["may trace the processes it starts", "shares uid"] {
            assert!(
                !lab.broker().stderr().contains(acknowledgement),
                "the broker served on a development acknowledgement: {}",
                lab.broker().stderr()
            );
        }
        evidence(
            IDENTITY_SUITE,
            "i06-broker-start-up-posture-production",
            &format!("yama-{scope}"),
            HOSTED,
            "broker-start-up-admission",
        );
        let body = peer.answer(Duration::from_secs(180));
        let out = sandboxed(&body);
        let text_out = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert_eq!(out.residue, ResidueVerdict::Pass, "{text_out}");
        let granted = object(field(&text_out, "granted"));
        assert_eq!(int(&granted, "status"), 200, "{text_out}");
        evidence(
            IDENTITY_SUITE,
            "a03-https-granted-origin-three-identities",
            "200-verified",
            HOSTED,
            "relay-and-connect-proxy-grant",
        );
        // A09: the agent and the broker share the bounded workspace through
        // the group: the workload made it 0660 in group 10001, the broker
        // reads it for the runtime.
        let plan = root.join("agent/plan.txt");
        let meta = std::fs::metadata(&plan).unwrap();
        assert_eq!(meta.uid(), 10001);
        assert_eq!(meta.gid(), WORKSPACE_GID);
        assert_eq!(meta.mode() & 0o777, 0o660);
        assert_eq!(peer.read("/workspace/agent/plan.txt"), b"plan");
        evidence(
            IDENTITY_SUITE,
            "a09-agent-and-broker-share-the-bounded-workspace",
            "0660-gid-10001-read-back",
            HOSTED,
            "workspace-group-10001",
        );
        // I05 from inside: the workload has no runtime socket either.
        let mut escape = vec!["workload-escape", lab.pins.socket.as_str()];
        let broker_dir = lab.broker_socket.parent().unwrap().display().to_string();
        escape.push(&broker_dir);
        let line = lab.fixture(&mut peer, &escape);
        assert_eq!(field(&line, "runtime_sockets"), "0", "{line}");
        assert!(line.contains("exists=false"), "{line}");
        assert!(!line.contains("exists=true"), "{line}");
        evidence(
            IDENTITY_SUITE,
            "i05-workload-cannot-reach-the-oci-socket",
            "absent",
            HOSTED,
            "mount-namespace",
        );

        // I08: an identity-separated crash and restart never repeat an
        // uncertain agent.
        std::fs::remove_dir_all(root.join("agent")).unwrap();
        peer.send_exec("agent-3id-lost", FIXTURE, &words, 120);
        let container = lab.container(&peer.run);
        lab.runtime.awaited(&container, &Lab::agent_children());
        lab.kill_server();
        assert!(lab.runtime.exists(&container));
        lab.start_server();
        let state_now: String = raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'agent-3id-lost'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state_now, "UNKNOWN");
        assert!(!lab.runtime.exists(&container));
        evidence(
            IDENTITY_SUITE,
            "i08-authority-crash-unknown-environment-destroyed",
            "UNKNOWN",
            HOSTED,
            "authority-ledger-and-reconciliation",
        );
        let mut again = lab.peer(1);
        std::fs::remove_dir_all(root.join("agent")).ok();
        let body = again.exec("agent-3id-lost", FIXTURE, &words, 120);
        assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
        assert!(!root.join("agent").exists(), "an uncertain agent ran again");
        evidence(
            IDENTITY_SUITE,
            "i08-never-replayed",
            "IDEMPOTENCY_KEY_REUSED",
            HOSTED,
            "authority-shared-idempotency-namespace",
        );
        // The broker, its own identity, lost mid-agent.
        let mut d = lab.peer(2);
        d.send_exec("agent-3id-broker", FIXTURE, &words, 120);
        let container = lab.container(&d.run);
        lab.runtime.awaited(&container, &Lab::agent_children());
        lab.kill_broker();
        let body = d.answer(Duration::from_secs(120));
        let DwkpBody::ToolFailedV5(failure) = &body else {
            panic!("not failed: {body:?}")
        };
        assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN");
        assert_eq!(failure.environment_destroyed, Some(true));
        lab.start_broker();
        lab.kill_server();
        lab.start_server();
        assert!(!lab.runtime.exists(&container));
        evidence(
            IDENTITY_SUITE,
            "i08-broker-crash-unknown-environment-destroyed",
            "OUTCOME_UNKNOWN",
            HOSTED,
            "authority-ledger-and-reconciliation",
        );
        drop(again);
        drop(d);
        drop(peer);
    }

    #[test]
    #[ignore = "needs three host identities: make sandbox-agent-evidence (hosted)"]
    fn three_identities_a_broker_refuses_a_sandbox_identity_at_start() {
        // ADR-0052 §13 with real users: a broker told that the authority is
        // a sandbox identity refuses to serve, whatever else is in order.
        let ids = identities();
        let dir = TempDir::new("m5d5r");
        mode(dir.path(), 0o711);
        let stage = dir.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        mode(&stage, 0o755);
        let binary = stage.join("dwkd-broker");
        std::fs::copy(broker_bin(), &binary).unwrap();
        mode(&binary, 0o755);
        for (case, authority, role) in [
            (
                "i06-broker-refuses-a-workload-authority",
                10001u32,
                "every workload's",
            ),
            (
                "i06-broker-refuses-a-relay-authority",
                10002u32,
                "every relay's",
            ),
        ] {
            let socket = PathBuf::from(format!("/tmp/dwr-{}-{authority}", std::process::id()))
                .join("broker.sock");
            let refused = Broker::try_start_as(&ids.broker_user, &binary, &socket, authority, &[]);
            let Err(text) = refused else {
                panic!("{case}: the broker served")
            };
            assert!(
                text.contains(&format!(
                    "cannot serve: the authority's uid {authority} is {role}"
                )),
                "{case}: {text}"
            );
            evidence(
                IDENTITY_SUITE,
                case,
                "refused-at-start",
                HOSTED,
                "broker-start-up-admission",
            );
            remove_as(&ids.broker_user, socket.parent().unwrap());
        }
    }

    /// The capacity of the filesystem whose root `root` is, as `statvfs`
    /// counts it: blocks times the fragment size.
    fn capacity(root: &Path) -> u64 {
        let stat = rustix::fs::statvfs(root).unwrap();
        stat.f_blocks * stat.f_frsize
    }
}
