//! Real-process fixtures for the M4b brokered `fs.read` evidence (ADR-0043).
//!
//! Three real processes on every test: the released `dwkd-authority serve`,
//! the released `dwkd-broker serve`, and this test process as the runtime —
//! speaking DWKP over the authority's real socket. The authority reaches the
//! broker over the private channel exactly as an operator deploys it; nothing
//! is stubbed, and the only in-process step is trusted operator setup (the
//! workspace binding) before the authority starts.
//!
//! Locally all three run as one uid, so the authority is started with
//! `--allow-shared-broker-uid` and the broker with
//! `--allow-shared-authority-uid`: that proves the channel, the exchange and
//! every refusal, and says nothing about uid separation. The separated case
//! — three distinct users — is the hosted CI job's (`transport_foreign.rs`
//! style, `#[ignore]`d here and fail-closed there).

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::wire::id::{RunId, SessionId};
use dwkd_authority::state::{AuditRecord, WorkspaceId, WorkspaceSensitivity, read_audit_log};

use super::state_support::{
    START_MS, TempDir, acquire_msg, admit_msg, ceiling, decode, id, install_fixtures, session,
    start,
};
use super::transport_support::{BIN, Client, PROMPT, Server, own_uid};

/// The broker binary: built beside the authority by `cargo test --workspace`
/// (the broker's own integration tests make Cargo build it) and by the
/// evidence command, which builds it explicitly.
pub(crate) fn broker_bin() -> PathBuf {
    let path = Path::new(BIN).with_file_name("dwkd-broker");
    assert!(
        path.is_file(),
        "{} does not exist: build it with `cargo build -p dwkd-broker` (or run \
         `cargo test --workspace`) before these tests",
        path.display()
    );
    path
}

/// The operator policy every brokered test runs under, unless it says
/// otherwise. `${WORKSPACE}` is the run's workspace; `secret/` is denied by a
/// rule, `capped/` only for reads of at most 16 bytes, and the rest of the
/// workspace for reads of at most 256 KiB.
pub(crate) const POLICY: &str = r#"schema_version = 1

[meta]
name = "m4b"

[[rule]]
id = "deny-secret"
effect = "DENY"
reason = "SENSITIVE_PATH"
when.verb = "fs.read"
when.path_under = "${WORKSPACE}/secret"

[[rule]]
id = "allow-capped"
effect = "ALLOW"
when.verb = "fs.read"
when.path_under = "${WORKSPACE}/capped"
when.max_bytes = 16

[[rule]]
id = "deny-capped"
effect = "DENY"
reason = "NO_MATCHING_RULE"
when.verb = "fs.read"
when.path_under = "${WORKSPACE}/capped"

[[rule]]
id = "allow-workspace-read"
effect = "ALLOW"
when.verb = "fs.read"
when.path_under = "${WORKSPACE}"
when.max_bytes = 262144

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// The M4c operator policy (ADR-0044): reads, listings and stats anywhere in
/// the workspace; writes, creations and deletions too, except where a rule
/// says otherwise:
///
/// * `locked/` — every mutation denied by a rule;
/// * `nocreate/` — writes allowed, creations denied: a creating write is a
///   compound plan one of whose actions is denied;
/// * `artifacts/` — writes and creations allowed only with
///   `require_artifact_capture`, which this build cannot enforce;
/// * `approval/` — deletion requires approval, which this build cannot obtain.
pub(crate) const FSOPS_POLICY: &str = r#"schema_version = 1

[meta]
name = "m4c"

[[rule]]
id = "deny-locked"
effect = "DENY"
reason = "SENSITIVE_PATH"
when.verb = ["fs.write", "fs.create", "fs.delete"]
when.path_under = "${WORKSPACE}/locked"

[[rule]]
id = "deny-create-in-nocreate"
effect = "DENY"
reason = "NO_MATCHING_RULE"
when.verb = "fs.create"
when.path_under = "${WORKSPACE}/nocreate"

[[rule]]
id = "artifact-captured-writes"
effect = "ALLOW"
when.verb = ["fs.write", "fs.create"]
when.path_under = "${WORKSPACE}/artifacts"
obligations = ["require_artifact_capture"]

[[rule]]
id = "approve-deletes"
effect = "REQUIRE_APPROVAL"
reason = "DESTRUCTIVE_IN_WORKSPACE"
when.verb = "fs.delete"
when.path_under = "${WORKSPACE}/approval"
approval.scope = "path_set"
approval.ttl = "10m"
approval.max_uses = 1

[[rule]]
id = "allow-workspace-observe"
effect = "ALLOW"
when.verb = ["fs.read", "fs.list", "fs.stat"]
when.path_under = "${WORKSPACE}"
when.max_bytes = 16777216

[[rule]]
id = "allow-workspace-mutate"
effect = "ALLOW"
when.verb = ["fs.write", "fs.create", "fs.delete"]
when.path_under = "${WORKSPACE}"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// The M4b ceiling and the filesystem verbs M4c implements.
pub(crate) fn fsops_ceiling() -> Vec<String> {
    let mut all = ceiling();
    for verb in ["fs.list", "fs.stat", "fs.write", "fs.create", "fs.delete"] {
        all.push(format!("{verb}:*"));
    }
    all
}

/// Every filesystem capability a `maintainer` run of the M4c fixture asks for.
pub(crate) const FSOPS_CAPABILITIES: &[&str] = &[
    "fs.read:/workspace",
    "fs.list:/workspace",
    "fs.stat:/workspace",
    "fs.write:/workspace",
    "fs.create:/workspace",
    "fs.delete:/workspace",
];

/// Bytes 0..=255, twice: every byte value, so a lossy path shows.
pub(crate) fn every_byte() -> Vec<u8> {
    (0..=255u8).chain(0..=255u8).collect()
}

/// A running `dwkd-broker serve`, killed when dropped.
pub(crate) struct Broker {
    child: Child,
    /// The broker's own pid, from its ready line.
    pub(crate) pid: u32,
    stderr: Arc<Mutex<String>>,
    /// The user it was started as through `sudo`, if not this process's.
    user: Option<String>,
}

impl Broker {
    /// Start the real broker binary and wait until it says it is serving.
    pub(crate) fn start(socket: &Path, authority_uid: u32, extra: &[&str]) -> Self {
        match Self::try_start(socket, authority_uid, extra) {
            Ok(broker) => broker,
            Err(text) => panic!("the broker did not start:\n{text}"),
        }
    }

    /// Start, or report how it refused.
    pub(crate) fn try_start(
        socket: &Path,
        authority_uid: u32,
        extra: &[&str],
    ) -> Result<Self, String> {
        let mut command = Command::new(broker_bin());
        command.env_clear();
        Self::spawn(command, None, socket, authority_uid, extra)
    }

    /// Start the (debug) broker so that it aborts at crash point `point`
    /// (M4c, `DWKD_BROKER_CRASH_AT`), as this uid.
    pub(crate) fn start_crashing_at(socket: &Path, point: &str) -> Self {
        let mut command = Command::new(broker_bin());
        command.env_clear().env("DWKD_BROKER_CRASH_AT", point);
        match Self::spawn(
            command,
            None,
            socket,
            own_uid(),
            &["--allow-shared-authority-uid"],
        ) {
            Ok(broker) => broker,
            Err(text) => panic!("the broker did not start:\n{text}"),
        }
    }

    /// Whether the process has exited (a crash point aborted it).
    pub(crate) fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Start the broker as `user` through `sudo -n -u` -- a test harness
    /// switching users, never the authority (TX010). `binary` must be a copy
    /// that user can execute.
    pub(crate) fn start_as(user: &str, binary: &Path, socket: &Path, authority_uid: u32) -> Self {
        let mut command = Command::new("sudo");
        command.args(["-n", "-u", user]).arg(binary);
        match Self::spawn(command, Some(user.to_owned()), socket, authority_uid, &[]) {
            Ok(broker) => broker,
            Err(text) => panic!("the broker did not start as {user}:\n{text}"),
        }
    }

    fn spawn(
        mut command: Command,
        user: Option<String>,
        socket: &Path,
        authority_uid: u32,
        extra: &[&str],
    ) -> Result<Self, String> {
        let mut child = super::state_support::spawn(
            command
                .arg("serve")
                .arg("--socket")
                .arg(socket)
                .arg("--authority-uid")
                .arg(authority_uid.to_string())
                .args(extra)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .expect("the broker spawns");
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        let pipe = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut text = sink.lock().unwrap();
                text.push_str(&line);
                text.push('\n');
            }
        });
        let stdout = child.stdout.take().expect("stdout");
        let (lines, ready): (mpsc::Sender<String>, Receiver<String>) = mpsc::channel();
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
                let pid = line
                    .rsplit_once("(pid ")
                    .and_then(|(_, rest)| rest.trim_end_matches(')').parse().ok())
                    .expect("the ready line names the broker's pid");
                return Ok(Self {
                    child,
                    pid,
                    stderr,
                    user,
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                return Err(format!("{status:?}\n{}", stderr.lock().unwrap()));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out\n{}", stderr.lock().unwrap()));
            }
        }
    }

    pub(crate) fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Every `event=` line the broker has written, without the prefix.
    pub(crate) fn events(&self) -> Vec<String> {
        self.stderr()
            .lines()
            .filter_map(|line| line.split_once("event=").map(|(_, e)| e.to_owned()))
            .collect()
    }

    /// How many events start with `kind`.
    pub(crate) fn count(&self, kind: &str) -> usize {
        self.events().iter().filter(|e| e.starts_with(kind)).count()
    }

    /// How many staging reclamations the broker executed (ADR-0044 §10):
    /// housekeeping after an outcome, never an invocation performed.
    pub(crate) fn reclaims(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| e.starts_with("executed") && e.ends_with("op=broker.fs_reclaim"))
            .count()
    }

    /// Wait until at least `n` events start with `kind`.
    pub(crate) fn wait_for(&self, kind: &str, n: usize) {
        let deadline = Instant::now() + PROMPT;
        while self.count(kind) < n {
            assert!(
                Instant::now() < deadline,
                "waited for {n} {kind} events:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// `SIGKILL` -- to the broker itself: `sudo` does not relay a signal it
    /// cannot catch, so a broker started as another user is killed as that
    /// user.
    pub(crate) fn kill(&mut self) {
        if let Some(user) = &self.user {
            let _ = super::state_support::status(Command::new("sudo").args([
                "-n",
                "-u",
                user,
                "kill",
                "-9",
                &self.pid.to_string(),
            ]));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The uid the kernel says the broker process runs as, from
    /// `/proc/<pid>/status` (readable by every user).
    pub(crate) fn uid(&self) -> u32 {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid)).unwrap();
        let line = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .expect("a Uid line");
        line.split_whitespace().nth(2).unwrap().parse().unwrap()
    }

    /// Open descriptors, from `/proc` (same uid locally).
    pub(crate) fn open_fds(&self) -> usize {
        std::fs::read_dir(format!("/proc/{}/fd", self.pid))
            .map(Iterator::count)
            .unwrap_or(usize::MAX)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.kill();
    }
}

/// A workspace, an operator policy, a prepared authority store, and the
/// paths the two daemons serve at.
pub(crate) struct Setup {
    pub(crate) dir: TempDir,
    pub(crate) root: PathBuf,
    pub(crate) outside: PathBuf,
    pub(crate) policy: PathBuf,
    /// The policy profile name `--policy-profile` names.
    pub(crate) profile: &'static str,
    /// The mode ceiling.
    pub(crate) ceiling: Vec<String>,
}

/// The fixture workspace's name.
pub(crate) const WORKSPACE: &str = "proj";

impl Setup {
    /// A fresh directory with a workspace tree and a file outside it, and an
    /// authority store with the fixture profiles, the workspace bound to the
    /// tree, and session 1 bound to the workspace.
    pub(crate) fn new(tag: &str) -> Self {
        Self::with_policy(tag, POLICY)
    }

    pub(crate) fn with_policy(tag: &str, policy_text: &str) -> Self {
        Self::build(tag, policy_text, "m4b", ceiling(), |_| {})
    }

    /// The M4c fixture (ADR-0044): the M4b tree, the write-enabled policy
    /// [`FSOPS_POLICY`], a `maintainer` agent profile that declares every
    /// filesystem verb M4c implements, and a mode ceiling that allows them.
    pub(crate) fn fsops(tag: &str) -> Self {
        Self::fsops_with(tag, FSOPS_POLICY)
    }

    /// The M4d fixture (ADR-0045): the M4b tree, `policy_text` as the
    /// operator policy, an `operator` agent profile declaring the three
    /// process verbs for every executable, and a mode ceiling that allows
    /// them.
    pub(crate) fn process(tag: &str, policy_text: &str) -> Self {
        let mut ceiling = ceiling();
        for verb in ["process.exec", "process.inspect", "process.signal"] {
            ceiling.push(format!("{verb}:*"));
        }
        Self::build(tag, policy_text, "m4d", ceiling, |authority| {
            authority
                .operator()
                .install_agent_profile(&super::state_support::profile(
                    "operator",
                    &["process.exec:*", "process.inspect:*", "process.signal:*"],
                    &[],
                    dwkd_authority::capability::PrivacyClass::Any,
                ))
                .expect("operator installs");
        })
    }

    /// The same fixture, its policy file composed as `profile` (a shipped
    /// pack's `meta.name`).
    pub(crate) fn with_profile_name(mut self, profile: &'static str) -> Self {
        self.profile = profile;
        self
    }

    /// The M4c fixture under another policy.
    pub(crate) fn fsops_with(tag: &str, policy_text: &str) -> Self {
        Self::build(tag, policy_text, "m4c", fsops_ceiling(), |authority| {
            authority
                .operator()
                .install_agent_profile(&super::state_support::profile(
                    "maintainer",
                    &[
                        "fs.read:*",
                        "fs.list:*",
                        "fs.stat:*",
                        "fs.write:*",
                        "fs.create:*",
                        "fs.delete:*",
                        "model.call:*",
                    ],
                    &[],
                    dwkd_authority::capability::PrivacyClass::Any,
                ))
                .expect("maintainer installs");
        })
    }

    fn build(
        tag: &str,
        policy_text: &str,
        profile: &'static str,
        ceiling: Vec<String>,
        extra: impl FnOnce(&mut dwkd_authority::state::Authority),
    ) -> Self {
        let dir = TempDir::new(tag);
        let root = dir.path().join("proj");
        for sub in ["src", "secret", "capped", "empty-dir"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(root.join("a.txt"), b"hello, workspace\n").unwrap();
        std::fs::write(root.join("bytes.bin"), every_byte()).unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}\n").unwrap();
        std::fs::write(root.join("secret/key"), b"do not read me").unwrap();
        std::fs::write(root.join("capped/f"), b"0123456789abcdefXYZ").unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"OUTSIDE-SECRET").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("link")).unwrap();
        let policy = dir.path().join(format!("{profile}.toml"));
        std::fs::write(&policy, policy_text).unwrap();

        let clock = Arc::new(dwkd_authority::state::ManualClock::new(START_MS));
        let (mut authority, _) = start(
            &dir.state(),
            &super::state_support::balanced(),
            &clock,
            None,
        )
        .expect("the fixture store starts");
        install_fixtures(&mut authority);
        extra(&mut authority);
        {
            let workspace = WorkspaceId::new(WORKSPACE).unwrap();
            let mut operator = authority.operator();
            operator
                .install_workspace(&workspace, WorkspaceSensitivity::Private)
                .unwrap();
            operator
                .install_workspace_root(&workspace, root.to_str().unwrap())
                .unwrap();
            for n in 1..=4 {
                operator
                    .bind_session_workspace(&session(n), &workspace)
                    .unwrap();
            }
        }
        drop(authority);
        Self {
            dir,
            root,
            outside,
            policy,
            profile,
            ceiling,
        }
    }

    pub(crate) fn state(&self) -> PathBuf {
        self.dir.state()
    }

    pub(crate) fn kernel_socket(&self) -> PathBuf {
        self.dir.path().join("ipc").join("kernel.sock")
    }

    pub(crate) fn broker_socket(&self) -> PathBuf {
        self.dir.path().join("bipc").join("broker.sock")
    }

    /// `serve` arguments: this process's uid may speak DWKP, the operator
    /// policy, and the broker at `broker_socket()` served by `broker_uid`.
    pub(crate) fn authority_args(&self, broker_uid: Option<u32>, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "serve".to_owned(),
            "--state-dir".to_owned(),
            self.state().display().to_string(),
            "--socket".to_owned(),
            self.kernel_socket().display().to_string(),
            "--policy-file".to_owned(),
            self.policy.display().to_string(),
            "--policy-profile".to_owned(),
            self.profile.to_owned(),
            "--mode".to_owned(),
            "balanced".to_owned(),
            "--allow-uid".to_owned(),
            own_uid().to_string(),
            "--allow-authority-uid".to_owned(),
        ];
        for capability in &self.ceiling {
            args.push("--ceiling".to_owned());
            args.push(capability.clone());
        }
        if let Some(uid) = broker_uid {
            args.push("--broker-socket".to_owned());
            args.push(self.broker_socket().display().to_string());
            args.push("--broker-uid".to_owned());
            args.push(uid.to_string());
            if uid == own_uid() {
                args.push("--allow-shared-broker-uid".to_owned());
            }
        }
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args
    }

    /// The local deployment: a broker and an authority, both as this uid.
    pub(crate) fn start_both(&self) -> (Broker, Server) {
        let broker = Broker::start(
            &self.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        let server = Server::start(&self.authority_args(Some(own_uid()), &[]));
        (broker, server)
    }

    /// Every verified record in `audit.log`.
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

/// A connected runtime with a lease and an admitted run.
pub(crate) struct Runtime {
    pub(crate) client: Client,
    pub(crate) session: SessionId,
    pub(crate) epoch: u64,
    pub(crate) run: RunId,
    /// What the admission granted and withheld.
    pub(crate) grant: dwk_proto::dwkp::messages::RunGrant,
    sent: u64,
}

impl Runtime {
    /// Handshake, lease session `n`, admit a `researcher` run requesting
    /// `capabilities`.
    pub(crate) fn admit(socket: &Path, n: u64, capabilities: &[&str]) -> Self {
        let mut client = Client::connect(socket);
        client.handshake();
        let session = session(n);
        let epoch = match &client.call(&acquire_msg(&session)).body {
            DwkpBody::LeaseGrant(grant) => grant.epoch,
            other => panic!("lease: {other:?}"),
        };
        let admitted = client.call(&admit_msg(
            &session,
            epoch,
            &format!("k{n}"),
            "researcher",
            &[],
            capabilities,
            n,
        ));
        let grant = match &admitted.body {
            DwkpBody::RunGrant(grant) => grant.clone(),
            other => panic!("admission: {other:?}"),
        };
        Self {
            client,
            session,
            epoch: epoch.get(),
            run: grant.run_id.clone(),
            grant,
            sent: 0,
        }
    }

    /// Handshake, lease session `n`, admit a run of `agent_profile`
    /// requesting `capabilities`.
    pub(crate) fn admit_as(
        socket: &Path,
        n: u64,
        agent_profile: &str,
        capabilities: &[&str],
    ) -> Self {
        let mut client = Client::connect(socket);
        client.handshake();
        let session = session(n);
        let epoch = match &client.call(&acquire_msg(&session)).body {
            DwkpBody::LeaseGrant(grant) => grant.epoch,
            other => panic!("lease: {other:?}"),
        };
        let admitted = client.call(&admit_msg(
            &session,
            epoch,
            &format!("k{n}"),
            agent_profile,
            &[],
            capabilities,
            n,
        ));
        let grant = match &admitted.body {
            DwkpBody::RunGrant(grant) => grant.clone(),
            other => panic!("admission: {other:?}"),
        };
        Self {
            client,
            session,
            epoch: epoch.get(),
            run: grant.run_id.clone(),
            grant,
            sent: 0,
        }
    }

    /// A version-2 tool request (M4c): `payload` is the `ToolCall` object's
    /// JSON text; an invocation carries `key` as its idempotency key.
    pub(crate) fn v2_json(&mut self, schema: &str, payload: &str, key: Option<&str>) -> String {
        let n = self.next();
        let key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#));
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":2,"ts":"2026-09-24T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
            id = id("msg", 800_000 + n),
            session = self.session.as_str(),
            run = self.run.as_str(),
            epoch = self.epoch,
        )
    }

    /// A version-3 tool request (M4d): `payload` is the `ToolCallV3`
    /// object's JSON text; an invocation carries `key`.
    pub(crate) fn v3_json(&mut self, schema: &str, payload: &str, key: Option<&str>) -> String {
        self.v2_json(schema, payload, key).replacen(
            r#""schema_version":2"#,
            r#""schema_version":3"#,
            1,
        )
    }

    /// Version-3 `ToolInvoke` with idempotency key `key`.
    pub(crate) fn invoke_v3(&mut self, payload: &str, key: &str) -> DwkpMessage {
        let text = self.v3_json("direwolf.tool.invoke", payload, Some(key));
        self.client.call(&decode(&text))
    }

    /// Version-3 `CanonicalPreview`.
    pub(crate) fn preview_v3(&mut self, payload: &str) -> DwkpMessage {
        let text = self.v3_json("direwolf.tool.preview", payload, None);
        self.client.call(&decode(&text))
    }

    /// Version-2 `ToolInvoke` with idempotency key `key`.
    pub(crate) fn invoke_v2(&mut self, payload: &str, key: &str) -> DwkpMessage {
        let text = self.v2_json("direwolf.tool.invoke", payload, Some(key));
        self.client.call(&decode(&text))
    }

    /// Version-2 `CanonicalPreview`.
    pub(crate) fn preview_v2(&mut self, payload: &str) -> DwkpMessage {
        let text = self.v2_json("direwolf.tool.preview", payload, None);
        self.client.call(&decode(&text))
    }

    /// Admit another run in the same session and lease.
    pub(crate) fn admit_another(&mut self, key: &str, capabilities: &[&str]) -> RunId {
        self.sent += 1;
        let epoch = dwk_proto::wire::scalar::Epoch::new(self.epoch).unwrap();
        let admitted = self.client.call(&admit_msg(
            &self.session,
            epoch,
            key,
            "researcher",
            &[],
            capabilities,
            900 + self.sent,
        ));
        match &admitted.body {
            DwkpBody::RunGrant(grant) => grant.run_id.clone(),
            other => panic!("admission: {other:?}"),
        }
    }

    fn next(&mut self) -> u64 {
        self.sent += 1;
        self.sent
    }

    /// A tool request, as JSON text, for `run` at `epoch`.
    pub(crate) fn tool_json(
        &mut self,
        schema: &str,
        run: &RunId,
        epoch: u64,
        path: &str,
        max_bytes: u64,
    ) -> String {
        let n = self.next();
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":1,"ts":"2026-09-23T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"payload":{{"fs_read":{{"path":"{path}","max_bytes":{max_bytes}}}}}}}"#,
            id = id("msg", 700_000 + n),
            session = self.session.as_str(),
            run = run.as_str(),
        )
    }

    /// `ToolInvoke` for this runtime's run.
    pub(crate) fn invoke(&mut self, path: &str, max_bytes: u64) -> DwkpMessage {
        let run = self.run.clone();
        self.invoke_as(&run, self.epoch, path, max_bytes)
    }

    pub(crate) fn invoke_as(
        &mut self,
        run: &RunId,
        epoch: u64,
        path: &str,
        max_bytes: u64,
    ) -> DwkpMessage {
        let text = self.tool_json("direwolf.tool.invoke", run, epoch, path, max_bytes);
        self.client.call(&decode(&text))
    }

    /// `CanonicalPreview` for this runtime's run.
    pub(crate) fn preview(&mut self, path: &str, max_bytes: u64) -> DwkpMessage {
        let run = self.run.clone();
        let text = self.tool_json("direwolf.tool.preview", &run, self.epoch, path, max_bytes);
        self.client.call(&decode(&text))
    }
}

/// One line of structured evidence for the M4b evidence command.
pub(crate) fn evidence(suite: &str, case: &str, outcome: &str, broker_contacts: usize) {
    println!(
        "BROKER-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
         \"broker_contacts\":{broker_contacts},\"authority\":\"{BIN}\"}}"
    );
}
