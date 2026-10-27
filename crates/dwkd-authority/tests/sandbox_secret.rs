//! M5d.3's secret evidence at the authority (ADR-0052 §7; ADR-0046 §§15–20):
//! the **real** authority state (`kernel.db`, `audit.log`), **synthetic**
//! values in the **real** kernel keyring read by the real backend, the
//! **released** `dwkd-broker`, a **real** OCI runtime, and a **real** DWKP
//! client -- through the server seam that serves an authority this test
//! built (`serve_authority`), and through the released
//! `dwkd-authority serve --sandbox-config --secrets-file` binary.
//!
//! Every test is `#[ignore]`d: it needs a runtime, the evidence image and its
//! pinned digests (`make sandbox-secret-evidence`, `DW_SANDBOX_*`), and a
//! usable kernel keyring. Run any other way, or without a keyring, it panics
//! `NOT EXERCISED`.
//!
//! The policy is the evidence's own operator policy -- `secret.use` allowed
//! in a sandbox with `audit_level=full` -- unless a test names a shipped
//! pack, which it then says. Every value is generated here; assertions
//! compare fingerprints, lengths and booleans, never values.

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
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::sandbox::NetworkTopology;
    use dwk_proto::dwkp::sandboxops::{ResidueVerdict, SandboxedExecResult};
    use dwk_proto::dwkp::secretops::{PlannedSpawnInjectionAction, SpawnInjection, ToolPlanV6};
    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::error::ErrorCode;
    use dwk_proto::wire::id::{RunId, SessionId};
    use dwk_proto::wire::scalar::{DecisionEffect, Epoch, ProcessDecisionReason};
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::sandbox::{SandboxConfig, WorkloadBudget, WorkspaceSetting};
    use dwkd_authority::server::{PeerPolicy, Served, serve_authority};
    use dwkd_authority::state::{
        Authority, CallerContext, CrashHook, CrashPoint, HookAction, ManualClock, Mode, PolicySet,
        Reply, StartOptions, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };
    use linux_keyutils::{Key, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};

    use super::broker_support::Broker;
    use super::state_support::{
        START_MS, TempDir, acquire_msg, admit_msg, decode, id, policy, profile, session,
        spawn_guard, subject,
    };
    use super::transport_support::{Client, Server, own_uid};

    const SUITE: &str = "sandbox-authority-secret";
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    const PROBE: &str = "/usr/libexec/direwolf/sandbox-probe";
    const TRUE: &str = "/usr/bin/true";
    const DEPLOY: &str = "deploy-key";
    const ENV_TOKEN: &str = "env-token";
    const SPARE: &str = "spare-key";
    const VARIABLE: &str = "GH_TOKEN";
    const PLACEHOLDER: &str = "[redacted:deploy-key]";
    /// What a line is (M5e.1): a real DWKP client on the authority's socket,
    /// the seam's or the released `serve`'s (`E2E`), or the authority's own
    /// dispatch (`OCI`) -- each over the released broker and a real runtime.
    const OCI: &str = "real-oci";
    const E2E: &str = "dwkp-end-to-end";

    /// One line of evidence, printed only after the assertions before it
    /// held: the case, how it ended, its level and what enforced or observed
    /// it (M5e.1, OD-E1) -- canonical JSON, so no outcome can break the line.
    /// No line carries a value: outcomes name fingerprints and reasons.
    fn evidence(case: &str, outcome: &str, level: &str, enforcement: &str) {
        use dwk_proto::json::{Object, Value, to_canonical_string};
        let mut fields = Object::new();
        for (key, value) in [
            ("suite", SUITE),
            ("case", case),
            ("outcome", outcome),
            ("level", level),
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

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-secret-evidence`, which \
                 builds the evidence image and pins its digests"
            )
        })
    }

    /// A synthetic value from the kernel's random source: never a real
    /// credential, never the same twice.
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

    fn fnv(bytes: &[u8]) -> String {
        let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash: u64, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        format!("{hash:016x}")
    }

    /// Whether `haystack` holds `value`, raw or hex-encoded.
    fn holds(haystack: &[u8], value: &[u8]) -> bool {
        let hex: Vec<u8> = value
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        [value, &hex[..]]
            .iter()
            .any(|needle| haystack.windows(needle.len()).any(|w| w == *needle))
    }

    /// Whether any file of `state` holds `value`: the store, its WAL and
    /// shared memory, the audit log.
    fn durable_holds(state: &Path, value: &[u8]) -> bool {
        std::fs::read_dir(state).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            std::fs::read(&path).is_ok_and(|bytes| holds(&bytes, value))
        })
    }

    /// A kernel-keyring entry, provisioned as the keychain backend requires
    /// of an operator (`secret/backend/keychain.rs`), removed when dropped.
    struct Seeded(String, Key);

    impl Seeded {
        fn new(tag: &str, value: &[u8]) -> Self {
            let name = format!("direwolf-evidence/m5d3-{tag}-{}", std::process::id());
            let made = (|| {
                let staging = KeyRing::from_special_id(KeyRingIdentifier::Process, true).ok()?;
                let user = KeyRing::from_special_id(KeyRingIdentifier::User, true).ok()?;
                let key = staging.add_key(&name, value).ok()?;
                let perms = KeyPermissionsBuilder::builder()
                    .posessor(Permission::ALL)
                    .user(Permission::VIEW | Permission::READ | Permission::SEARCH)
                    .build();
                let placed = user.link_key(key).and_then(|()| key.set_perms(perms));
                let _ = staging.unlink_key(key);
                if placed.is_err() {
                    let _ = user.unlink_key(key);
                    return None;
                }
                Some(key)
            })();
            let key = made.expect("NOT EXERCISED: no usable kernel keyring on this host");
            Self(name, key)
        }
    }

    impl Drop for Seeded {
        fn drop(&mut self) {
            let _ = self.1.invalidate();
            if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false) {
                let _ = ring.unlink_key(self.1);
            }
        }
    }

    /// The evidence's synthetic credentials, each in the keyring.
    struct Values {
        deploy: Vec<u8>,
        env: Vec<u8>,
        _held: Vec<Seeded>,
        secrets: String,
    }

    impl Values {
        fn new(tag: &str) -> Self {
            let deploy = synthetic(40);
            let env = synthetic(36);
            let a = Seeded::new(&format!("{tag}-deploy"), &deploy);
            let b = Seeded::new(&format!("{tag}-env"), &env);
            let secrets = format!(
                r#"schema_version = 1

[secrets.deploy-key]
type = "generic"
storage = "keychain"
keychain = "{a}"
injection = ["fd_at_spawn"]
consumers = ["{FIXTURE}"]

[secrets.env-token]
type = "generic"
storage = "keychain"
keychain = "{b}"
injection = ["env_at_spawn"]
consumers = ["{FIXTURE}"]
env = "{VARIABLE}"

[secrets.spare-key]
type = "generic"
storage = "keychain"
keychain = "{a}"
injection = ["fd_at_spawn"]
consumers = ["{FIXTURE}"]
"#,
                a = a.0,
                b = b.0,
            );
            Self {
                deploy,
                env,
                _held: vec![a, b],
                secrets,
            }
        }
    }

    /// The evidence's operator policy: the fixture in a sandbox, `secret.use`
    /// in a sandbox with `audit_level=full`, nothing on the host, everything
    /// else denied. **Not** a shipped pack.
    fn secret_policy(fixture: &str) -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5d3"

[[rule]]
id = "allow-the-fixture-in-a-sandbox"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{FIXTURE}@{fixture}"]
obligations = ["max_output_bytes=65536"]

[[rule]]
id = "secret-use-in-a-sandbox"
effect = "ALLOW"
when.verb = "secret.use"
when.environment = "sandbox"
obligations = ["audit_level=full"]

[[rule]]
id = "never-on-the-host"
effect = "DENY"
reason = "HOST_EXECUTION_DISABLED"
when.verb = ["process.exec", "secret.use"]
when.environment = "host"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#
        )
    }

    #[derive(Clone)]
    struct Runtime {
        client: PathBuf,
        socket: String,
    }

    impl Runtime {
        fn load() -> Self {
            Self {
                client: PathBuf::from(var("DW_SANDBOX_RUNTIME")),
                socket: var("DW_SANDBOX_SOCKET"),
            }
        }

        fn docker(&self, args: &[&str]) -> Output {
            Command::new(&self.client)
                .env_clear()
                .env("HOME", std::env::temp_dir())
                .arg("--host")
                .arg(format!("unix://{}", self.socket))
                .args(args)
                .output()
                .unwrap()
        }

        fn exists(&self, id: &str) -> bool {
            self.docker(&["container", "inspect", "--format", "{{.Id}}", id])
                .status
                .success()
        }

        fn label(&self, id: &str, key: &str) -> String {
            let out = self.docker(&[
                "container",
                "inspect",
                "--format",
                &format!("{{{{index .Config.Labels \"{key}\"}}}}"),
                id,
            ]);
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        }

        /// How many processes the container holds besides init.
        fn others(&self, container: &str) -> u32 {
            let out = self.docker(&["container", "exec", container, FIXTURE, "workload-ps"]);
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.strip_prefix("others="))
                .and_then(|n| n.trim().parse::<u32>().ok())
                .map_or(u32::MAX, |n| n.saturating_sub(1))
        }
    }

    struct Reaper {
        runtime: Runtime,
        stores: Mutex<Vec<String>>,
    }

    impl Drop for Reaper {
        fn drop(&mut self) {
            for store in self.stores.lock().unwrap().iter() {
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

    /// A real authority on a fresh store, a real broker, a workspace, a
    /// policy, an image manifest and the evidence's credentials.
    struct Lab {
        dir: TempDir,
        clock: Arc<ManualClock>,
        config: StartupConfig,
        broker_socket: PathBuf,
        broker: Broker,
        authority: Option<Authority>,
        sandbox: SandboxConfig,
        runtime: Runtime,
        reaper: Reaper,
        values: Values,
    }

    fn stop_at(point: CrashPoint) -> CrashHook {
        Arc::new(move |p| {
            if p == point {
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        })
    }

    impl Lab {
        fn new(tag: &str, policy_set: Option<PolicySet>) -> Self {
            let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
            let probe = var("DW_SANDBOX_PROBE_SHA256");
            let manifest = [
                (FIXTURE, fixture.as_str()),
                (TRUE, fixture.as_str()),
                (PROBE, probe.as_str()),
            ];
            let sandbox = SandboxConfig::new(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                &var("DW_SANDBOX_WORKLOAD_IMAGE"),
                &probe,
                NetworkTopology::NoNetwork,
                WorkspaceSetting::UnverifiedEvidence,
            )
            .unwrap()
            .with_workloads(&manifest, WorkloadBudget::default())
            .unwrap();
            let runtime = Runtime::load();
            let reaper = Reaper {
                runtime: runtime.clone(),
                stores: Mutex::new(Vec::new()),
            };
            let dir = TempDir::new(tag);
            let broker_socket = dir.path().join("broker").join("broker.sock");
            let broker = Broker::start(
                &broker_socket,
                own_uid(),
                &[
                    "--allow-shared-authority-uid",
                    "--allow-evidence-topology",
                    "--allow-unverified-workspace",
                ],
            );
            let workspace = dir.path().join("workspace");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o777)).unwrap();
            let mut ceiling = super::state_support::ceiling();
            for extra in ["process.exec:*", "fs.stat:*", "secret.use:*"] {
                ceiling.push(extra.to_owned());
            }
            let values = Values::new(tag);
            let mut config = StartupConfig::new(
                policy_set.unwrap_or_else(|| policy("m5d3", &secret_policy(&fixture))),
                Mode::Balanced,
                ceiling,
            );
            config.secrets = dwkd_authority::secret::metadata::parse(&values.secrets).unwrap();
            let mut lab = Self {
                dir,
                clock: Arc::new(ManualClock::new(START_MS)),
                config,
                broker_socket,
                broker,
                authority: None,
                sandbox,
                runtime,
                reaper,
                values,
            };
            lab.start(None);
            let authority = lab.authority();
            super::state_support::install_fixtures(authority);
            let mut operator = authority.operator();
            operator
                .install_agent_profile(&profile(
                    "operator",
                    &["process.exec:*", "fs.read:*", "fs.stat:*", "secret.use:*"],
                    &[],
                    PrivacyClass::Any,
                ))
                .unwrap();
            operator
                .install_workspace(
                    &WorkspaceId::new("ws").unwrap(),
                    WorkspaceSensitivity::Private,
                )
                .unwrap();
            operator
                .install_workspace_root(
                    &WorkspaceId::new("ws").unwrap(),
                    workspace.to_str().unwrap(),
                )
                .unwrap();
            lab
        }

        fn start(&mut self, hook: Option<CrashHook>) {
            self.authority = None;
            let link: Arc<dyn EffectBroker> =
                Arc::new(UnixBroker::new(self.broker_socket.clone(), own_uid()));
            let (authority, _) = {
                let _guard = spawn_guard();
                Authority::start(
                    &self.dir.state(),
                    &self.config,
                    StartOptions {
                        clock: self.clock.clone(),
                        crash_hook: hook,
                        broker: Some(link),
                    },
                )
                .expect("the authority starts")
            };
            self.authority = Some(authority);
            let config = self.sandbox.clone();
            self.authority().attach_sandbox(config).unwrap();
        }

        fn serve(&mut self) -> Served {
            let authority = self.authority.take().expect("an authority to serve");
            let socket = self.dir.path().join("ipc").join("kernel.sock");
            serve_authority(
                authority,
                &socket,
                PeerPolicy::new([own_uid()].into_iter().collect(), true),
                60_000,
            )
            .expect("the seam serves")
        }

        fn authority(&mut self) -> &mut Authority {
            self.authority.as_mut().unwrap()
        }

        fn reap(&self, container: &str) {
            let store = self.runtime.label(container, "io.direwolf.store");
            self.reaper.stores.lock().unwrap().push(store);
        }

        fn rows(&self, sql: &str) -> i64 {
            super::state_support::raw(&self.dir.state())
                .query_row(sql, [], |row| row.get(0))
                .unwrap()
        }

        fn one(&self, sql: &str) -> String {
            super::state_support::raw(&self.dir.state())
                .query_row(sql, [], |row| row.get(0))
                .unwrap()
        }

        fn container_of(&self, environment: &str) -> String {
            self.one(&format!(
                "SELECT container FROM environment WHERE environment_id = '{environment}'"
            ))
        }
    }

    static NEXT_MESSAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn next_message() -> u64 {
        NEXT_MESSAGE.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn tool_message(
        (session, run, epoch): (&SessionId, &RunId, Epoch),
        version: u8,
        schema: &str,
        key: Option<&str>,
        payload: &str,
    ) -> DwkpMessage {
        decode(&tool_json(
            (session, run, epoch),
            version,
            schema,
            key,
            payload,
        ))
    }

    fn tool_json(
        (session, run, epoch): (&SessionId, &RunId, Epoch),
        version: u8,
        schema: &str,
        key: Option<&str>,
        payload: &str,
    ) -> String {
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":{version},"ts":"2026-10-19T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
            id = id("msg", 95_000 + next_message()),
            session = session.as_str(),
            run = run.as_str(),
            epoch = epoch.get(),
            key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#)),
        )
    }

    /// A runtime: one DWKP connection, its session's lease, and one run.
    struct Peer {
        client: Client,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
    }

    impl Peer {
        fn admit(
            socket: &Path,
            n: u64,
            capabilities: &[&str],
            bind: impl FnOnce(SessionId),
        ) -> Self {
            let session = session(n);
            bind(session.clone());
            let mut client = Client::connect(socket);
            client.handshake();
            let granted = client.call(&acquire_msg(&session));
            let DwkpBody::LeaseGrant(lease) = granted.body else {
                panic!("a lease: {granted:?}")
            };
            let epoch = lease.epoch;
            let message = next_message();
            let admitted = client.call(&admit_msg(
                &session,
                epoch,
                &format!("admit-{n}-{message}"),
                "operator",
                &[],
                capabilities,
                message,
            ));
            let DwkpBody::RunGrant(grant) = admitted.body else {
                panic!("a run: {admitted:?}")
            };
            Self {
                client,
                session,
                epoch,
                run: grant.run_id,
            }
        }

        fn ids(&self) -> (&SessionId, &RunId, Epoch) {
            (&self.session, &self.run, self.epoch)
        }

        fn send(&mut self, schema: &str, key: Option<&str>, call: &str) {
            let message = tool_message(
                self.ids(),
                6,
                schema,
                key,
                &format!(r#"{{"process_exec":{call}}}"#),
            );
            self.client.send(&message);
        }

        fn exec(&mut self, key: &str, call: &str) -> DwkpBody {
            self.send("direwolf.tool.invoke", Some(key), call);
            self.client.recv(Duration::from_secs(240)).message().body
        }

        fn preview(&mut self, call: &str) -> DwkpBody {
            self.send("direwolf.tool.preview", None, call);
            self.client.recv(Duration::from_secs(60)).message().body
        }
    }

    fn launch(args: &[&str], handle: Option<&str>) -> String {
        let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        let credential =
            handle.map_or_else(String::new, |h| format!(r#","credential_handle":"{h}""#));
        format!(
            r#"{{"executable":"{FIXTURE}","args":[{}]{credential}}}"#,
            args.join(",")
        )
    }

    fn plan(body: &DwkpBody) -> &ToolPlanV6 {
        match body {
            DwkpBody::ToolResultV6(r) => &r.plan,
            DwkpBody::ToolDeniedV6(d) => &d.plan,
            DwkpBody::ToolPreviewedV6(p) => &p.plan,
            other => panic!("no version-6 plan: {other:?}"),
        }
    }

    fn injection(plan: &ToolPlanV6) -> Option<&PlannedSpawnInjectionAction> {
        plan.actions
            .as_slice()
            .iter()
            .find_map(|a| a.spawn_injection.as_ref())
    }

    fn output(body: &DwkpBody) -> &SandboxedExecResult {
        match body {
            DwkpBody::ToolResultV6(r) => r.output.process_exec_sandboxed.as_ref().unwrap(),
            other => panic!("not a sandboxed result: {other:?}"),
        }
    }

    fn stdout(body: &DwkpBody) -> String {
        String::from_utf8(output(body).stdout.content.to_bytes()).unwrap()
    }

    fn line<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {key} in the fixture's report"))
    }

    fn refusal(body: &DwkpBody) -> &'static str {
        match body {
            DwkpBody::ToolRefusedV6(r) => r.reason.as_str(),
            other => panic!("not refused: {other:?}"),
        }
    }

    fn binder(served: &Served) -> impl FnOnce(SessionId) + '_ {
        move |session| {
            served
                .operate(move |authority| {
                    authority
                        .operator()
                        .bind_session_workspace(&session, &WorkspaceId::new("ws").unwrap())
                        .unwrap();
                })
                .unwrap();
        }
    }

    const GRANTS: &[&str] = &[
        "process.exec:*",
        "secret.use:deploy-key",
        "secret.use:env-token",
    ];

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn the_public_route_delivers_a_credential_to_the_sandboxed_launch_and_never_to_the_runtime() {
        let mut lab = Lab::new("m5d3-public", None);
        let served = lab.serve();
        let mut a = Peer::admit(served.path(), 1, GRANTS, binder(&served));

        // Mode C: descriptor 3 of the image's executable, and nothing else.
        let body = a.exec("p-fd", &launch(&["workload-secret-fd"], Some(DEPLOY)));
        let plan_of = plan(&body);
        assert_eq!(plan_of.effect, DecisionEffect::Allow);
        let spawn = injection(plan_of).unwrap();
        assert_eq!(spawn.mode, SpawnInjection::FdAtSpawn);
        assert_eq!(spawn.decision.effect, DecisionEffect::Allow);
        evidence(
            "public-plan-states-both-actions",
            "workload+spawn_injection FD_AT_SPAWN",
            E2E,
            "authority-plan",
        );
        let out = stdout(&body);
        let container = lab.container_of(output(&body).environment_id.as_str());
        lab.reap(&container);
        assert_eq!(line(&out, "fd3"), "pipe");
        assert!(
            line(&out, "fnv") == fnv(&lab.values.deploy),
            "another value arrived"
        );
        assert_eq!(line(&out, "len"), lab.values.deploy.len().to_string());
        assert_eq!(line(&out, "stdin"), "/dev/null");
        assert_eq!(line(&out, "fds"), "0,1,2,3");
        evidence(
            "public-fd-at-spawn-delivered",
            "fd3=pipe, fingerprint matches",
            E2E,
            "trusted-launcher",
        );

        // Mode B: the operator's variable.
        let body = a.exec(
            "p-env",
            &launch(&["workload-secret-env", VARIABLE], Some(ENV_TOKEN)),
        );
        assert_eq!(
            injection(plan(&body)).unwrap().mode,
            SpawnInjection::EnvAtSpawn
        );
        let out = stdout(&body);
        assert_eq!(line(&out, "set"), "1");
        assert!(
            line(&out, "fnv") == fnv(&lab.values.env),
            "another value arrived"
        );
        evidence(
            "public-env-at-spawn-delivered",
            "GH_TOKEN set, fingerprint matches",
            E2E,
            "trusted-launcher",
        );

        // The return path: the value never reaches the runtime, even echoed
        // split across reads.
        let body = a.exec("p-echo", &launch(&["workload-echo-fd", "3"], Some(DEPLOY)));
        let result = output(&body);
        let (out, err) = (
            result.stdout.content.to_bytes(),
            result.stderr.content.to_bytes(),
        );
        assert!(!holds(&out, &lab.values.deploy) && !holds(&err, &lab.values.deploy));
        assert_eq!(
            String::from_utf8_lossy(&out).matches(PLACEHOLDER).count(),
            3
        );
        assert_eq!(
            String::from_utf8_lossy(&err).matches(PLACEHOLDER).count(),
            1
        );
        evidence(
            "public-echo-redacted",
            "4 placeholders, 0 bytes of the value",
            E2E,
            "output-redaction",
        );

        // Recorded, linked and counted; nothing durable holds a value.
        assert_eq!(
            lab.rows("SELECT count(*) FROM secret_injection WHERE state = 'INJECTED'"),
            3
        );
        assert_eq!(lab.rows("SELECT count(*) FROM workload_secret"), 3);
        assert_eq!(
            lab.rows("SELECT uses FROM secret_use WHERE handle = 'deploy-key'"),
            2
        );
        for value in [&lab.values.deploy, &lab.values.env] {
            assert!(
                !durable_holds(&lab.dir.state(), value),
                "a value is durable"
            );
            assert!(
                !holds(lab.broker.stderr().as_bytes(), value),
                "the broker logged a value"
            );
        }
        evidence(
            "public-no-plaintext-durable-or-logged",
            "absent",
            E2E,
            "secret-not-persisted",
        );
        assert_eq!(lab.broker.count("process_start"), 0, "a host launch");
        evidence(
            "public-never-on-the-host",
            "no host launch",
            E2E,
            "authority-environment-decision",
        );

        // Never twice, by any tool.
        let uses = lab.rows("SELECT count(*) FROM secret_injection");
        let again = a.exec("p-fd", &launch(&["workload-secret-fd"], Some(DEPLOY)));
        assert_eq!(refusal(&again), "IDEMPOTENCY_KEY_REUSED");
        assert_eq!(lab.rows("SELECT count(*) FROM secret_injection"), uses);
        evidence(
            "public-replay-refused",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-idempotency",
        );

        // A preview decides both actions and reads, records, runs nothing.
        let preview = a.preview(&launch(&["workload-secret-fd"], Some(DEPLOY)));
        assert!(
            matches!(preview, DwkpBody::ToolPreviewedV6(_)),
            "{preview:?}"
        );
        assert!(injection(plan(&preview)).is_some());
        assert_eq!(lab.rows("SELECT count(*) FROM secret_injection"), uses);
        evidence(
            "public-preview-reads-nothing",
            "no use recorded",
            E2E,
            "authority-plan",
        );

        // Not granted: denied by the capability gate, even though the run may
        // run the executable; nothing is read or recorded.
        let body = a.exec("p-spare", &launch(&["workload-secret-fd"], Some(SPARE)));
        assert!(matches!(body, DwkpBody::ToolDeniedV6(_)), "{body:?}");
        let spawn = injection(plan(&body)).unwrap();
        assert_eq!(spawn.decision.reason, ProcessDecisionReason::NoCapability);
        assert_eq!(lab.rows("SELECT count(*) FROM secret_injection"), uses);
        evidence(
            "public-ungranted-handle-denied",
            "NO_CAPABILITY",
            E2E,
            "authority-capability",
        );
        // Not configured: refused before either gate.
        let body = a.exec(
            "p-none",
            &launch(&["workload-secret-fd"], Some("never-configured")),
        );
        assert_eq!(refusal(&body), "CREDENTIAL_UNAVAILABLE");
        evidence(
            "public-unconfigured-handle-refused",
            "CREDENTIAL_UNAVAILABLE",
            E2E,
            "secret-metadata",
        );

        // The ordinary launch: one action at version 6, unchanged at 5.
        let body = a.exec("p-plain", &launch(&["workload-secret-fd"], None));
        assert_eq!(plan(&body).actions.as_slice().len(), 1);
        assert_eq!(line(&stdout(&body), "fd3"), "absent");
        let v5 = tool_message(
            a.ids(),
            5,
            "direwolf.tool.invoke",
            Some("p-v5"),
            &format!(
                r#"{{"process_exec":{}}}"#,
                launch(&["workload-secret-fd"], None)
            ),
        );
        let v5 = a.client.call(&v5).body;
        assert!(matches!(v5, DwkpBody::ToolResultV5(_)), "{v5:?}");
        evidence(
            "public-ordinary-launch-unchanged",
            "v6 one action; v5 result",
            E2E,
            "authority-route",
        );

        // What a runtime cannot say: a version-5 credential, a mode, a
        // variable or a value -- raw frames, refused by the server's decoder.
        for (case, version, call) in [
            ("v5-credential", 5, launch(&[], Some(DEPLOY))),
            (
                "v6-mode",
                6,
                launch(&[], Some(DEPLOY)).replacen('}', r#","injection_mode":"ENV_AT_SPAWN"}"#, 1),
            ),
            (
                "v6-variable",
                6,
                launch(&[], Some(DEPLOY)).replacen('}', r#","env_name":"GH_TOKEN"}"#, 1),
            ),
            (
                "v6-value",
                6,
                launch(&[], Some(DEPLOY)).replacen('}', r#","value":"hunter2"}"#, 1),
            ),
        ] {
            let json = tool_json(
                a.ids(),
                version,
                "direwolf.tool.invoke",
                Some(&format!("p-{case}")),
                &format!(r#"{{"process_exec":{call}}}"#),
            );
            let mut d = Client::connect(served.path());
            d.handshake();
            d.body(json.as_bytes()).unwrap();
            let message = d.recv(Duration::from_secs(10)).message();
            let DwkpBody::ProtocolError(error) = message.body else {
                panic!("{case}: {:?}", message.body)
            };
            assert_eq!(error.code, ErrorCode::SchemaViolation, "{case}");
        }
        assert_eq!(lab.rows("SELECT count(*) FROM secret_injection"), uses);
        evidence(
            "public-hostile-credential-frames-refused",
            "SCHEMA_VIOLATION",
            E2E,
            "dwkp-schema",
        );
        served.stop();
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn a_crash_in_a_credential_bearing_launch_leaves_it_unknown_and_its_environment_gone() {
        let mut lab = Lab::new("m5d3-crash", None);
        for (point, case, sleeping) in [
            (
                CrashPoint::SecretAfterHandoff,
                "crash-r6-after-handoff",
                false,
            ),
            (
                CrashPoint::SecretAfterBroker,
                "crash-r8-broker-running-it",
                true,
            ),
        ] {
            lab.start(Some(stop_at(point)));
            let n = next_message();
            let session_id = session(100 + n);
            let (caller, epoch, run) = admit_in_process(&mut lab, &session_id, n);
            let message = tool_message(
                (&session_id, &run, epoch),
                6,
                "direwolf.tool.invoke",
                Some(&format!("c-{n}")),
                &format!(
                    r#"{{"process_exec":{}}}"#,
                    launch(&["workload-sleep", "300"], Some(DEPLOY))
                ),
            );
            let result = lab.authority().dispatch(&caller, &message);
            assert!(result.is_err(), "{case}: stopped");
            let environment = lab.one(&format!(
                "SELECT environment_id FROM environment WHERE run_id = '{}'",
                run.as_str()
            ));
            let container = lab.container_of(&environment);
            lab.reap(&container);
            if sleeping {
                assert_eq!(lab.runtime.others(&container), 1, "{case}: running");
            } else {
                assert_eq!(lab.runtime.others(&container), 0, "{case}: nothing ran");
            }
            lab.start(None);
            let states = lab.one(&format!(
                "SELECT w.state || '/' || s.state FROM workload_secret ws \
                 JOIN workload w ON w.invocation_id = ws.workload_invocation_id \
                 JOIN secret_injection s ON s.invocation_id = ws.injection_invocation_id \
                 WHERE w.idempotency_key = 'c-{n}'"
            ));
            assert_eq!(states, "UNKNOWN/UNKNOWN", "{case}");
            assert!(
                !lab.runtime.exists(&container),
                "{case}: the restart destroyed it"
            );
            assert!(!durable_holds(&lab.dir.state(), &lab.values.deploy));
            evidence(
                case,
                "unknown/unknown, environment destroyed",
                OCI,
                "authority-reconciliation",
            );
        }
    }

    /// A run admitted in-process, for a test that stops the authority where a
    /// crash would.
    fn admit_in_process(
        lab: &mut Lab,
        session_id: &SessionId,
        n: u64,
    ) -> (CallerContext, Epoch, RunId) {
        let authority = lab.authority();
        authority
            .operator()
            .bind_session_workspace(session_id, &WorkspaceId::new("ws").unwrap())
            .unwrap();
        let caller = authority.connect(subject(1000));
        let Reply::Done(epoch) = authority.acquire_lease(&caller, session_id).unwrap() else {
            panic!("a lease")
        };
        let admitted = authority
            .admit_run(
                &caller,
                &admit_msg(
                    session_id,
                    epoch,
                    &format!("k{n}"),
                    "operator",
                    &[],
                    GRANTS,
                    n,
                ),
            )
            .unwrap();
        let Reply::Done(admission) = admitted else {
            panic!("admitted: {admitted:?}")
        };
        (caller, epoch, admission.run_id().clone())
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn the_shipped_packs_never_let_a_launch_use_a_credential() {
        for pack in ["safe", "balanced", "power"] {
            let mut lab = Lab::new(
                &format!("m5d3-{pack}"),
                Some(PolicySet::shipped(pack).unwrap()),
            );
            let served = lab.serve();
            let mut a = Peer::admit(served.path(), 1, GRANTS, binder(&served));
            let body = a.exec("k-1", &launch(&["workload-secret-fd"], Some(DEPLOY)));
            let plan = plan(&body);
            assert!(
                matches!(body, DwkpBody::ToolDeniedV6(_)),
                "{pack}: {body:?}"
            );
            let spawn = injection(plan).unwrap();
            assert_eq!(spawn.decision.effect, DecisionEffect::Deny, "{pack}");
            assert_eq!(
                lab.rows("SELECT count(*) FROM secret_injection"),
                0,
                "{pack}"
            );
            assert_eq!(lab.rows("SELECT count(*) FROM workload"), 0, "{pack}");
            evidence(
                &format!("shipped-{pack}-denies-a-launch-credential"),
                spawn.decision.reason.as_str(),
                E2E,
                "authority-policy",
            );
            served.stop();
        }
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-secret-evidence"]
    fn production_serve_delivers_a_credential_from_the_operators_files_and_survives_its_death() {
        let mut lab = Lab::new("m5d3-serve", None);
        let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        lab.authority()
            .operator()
            .bind_session_workspace(&session(1), &WorkspaceId::new("ws").unwrap())
            .unwrap();
        lab.authority = None;
        let private = |path: &Path, text: &str| {
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        let config = lab.dir.path().join("sandbox.toml");
        private(
            &config,
            &format!(
                "schema_version = 1\nruntime = \"{runtime}\"\nsocket = \"{socket}\"\n\
                 image = \"{image}\"\nprobe_sha256 = \"{probe}\"\nnetwork = \"NO_NETWORK\"\n\
                 [executables]\n\"{FIXTURE}\" = \"{fixture}\"\n\
                 [workspace]\nunverified_evidence = true\n",
                runtime = var("DW_SANDBOX_RUNTIME"),
                socket = var("DW_SANDBOX_SOCKET"),
                image = var("DW_SANDBOX_WORKLOAD_IMAGE"),
            ),
        );
        let secrets = lab.dir.path().join("secrets.toml");
        private(&secrets, &lab.values.secrets);
        let policy_file = lab.dir.path().join("m5d3.toml");
        std::fs::write(&policy_file, secret_policy(&fixture)).unwrap();
        let socket = lab.dir.path().join("ipc").join("kernel.sock");
        let args = |lab: &Lab| -> Vec<String> {
            let mut args: Vec<String> = [
                "serve",
                "--state-dir",
                lab.dir.state().to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--policy-file",
                policy_file.to_str().unwrap(),
                "--policy-profile",
                "m5d3",
                "--mode",
                "balanced",
                "--allow-uid",
                &own_uid().to_string(),
                "--allow-authority-uid",
                "--broker-socket",
                lab.broker_socket.to_str().unwrap(),
                "--broker-uid",
                &own_uid().to_string(),
                "--allow-shared-broker-uid",
                "--sandbox-config",
                config.to_str().unwrap(),
                "--secrets-file",
                secrets.to_str().unwrap(),
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            let mut ceiling = super::state_support::ceiling();
            ceiling.push("process.exec:*".to_owned());
            ceiling.push("secret.use:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            args
        };
        let mut server = Server::start(&args(&lab));
        let bind = |_: SessionId| {};
        let mut a = Peer::admit(&socket, 1, GRANTS, bind);
        let body = a.exec("s-1", &launch(&["workload-secret-fd"], Some(DEPLOY)));
        let out = stdout(&body);
        assert!(
            line(&out, "fnv") == fnv(&lab.values.deploy),
            "another value arrived"
        );
        assert_eq!(output(&body).residue, ResidueVerdict::Pass);
        let container = lab.container_of(output(&body).environment_id.as_str());
        lab.reap(&container);
        evidence(
            "production-serve-delivers-from-the-operators-files",
            "fingerprint matches",
            E2E,
            "secret-backend",
        );

        // W9 through the released binary, a credential handed over.
        a.send(
            "direwolf.tool.invoke",
            Some("s-2"),
            &launch(&["workload-sleep", "300"], Some(DEPLOY)),
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while lab.runtime.others(&container) < 1 {
            assert!(Instant::now() < deadline, "the workload never started");
            std::thread::sleep(Duration::from_millis(200));
        }
        server.kill();
        let _server = Server::start(&args(&lab));
        let states = lab.one(
            "SELECT w.state || '/' || s.state FROM workload_secret ws \
             JOIN workload w ON w.invocation_id = ws.workload_invocation_id \
             JOIN secret_injection s ON s.invocation_id = ws.injection_invocation_id \
             WHERE w.idempotency_key = 's-2'",
        );
        assert_eq!(states, "UNKNOWN/UNKNOWN");
        assert!(
            !lab.runtime.exists(&container),
            "the restart destroyed the environment"
        );
        evidence(
            "production-crash-mid-workload-unknown-destroyed",
            "unknown/unknown",
            E2E,
            "authority-reconciliation",
        );
        let mut b = Peer::admit(&socket, 1, GRANTS, bind);
        let body = b.exec("s-2", &launch(&["workload-secret-fd"], Some(DEPLOY)));
        assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
        assert_eq!(
            lab.rows("SELECT count(*) FROM secret_injection WHERE handle = 'deploy-key'"),
            2
        );
        evidence(
            "production-replay-after-restart-refused",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-idempotency",
        );
        assert!(!durable_holds(&lab.dir.state(), &lab.values.deploy));
        evidence(
            "production-no-plaintext-durable",
            "absent",
            E2E,
            "secret-not-persisted",
        );
    }
}
