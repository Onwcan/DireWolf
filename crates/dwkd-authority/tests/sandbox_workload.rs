//! M5d.1's workload evidence at the authority (ADR-0052 §§2, 4, 8–10, 17):
//! the **real** authority state (`kernel.db`, `audit.log`), the **released**
//! `dwkd-broker`, and a **real** OCI runtime — a workload decided by both
//! gates for a sandbox action, recorded before the broker hears of it, run in
//! the run's measured environment, and recorded again; its crash windows
//! exercised by stopping the authority where a crash would and starting a
//! new incarnation on the same files.
//!
//! Every test is `#[ignore]`d: it needs a runtime, the evidence image and the
//! pinned digests, which `make sandbox-workload-evidence` provides
//! (`DW_SANDBOX_*`). Run any other way it panics `NOT EXERCISED`.
//!
//! M5d.1's workload operation is an in-process authority API: this test
//! process calls it, exactly as the evidence harness does. M5d.2's public
//! route is reached the way a runtime reaches it: a real DWKP client on the
//! authority's socket — through the server seam that serves an authority
//! this test built (`serve_authority`), and through the released
//! `dwkd-authority serve --sandbox-config` binary itself. The policy is the
//! evidence's own operator policy unless a test names a shipped pack, which
//! it then says.

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
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::error::ErrorCode;
    use std::process::{Command, Output};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::sandbox::{NetworkTopology, Verdict};
    use dwk_proto::brokerp::workload::WorkloadEnding;
    use dwk_proto::wire::id::{EnvironmentId, RunId};
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::sandbox::{SandboxConfig, WorkloadBudget, WorkspaceSetting};
    use dwkd_authority::server::{PeerPolicy, Served, serve_authority};
    use dwkd_authority::state::{
        Authority, AuthorityError, CrashHook, CrashPoint, EnvironmentReply, EnvironmentState,
        HookAction, ManualClock, Mode, PolicySet, Reply, StartOptions, StartupConfig,
        WorkloadReply, WorkloadRequest, WorkloadState, WorkspaceId, WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::state_support::{
        START_MS, TempDir, acquire_msg, admit_msg, audit_events, decode, id, policy, profile,
        session, spawn_guard, subject,
    };
    use super::transport_support::{Client, own_uid};

    const SUITE: &str = "sandbox-authority-workload";
    /// What a line is (M5e.1): the real authority's own API over the
    /// released broker and a real runtime (`OCI`), or a real DWKP client on
    /// the authority's socket -- the seam's or the released `serve`'s --
    /// over the same (`E2E`).
    const OCI: &str = "real-oci";
    const E2E: &str = "dwkp-end-to-end";
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    const PROBE: &str = "/usr/libexec/direwolf/sandbox-probe";
    /// A manifest entry policy denies by default: it never reaches the broker.
    const DENIED: &str = "/usr/local/bin/denied-tool";
    /// The fixture again, at a path the host has too (OD-9).
    const TRUE: &str = "/usr/bin/true";

    /// One line of `suite`'s evidence, printed only after the assertions
    /// before it held: the case, how it ended, its level and what enforced
    /// or observed it (M5e.1, OD-E1) -- canonical JSON, so no outcome can
    /// break the line.
    fn evidence_line(suite: &str, case: &str, outcome: &str, level: &str, enforcement: &str) {
        use dwk_proto::json::{Object, Value, to_canonical_string};
        let mut fields = Object::new();
        for (key, value) in [
            ("suite", suite),
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

    fn evidence(case: &str, outcome: &str, level: &str, enforcement: &str) {
        evidence_line(SUITE, case, outcome, level, enforcement);
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-workload-evidence`, which \
                 builds the evidence image and pins its digests"
            )
        })
    }

    /// The evidence's operator policy: the fixture, by path and digest, in a
    /// sandbox; the probe in a sandbox only with an obligation no workload
    /// can keep (`network_deny`); nothing on the host; everything else
    /// denied. Concrete grants (OD-9) are the runs' own.
    fn workload_policy(fixture: &str) -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5d"

[[rule]]
id = "allow-the-fixture-in-a-sandbox"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{FIXTURE}@{fixture}"]
obligations = ["max_output_bytes=65536"]

[[rule]]
id = "the-fixture-at-a-host-path"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{TRUE}"]

[[rule]]
id = "the-probe-only-with-an-unkeepable-obligation"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{PROBE}"]
obligations = ["network_deny"]

[[rule]]
id = "stat-in-the-workspace"
effect = "ALLOW"
when.verb = "fs.stat"
when.path_under = "${{WORKSPACE}}"

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
"#
        )
    }

    /// The runtime client, as this test uses it directly: to look.
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

        /// How many processes the container holds besides init, as the
        /// fixture inside it counts them.
        fn others(&self, container: &str) -> u32 {
            let out = self.ok(&["container", "exec", container, FIXTURE, "workload-ps"]);
            out.lines()
                .find_map(|l| l.strip_prefix("others="))
                .and_then(|n| n.trim().parse::<u32>().ok())
                .map_or(u32::MAX, |n| n.saturating_sub(1))
        }

        /// Every process the container holds besides init and the census
        /// itself: `uid=<n> argv=<words>`, one line each.
        fn procs(&self, container: &str) -> Vec<String> {
            let out = self.ok(&["container", "exec", container, FIXTURE, "workload-procs"]);
            out.lines()
                .filter_map(|l| l.strip_prefix("proc "))
                .map(str::to_owned)
                .collect()
        }

        /// Wait, bounded, until the container holds `line` -- one process,
        /// by its uid and argument vector -- and return every other process
        /// it then held. A broker's start answer precedes the runtime's
        /// `exec` (the supervisor sends `go` with it, ADR-0052 §3): a census
        /// taken at once may run before the workload exists. Its argument
        /// vector being the target's proves the launcher reached `exec`.
        fn awaited(&self, container: &str, line: &str) -> Vec<String> {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let procs = self.procs(container);
                if procs.iter().any(|p| p == line) {
                    return procs;
                }
                assert!(
                    Instant::now() < deadline,
                    "{line:?} never ran; the container held {procs:?}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Everything a test had made, removed when it ends: every container
    /// labelled with its store.
    struct Reaper {
        runtime: Runtime,
        store: Mutex<Option<String>>,
    }

    impl Drop for Reaper {
        fn drop(&mut self) {
            if let Some(store) = self.store.lock().unwrap().clone() {
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

    /// A real authority on a fresh store, a real broker, a workspace, the
    /// evidence policy and an image manifest.
    struct Lab {
        dir: TempDir,
        clock: Arc<ManualClock>,
        config: StartupConfig,
        broker_socket: PathBuf,
        broker: Broker,
        authority: Option<Authority>,
        sandbox: SandboxConfig,
        workspace: PathBuf,
        next_session: u64,
        runtime: Runtime,
        reaper: Reaper,
        broker_flags: Vec<&'static str>,
    }

    /// Where a Lab's workspace is and under what contract (M5d.4, ADR-0052
    /// §6). The evidence's own unless a test says otherwise: a fresh
    /// world-writable directory under the unverified-evidence waiver, which
    /// its broker is started to allow.
    struct Provision {
        /// An operator-provisioned root, or `None`: a fresh scratch one.
        root: Option<PathBuf>,
        setting: WorkspaceSetting,
        /// The filesystem verbs too: a `maintainer` profile and a ceiling
        /// that write.
        writes: bool,
    }

    impl Provision {
        const fn evidence() -> Self {
            Self {
                root: None,
                setting: WorkspaceSetting::UnverifiedEvidence,
                writes: false,
            }
        }

        /// The broker's flags: the waiver only under the waiver's contract.
        fn broker_flags(&self) -> Vec<&'static str> {
            let mut flags = vec!["--allow-shared-authority-uid", "--allow-evidence-topology"];
            if self.setting == WorkspaceSetting::UnverifiedEvidence {
                flags.push("--allow-unverified-workspace");
            }
            flags
        }
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

    fn poisoned<T: std::fmt::Debug>(result: Result<T, AuthorityError>) {
        assert!(
            matches!(result, Err(AuthorityError::Poisoned(_))),
            "{result:?}"
        );
    }

    /// What a Lab is configured with: its policy, its image and that image's
    /// manifest, the workload budget.
    struct Custom {
        policy: PolicySet,
        image: String,
        manifest: Vec<(String, String)>,
        budget: WorkloadBudget,
    }

    impl Custom {
        /// The evidence's own: the workload image and the evidence policy.
        fn evidence(budget: WorkloadBudget) -> Self {
            let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
            Self {
                policy: policy("m5d", &workload_policy(&fixture)),
                image: var("DW_SANDBOX_WORKLOAD_IMAGE"),
                manifest: vec![
                    (FIXTURE.to_owned(), fixture.clone()),
                    (TRUE.to_owned(), fixture),
                    (PROBE.to_owned(), var("DW_SANDBOX_PROBE_SHA256")),
                    (DENIED.to_owned(), "d".repeat(64)),
                ],
                budget,
            }
        }
    }

    impl Lab {
        fn new(tag: &str, budget: WorkloadBudget) -> Self {
            Self::custom(tag, Custom::evidence(budget))
        }

        fn custom(tag: &str, custom: Custom) -> Self {
            Self::provisioned(tag, custom, Provision::evidence())
        }

        fn provisioned(tag: &str, custom: Custom, provision: Provision) -> Self {
            let probe = var("DW_SANDBOX_PROBE_SHA256");
            let manifest: Vec<(&str, &str)> = custom
                .manifest
                .iter()
                .map(|(path, sha)| (path.as_str(), sha.as_str()))
                .collect();
            let sandbox = SandboxConfig::new(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                &custom.image,
                &probe,
                NetworkTopology::NoNetwork,
                provision.setting,
            )
            .unwrap()
            .with_workloads(&manifest, custom.budget)
            .unwrap();
            let runtime = Runtime::load();
            let reaper = Reaper {
                runtime: runtime.clone(),
                store: Mutex::new(None),
            };
            let dir = TempDir::new(tag);
            let broker_socket = dir.path().join("broker").join("broker.sock");
            let broker_flags = provision.broker_flags();
            let broker = Broker::start(&broker_socket, own_uid(), &broker_flags);
            let workspace = provision.root.clone().unwrap_or_else(|| {
                let workspace = dir.path().join("workspace");
                std::fs::create_dir_all(&workspace).unwrap();
                // The environment's user writes the evidence's workspace;
                // the production ownership model is M5d.4's (ADR-0052 §6).
                std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o777))
                    .unwrap();
                workspace
            });
            let mut ceiling = super::state_support::ceiling();
            ceiling.push("process.exec:*".to_owned());
            ceiling.push("fs.stat:*".to_owned());
            if provision.writes {
                for verb in ["fs.list", "fs.write", "fs.create", "fs.delete"] {
                    ceiling.push(format!("{verb}:*"));
                }
            }
            let config = StartupConfig::new(custom.policy, Mode::Balanced, ceiling);
            let mut lab = Self {
                dir,
                clock: Arc::new(ManualClock::new(START_MS)),
                config,
                broker_socket,
                broker,
                authority: None,
                sandbox,
                workspace: workspace.clone(),
                next_session: 1,
                runtime,
                reaper,
                broker_flags,
            };
            lab.start(None);
            let authority = lab.authority();
            super::state_support::install_fixtures(authority);
            let mut operator = authority.operator();
            operator
                .install_agent_profile(&profile(
                    "operator",
                    &["process.exec:*", "fs.read:*", "fs.stat:*"],
                    &[],
                    PrivacyClass::Any,
                ))
                .unwrap();
            if provision.writes {
                operator
                    .install_agent_profile(&profile(
                        "maintainer",
                        &[
                            "process.exec:*",
                            "fs.read:*",
                            "fs.list:*",
                            "fs.stat:*",
                            "fs.write:*",
                            "fs.create:*",
                            "fs.delete:*",
                        ],
                        &[],
                        PrivacyClass::Any,
                    ))
                    .unwrap();
            }
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

        /// A new incarnation on the same files, with the sandbox attached.
        fn start(&mut self, hook: Option<CrashHook>) {
            self.start_detached(hook);
            let config = self.sandbox.clone();
            self.authority().attach_sandbox(config).unwrap();
        }

        /// A new incarnation with no sandbox attached yet: what its
        /// admissions resolve, they resolve on the host (OD-9).
        fn start_detached(&mut self, hook: Option<CrashHook>) {
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
        }

        /// Serve DWKP for this Lab's authority, as `serve` does for its own:
        /// the evidence's door to the public route.
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

        /// The store label of an environment's container, for the Reaper.
        fn reap_later(&self, container: &str) {
            let store = self.runtime.label(container, "io.direwolf.store");
            *self.reaper.store.lock().unwrap() = Some(store);
        }

        fn authority(&mut self) -> &mut Authority {
            self.authority.as_mut().unwrap()
        }

        /// A new active run under `profile`, requesting `capabilities`.
        fn admit(&mut self, profile: &str, capabilities: &[&str]) -> RunId {
            let n = self.next_session;
            self.next_session += 1;
            let authority = self.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &WorkspaceId::new("ws").unwrap())
                .unwrap();
            let caller = authority.connect(subject(1000));
            let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(n)).unwrap() else {
                panic!("a lease")
            };
            let admitted = authority
                .admit_run(
                    &caller,
                    &admit_msg(
                        &session(n),
                        epoch,
                        &format!("k{n}"),
                        profile,
                        &[],
                        capabilities,
                        n,
                    ),
                )
                .unwrap();
            let Reply::Done(admission) = admitted else {
                panic!("admitted: {admitted:?}")
            };
            admission.run_id().clone()
        }

        /// A run that may start workloads.
        fn operator_run(&mut self) -> RunId {
            self.admit("operator", &["process.exec:*"])
        }

        fn ready(&mut self, run: &RunId) -> (EnvironmentId, String) {
            match self.authority().environment_prepare(run).unwrap() {
                EnvironmentReply::Ready { report, .. } => {
                    let container = report.container.unwrap().as_str().to_owned();
                    let store = self.runtime.label(&container, "io.direwolf.store");
                    *self.reaper.store.lock().unwrap() = Some(store);
                    (report.environment, container)
                }
                other => panic!("not ready: {other:?}"),
            }
        }

        fn state_of(&mut self, environment: &EnvironmentId) -> EnvironmentState {
            self.authority()
                .environment_record(environment)
                .unwrap()
                .unwrap()
                .state
        }

        fn restart_broker(&mut self) {
            self.broker.kill();
            self.broker = Broker::start(&self.broker_socket, own_uid(), &self.broker_flags);
        }
    }

    fn request(executable: &str, args: &[&str], key: &str) -> WorkloadRequest {
        WorkloadRequest {
            executable: executable.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            stream_limit: 65_536,
            wall_clock_seconds: 60,
            key: key.to_owned(),
        }
    }

    fn fixture(args: &[&str], key: &str) -> WorkloadRequest {
        request(FIXTURE, args, key)
    }

    fn workload_rows(lab: &Lab) -> i64 {
        let conn = super::state_support::raw(&lab.dir.state());
        conn.query_row("SELECT count(*) FROM workload", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_workload_is_decided_recorded_run_in_its_environment_and_never_run_twice() {
        let mut lab = Lab::new("m5d-run", WorkloadBudget::default());
        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);

        let reply = lab
            .authority()
            .workload_run(&run, &fixture(&["workload-identity"], "w-1"))
            .unwrap();
        let WorkloadReply::Completed(outcome) = reply else {
            panic!("not completed: {reply:?}")
        };
        assert_eq!(outcome.ending, WorkloadEnding::Exited);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.environment, environment);
        let out = String::from_utf8(outcome.stdout.clone()).unwrap();
        assert!(out.contains("uid=10001"), "{out}");
        assert_eq!(outcome.residue, Verdict::Pass);
        assert!(!outcome.environment_destroyed);
        evidence(
            "authority-workload-completed",
            "exited-0-as-10001",
            OCI,
            "authority-route",
        );
        let record = lab
            .authority()
            .workload_record(&outcome.invocation)
            .unwrap()
            .unwrap();
        assert_eq!(record.state, WorkloadState::Completed);
        assert_eq!(record.ending.as_deref(), Some("EXITED"));
        assert_eq!(record.exit_code, Some(0));
        assert_eq!(record.residue.as_deref(), Some("PASS"));
        assert_eq!(record.environment, environment);
        evidence(
            "authority-workload-ledger-completed",
            "completed-exited-pass",
            OCI,
            "authority-ledger",
        );
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        evidence(
            "authority-workload-environment-kept-when-clean",
            "ready",
            OCI,
            "authority-environment-judgement",
        );

        // The intent is the authority's, durable before the broker heard: the
        // audit holds it, the decision and the outcome, never the output.
        let events = audit_events(&lab.dir.state());
        for event in [
            "workload.intent_recorded",
            "workload.outcome",
            "run.taint_raised",
        ] {
            assert!(events.iter().any(|e| e == event), "{event}: {events:?}");
        }
        let log = std::fs::read_to_string(lab.dir.state().join("audit.log")).unwrap();
        assert!(
            log.contains("\"environment\":\"sandbox\""),
            "a sandbox action"
        );
        assert!(!log.contains("uid=10001"), "output reached the audit");
        evidence(
            "authority-workload-audited",
            "intent-outcome-no-output",
            OCI,
            "authority-audit",
        );
        evidence(
            "authority-workload-taint-raised",
            "local-unverified",
            OCI,
            "authority-taint",
        );

        // The policy's `max_output_bytes=65536` is kept: each stream holds
        // its first half, whatever the request asked, and the intent is
        // charged at that bound.
        let reply = lab
            .authority()
            .workload_run(
                &run,
                &fixture(&["workload-print", "40000", "40000"], "w-out"),
            )
            .unwrap();
        let WorkloadReply::Completed(bounded) = reply else {
            panic!("not completed: {reply:?}")
        };
        assert_eq!(bounded.stdout.len(), 32_768);
        assert_eq!(bounded.stderr.len(), 32_768);
        assert!(bounded.truncated);
        let charged: i64 = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT stream_limit FROM workload WHERE invocation_id = ?1",
                [bounded.invocation.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(charged, 32_768);
        evidence(
            "authority-workload-obligation-output-bound",
            "32768-per-stream",
            OCI,
            "authority-obligation",
        );

        // The same key: the record, never a second run.
        let marker = lab.workspace.join("once");
        let first = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/once"], "w-mark"))
            .unwrap();
        assert!(matches!(first, WorkloadReply::Completed(_)), "{first:?}");
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();
        let again = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/once"], "w-mark"))
            .unwrap();
        let WorkloadReply::Replayed(replayed) = again else {
            panic!("not replayed: {again:?}")
        };
        assert_eq!(replayed.state, WorkloadState::Completed);
        assert!(!marker.exists(), "a replay ran the workload again");
        evidence(
            "authority-workload-replayed-never-rerun",
            "record-no-marker",
            OCI,
            "authority-idempotency",
        );
        // The same key for another workload: refused.
        let other = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/twice"], "w-mark"))
            .unwrap();
        assert_eq!(other, WorkloadReply::Refused("IDEMPOTENCY_KEY_REUSED"));
        assert!(!lab.workspace.join("twice").exists());
        evidence(
            "authority-workload-key-reused-differently-refused",
            "refused",
            OCI,
            "authority-idempotency",
        );
        assert!(lab.runtime.exists(&container));
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn every_gate_refuses_before_anything_runs() {
        let mut lab = Lab::new("m5d-gates", WorkloadBudget::default());
        let started = |lab: &Lab| {
            lab.broker
                .stderr()
                .matches("event=workload_started")
                .count()
        };

        // No environment: refused, never redirected to the host.
        let bare = lab.operator_run();
        let reply = lab
            .authority()
            .workload_run(&bare, &fixture(&["mark", "/workspace/bare"], "g-1"))
            .unwrap();
        assert_eq!(reply, WorkloadReply::Refused("NO_ENVIRONMENT"));
        evidence(
            "authority-workload-no-environment-refused",
            "refused",
            OCI,
            "authority-environment-decision",
        );
        assert!(!lab.workspace.join("bare").exists());
        assert_eq!(lab.broker.count("process_start"), 0);
        evidence(
            "authority-workload-never-on-the-host",
            "no-host-launch",
            OCI,
            "authority-environment-decision",
        );

        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);
        let refused = |lab: &mut Lab, request: WorkloadRequest| {
            lab.authority().workload_run(&run, &request).unwrap()
        };
        // Not in the image manifest.
        assert_eq!(
            refused(&mut lab, request("/usr/bin/sh", &[], "g-2")),
            WorkloadReply::Refused("EXECUTABLE_NOT_IN_MANIFEST")
        );
        evidence(
            "authority-workload-not-in-manifest-refused",
            "refused",
            OCI,
            "authority-image-manifest",
        );
        // Out of bounds.
        let mut too_long = fixture(&[], "g-3");
        too_long.wall_clock_seconds = 601;
        assert_eq!(
            refused(&mut lab, too_long),
            WorkloadReply::Refused("WALL_CLOCK_INVALID")
        );
        evidence(
            "authority-workload-bounds-refused",
            "wall-clock-invalid",
            OCI,
            "authority-request-bounds",
        );
        // Policy: a manifest entry no rule allows.
        assert_eq!(
            refused(&mut lab, request(DENIED, &[], "g-4")),
            WorkloadReply::Denied("DEFAULT_DENY")
        );
        evidence(
            "authority-workload-policy-denied",
            "default-deny",
            OCI,
            "authority-policy",
        );
        // An obligation no workload can keep (`network_deny`).
        assert_eq!(
            refused(&mut lab, request(PROBE, &["hold"], "g-5")),
            WorkloadReply::Denied("OBLIGATION_UNENFORCEABLE")
        );
        evidence(
            "authority-workload-obligation-unenforceable-denied",
            "denied",
            OCI,
            "authority-obligation",
        );
        // No capability: a run without `process.exec`.
        let plain = lab.admit("researcher", &["fs.read:*"]);
        lab.ready(&plain);
        let reply = lab
            .authority()
            .workload_run(&plain, &fixture(&["mark", "/workspace/nocap"], "g-6"))
            .unwrap();
        assert_eq!(reply, WorkloadReply::Denied("NO_CAPABILITY"));
        assert!(!lab.workspace.join("nocap").exists());
        evidence(
            "authority-workload-no-capability-denied",
            "denied",
            OCI,
            "authority-capability",
        );
        assert_eq!(
            started(&lab),
            0,
            "a refused or denied workload reached the broker"
        );
        assert_eq!(workload_rows(&lab), 0, "a refusal recorded an intent");
        evidence(
            "authority-workload-refusals-record-no-intent",
            "0-rows-0-runs",
            OCI,
            "authority-gates",
        );

        // The environment drifted after it was measured: the broker refuses
        // it, nothing runs, and the environment is destroyed.
        lab.runtime
            .ok(&["container", "update", "--pids-limit", "4096", &container]);
        let reply = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/drift"], "g-7"))
            .unwrap();
        let WorkloadReply::Failed {
            reason,
            environment_destroyed,
            ..
        } = reply
        else {
            panic!("not failed: {reply:?}")
        };
        assert_eq!(reason, "ENVIRONMENT_NOT_CLEAN");
        assert!(environment_destroyed);
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        assert!(!lab.workspace.join("drift").exists());
        evidence(
            "authority-workload-drifted-environment-destroyed",
            "failed-destroyed",
            OCI,
            "authority-environment-judgement",
        );
        // And a lower level is never accepted: no workload without a READY
        // environment at CONTAINER_ISOLATION (the only level `oci` earns).
        let reply = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/after"], "g-8"))
            .unwrap();
        assert_eq!(reply, WorkloadReply::Refused("NO_ENVIRONMENT"));
        evidence(
            "authority-workload-no-ready-environment-refused",
            "refused",
            OCI,
            "authority-environment-decision",
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn the_budget_is_charged_at_the_intent_and_never_refunded() {
        let mut lab = Lab::new(
            "m5d-budget",
            WorkloadBudget {
                workloads: 2,
                seconds: 120,
            },
        );
        let run = lab.operator_run();
        lab.ready(&run);
        let mut first = fixture(&["workload-exit", "0"], "b-1");
        first.wall_clock_seconds = 60;
        assert!(matches!(
            lab.authority().workload_run(&run, &first).unwrap(),
            WorkloadReply::Completed(_)
        ));
        // 60 of 120 seconds are spent though it ran for milliseconds.
        let mut second = fixture(&["workload-exit", "0"], "b-2");
        second.wall_clock_seconds = 61;
        assert_eq!(
            lab.authority().workload_run(&run, &second).unwrap(),
            WorkloadReply::Refused("BUDGET_EXHAUSTED")
        );
        evidence(
            "authority-workload-budget-seconds-charged-whole",
            "refused",
            OCI,
            "authority-run-budget",
        );
        second.wall_clock_seconds = 30;
        assert!(matches!(
            lab.authority().workload_run(&run, &second).unwrap(),
            WorkloadReply::Completed(_)
        ));
        // 90 of 120 seconds spent: ten more fit the seconds, not the count.
        let mut third = fixture(&["workload-exit", "0"], "b-3");
        third.wall_clock_seconds = 10;
        assert_eq!(
            lab.authority().workload_run(&run, &third).unwrap(),
            WorkloadReply::Refused("BUDGET_EXHAUSTED")
        );
        evidence(
            "authority-workload-budget-count-exhausted",
            "refused",
            OCI,
            "authority-run-budget",
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_crash_in_every_workload_window_leaves_it_unknown_and_never_run_again() {
        let mut lab = Lab::new("m5d-crash", WorkloadBudget::default());

        // W8: the intent is durable, the broker told nothing.
        lab.start(Some(stop_at(CrashPoint::WorkloadAfterIntent)));
        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);
        poisoned(
            lab.authority()
                .workload_run(&run, &fixture(&["mark", "/workspace/w8"], "c-8")),
        );
        assert!(!lab.workspace.join("w8").exists(), "W8 ran it");
        lab.start(None);
        let row: (String, String) = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state, failure FROM workload WHERE idempotency_key = 'c-8'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("UNKNOWN".to_owned(), "INTERRUPTED".to_owned()));
        evidence(
            "crash-w8-unknown",
            "interrupted",
            OCI,
            "authority-reconciliation",
        );
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence(
            "crash-w8-environment-destroyed",
            "destroyed-on-restart",
            OCI,
            "authority-reconciliation",
        );
        assert!(!lab.workspace.join("w8").exists());
        evidence(
            "crash-w8-never-ran",
            "no-marker",
            OCI,
            "authority-reconciliation",
        );

        // W9 (M5d.2): the broker started it and answered; the authority
        // died while it ran. Nothing proves how it ends: UNKNOWN, and the
        // environment's destruction is what ends it.
        lab.start(Some(stop_at(CrashPoint::WorkloadAfterStart)));
        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);
        poisoned(
            lab.authority()
                .workload_run(&run, &fixture(&["workload-sleep", "300"], "c-9")),
        );
        // The answer came first; the workload follows it. It is the target
        // itself -- the launcher reached its `exec` -- as the workload's
        // identity, and nothing else runs.
        let workload = format!("uid=10001 argv={FIXTURE} workload-sleep 300");
        let procs = lab.runtime.awaited(&container, &workload);
        assert_eq!(procs, [workload], "W9 is while it runs");
        assert_eq!(lab.runtime.others(&container), 1, "W9 is while it runs");
        evidence(
            "crash-w9-running-after-start",
            "target-as-workload",
            OCI,
            "runtime-process-list",
        );
        let environments = rows(&lab, "SELECT count(*) FROM environment");
        lab.start(None);
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'c-9'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence(
            "crash-w9-unknown-environment-destroyed",
            "unknown-destroyed",
            OCI,
            "authority-reconciliation",
        );
        // The same key again: its record, or the run's end -- never a second
        // execution, environment or container.
        let again = lab
            .authority()
            .workload_run(&run, &fixture(&["workload-sleep", "300"], "c-9"))
            .unwrap();
        match again {
            WorkloadReply::Replayed(replayed) => {
                assert_eq!(replayed.state, WorkloadState::Unknown);
            }
            WorkloadReply::Refused(reason) => assert_eq!(reason, "RUN_NOT_ACTIVE"),
            other => panic!("W9's key ran again: {other:?}"),
        }
        assert_eq!(
            rows(
                &lab,
                "SELECT count(*) FROM workload WHERE idempotency_key = 'c-9'"
            ),
            1
        );
        assert_eq!(rows(&lab, "SELECT count(*) FROM environment"), environments);
        evidence(
            "crash-w9-never-run-again",
            "no-second-execution",
            OCI,
            "authority-reconciliation",
        );

        // W10: the broker ran it and answered; the outcome is not durable.
        lab.start(Some(stop_at(CrashPoint::WorkloadAfterBroker)));
        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);
        poisoned(
            lab.authority()
                .workload_run(&run, &fixture(&["mark", "/workspace/w10"], "c-10")),
        );
        let marker = lab.workspace.join("w10");
        assert!(marker.exists(), "W10 is after the run");
        std::fs::remove_file(&marker).unwrap();
        lab.start(None);
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'c-10'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        evidence(
            "crash-w10-unknown-environment-destroyed",
            "unknown-destroyed",
            OCI,
            "authority-reconciliation",
        );
        assert!(!marker.exists(), "a restart ran it again");
        evidence(
            "crash-w10-never-rerun",
            "no-marker",
            OCI,
            "authority-reconciliation",
        );

        // W11: the outcome is durable; it stays.
        lab.start(Some(stop_at(CrashPoint::WorkloadAfterOutcome)));
        let run = lab.operator_run();
        let (environment, _) = lab.ready(&run);
        poisoned(
            lab.authority()
                .workload_run(&run, &fixture(&["workload-exit", "0"], "c-11")),
        );
        lab.start(None);
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'c-11'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "COMPLETED");
        // A clean residue left nothing for the outcome to destroy; the
        // restart reaped the run, and since the M5d closeout its environment
        // with it (ADR-0052 §8) -- the outcome is kept all the same.
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        evidence(
            "crash-w11-outcome-kept",
            "completed",
            OCI,
            "authority-reconciliation",
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn an_uncertain_ending_takes_its_environment_down() {
        let mut lab = Lab::new("m5d-unknown", WorkloadBudget::default());
        let run = lab.operator_run();
        let (environment, container) = lab.ready(&run);
        // The broker dies while the workload runs: the authority hears
        // nothing it can believe.
        let pid = lab.broker.pid;
        let runtime = lab.runtime.clone();
        let watched = container.clone();
        let killer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while runtime.others(&watched) < 1 {
                assert!(Instant::now() < deadline, "the workload never started");
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        });
        let reply = lab
            .authority()
            .workload_run(&run, &fixture(&["workload-sleep", "300"], "u-1"))
            .unwrap();
        killer.join().unwrap();
        let WorkloadReply::Unknown { reason, .. } = reply else {
            panic!("not unknown: {reply:?}")
        };
        evidence("unknown-ending-recorded", reason, OCI, "authority-ledger");
        // The workload outlived its broker; the destruction is durable and
        // completes once a broker answers.
        assert!(lab.runtime.exists(&container));
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroying);
        lab.restart_broker();
        let report = lab.authority().environment_reconcile().unwrap();
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence(
            "unknown-ending-environment-destroyed",
            "destroyed",
            OCI,
            "authority-reconciliation",
        );
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'u-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        evidence(
            "unknown-ending-never-rerun",
            "unknown",
            OCI,
            "authority-idempotency",
        );
    }

    // ---- M5d.2: the public route, over DWKP ---------------------------------

    static NEXT_MESSAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn next_message() -> u64 {
        NEXT_MESSAGE.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// A runtime: one DWKP connection, its session's lease, and one run.
    struct Peer {
        client: Client,
        session: dwk_proto::wire::id::SessionId,
        epoch: dwk_proto::wire::scalar::Epoch,
        run: RunId,
    }

    impl Peer {
        /// Connect to `socket`, lease session `n` and admit a run of
        /// `capabilities`. `bind` puts the session in the workspace first --
        /// trusted operator setup, in-process.
        fn admit(
            socket: &std::path::Path,
            n: u64,
            capabilities: &[&str],
            bind: impl FnOnce(dwk_proto::wire::id::SessionId),
        ) -> Self {
            Self::admit_as(socket, n, "operator", capabilities, bind)
        }

        /// [`Peer::admit`], under the agent profile `profile`.
        fn admit_as(
            socket: &std::path::Path,
            n: u64,
            profile: &str,
            capabilities: &[&str],
            bind: impl FnOnce(dwk_proto::wire::id::SessionId),
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
            // An admission key is spent for ever, even once its run ended
            // (ADR-0040): each admission has its own.
            let message = next_message();
            let admitted = client.call(&admit_msg(
                &session,
                epoch,
                &format!("admit-{n}-{message}"),
                profile,
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

        /// A tool message at `version`, in this peer's run.
        fn tool(&self, version: u8, schema: &str, key: Option<&str>, payload: &str) -> DwkpMessage {
            decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":{version},"ts":"2026-10-18T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
                id = id("msg", 90_000 + next_message()),
                session = self.session.as_str(),
                run = self.run.as_str(),
                epoch = self.epoch.get(),
                key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#)),
            ))
        }

        /// A version-5 `process.exec`, sent; its answer is read separately.
        fn send_exec(&mut self, key: &str, call: &str) {
            let message = self.tool(
                5,
                "direwolf.tool.invoke",
                Some(key),
                &format!(r#"{{"process_exec":{call}}}"#),
            );
            self.client.send(&message);
        }

        /// The answer to what was sent, within `wait`.
        fn answer(&mut self, wait: Duration) -> DwkpBody {
            self.client.recv(wait).message().body
        }

        /// A version-5 `process.exec`, and its answer.
        fn exec(&mut self, key: &str, call: &str) -> DwkpBody {
            self.send_exec(key, call);
            self.answer(Duration::from_secs(240))
        }
    }

    fn call(executable: &str, args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        format!(
            r#"{{"executable":"{executable}","args":[{}]}}"#,
            args.join(",")
        )
    }

    fn sandboxed(body: &DwkpBody) -> &dwk_proto::dwkp::sandboxops::SandboxedExecResult {
        match body {
            DwkpBody::ToolResultV5(result) => {
                result.output.process_exec_sandboxed.as_ref().unwrap()
            }
            other => panic!("not a sandboxed result: {other:?}"),
        }
    }

    fn plan_action(body: &DwkpBody) -> &dwk_proto::dwkp::sandboxops::PlannedWorkloadAction {
        let plan = match body {
            DwkpBody::ToolResultV5(r) => &r.plan,
            DwkpBody::ToolDeniedV5(d) => &d.plan,
            other => panic!("no plan: {other:?}"),
        };
        plan.actions.as_slice()[0].workload.as_ref().unwrap()
    }

    fn refusal(body: &DwkpBody) -> &'static str {
        match body {
            DwkpBody::ToolRefusedV5(r) => r.reason.as_str(),
            DwkpBody::ToolRefusedV4(r) => r.reason.as_str(),
            other => panic!("not refused: {other:?}"),
        }
    }

    fn binder(served: &Served) -> impl FnOnce(dwk_proto::wire::id::SessionId) + '_ {
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

    fn rows(lab: &Lab, sql: &str) -> i64 {
        let conn = super::state_support::raw(&lab.dir.state());
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn the_public_route_runs_process_exec_where_the_authority_decides() {
        let mut lab = Lab::new("m5d2-public", WorkloadBudget::default());
        let served = lab.serve();
        let mut a = Peer::admit(
            served.path(),
            1,
            &["process.exec:*", "fs.stat:*"],
            binder(&served),
        );
        let fixture = var("DW_SANDBOX_FIXTURE_SHA256");

        // The run has no environment: the authority prepares one, and the
        // launch runs there -- as the environment's user, the image's bytes.
        let since = Instant::now();
        let body = a.exec("p-1", &call(FIXTURE, &["workload-identity"]));
        let prepared_and_run = since.elapsed();
        let out = sandboxed(&body);
        let container: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [out.environment_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        lab.reap_later(&container);
        // How long a preparation holds the worker (ADR-0052 §2a), with the
        // launch: the measured cost, not a bound.
        evidence(
            "public-exec-environment-prepared-by-the-authority",
            &format!("ready-and-run-in-{}ms", prepared_and_run.as_millis()),
            E2E,
            "authority-environment-decision",
        );
        assert_eq!(
            out.assurance,
            dwk_proto::dwkp::sandboxops::ExecutionAssurance::ContainerIsolation
        );
        assert_eq!(
            out.executable.image.as_str(),
            var("DW_SANDBOX_WORKLOAD_IMAGE")
        );
        assert_eq!(out.executable.path.as_str(), FIXTURE);
        assert_eq!(out.executable.sha256.as_str(), fixture);
        assert_eq!(
            out.residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        assert!(!out.environment_destroyed);
        evidence(
            "public-exec-result-names-environment-assurance-identity",
            "container-isolation",
            E2E,
            "authority-environment-judgement",
        );
        let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert!(text.contains("uid=10001"), "{text}");
        assert_eq!(out.exit_code.map(|c| c.get()), Some(0));
        evidence(
            "public-exec-runs-as-the-sandbox-user",
            "uid-10001",
            E2E,
            "oci-user",
        );
        // Who asked is the kernel's word for the connection, in the intent.
        let intent =
            super::state_support::audit_records(&lab.dir.state(), "workload.intent_recorded");
        let last = intent.last().unwrap();
        assert_eq!(
            super::state_support::text(last, "subject"),
            Some(format!("uid:{}", own_uid()).as_str())
        );
        assert_eq!(super::state_support::int(last, "protocol_version"), Some(5));
        evidence(
            "public-exec-caller-from-the-transport",
            "uid",
            E2E,
            "kernel-process-credentials",
        );
        assert_eq!(lab.broker.count("process_start"), 0, "a host launch");
        evidence(
            "public-exec-never-on-the-host",
            "no-host-launch",
            E2E,
            "authority-environment-decision",
        );

        // Output is bounded by the call's own narrowing; every byte counted.
        let body = a.exec(
            "p-2",
            r#"{"executable":"/usr/libexec/direwolf/sandbox-fixture","args":["workload-print","5000","0"],"max_stream_bytes":1024}"#,
        );
        let out = sandboxed(&body);
        assert_eq!(out.stdout.content.to_bytes().len(), 1024);
        assert_eq!(out.stdout.observed.get(), 5000);
        assert!(out.stdout.truncated);
        evidence(
            "public-exec-output-bounded",
            "1024-of-5000",
            E2E,
            "output-bound",
        );
        // A daemonised grandchild is ended by the environment's init.
        let body = a.exec("p-3", &call(FIXTURE, &["workload-daemon"]));
        let out = sandboxed(&body);
        assert_eq!(
            out.residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        assert!(out.ended_processes.get() >= 1, "{out:?}");
        assert_eq!(lab.runtime.others(&container), 0);
        evidence(
            "public-exec-detached-child-reaped",
            "residue-pass",
            E2E,
            "environment-init-reap",
        );

        // While a long workload runs, the authority and the broker answer
        // everyone else: another runtime previews, stats a file and runs its
        // own workload in its own environment.
        a.send_exec(
            "p-long",
            r#"{"executable":"/usr/libexec/direwolf/sandbox-fixture","args":["workload-sleep","600"],"timeout_seconds":20}"#,
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while lab.runtime.others(&container) < 1 {
            assert!(Instant::now() < deadline, "the long workload never started");
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut b = Peer::admit(
            served.path(),
            2,
            &["process.exec:*", "fs.stat:*"],
            binder(&served),
        );
        let since = Instant::now();
        let preview = b.tool(
            5,
            "direwolf.tool.preview",
            None,
            &format!(
                r#"{{"process_exec":{}}}"#,
                call(FIXTURE, &["workload-identity"])
            ),
        );
        assert!(matches!(
            b.client.call(&preview).body,
            DwkpBody::ToolPreviewedV5(_)
        ));
        assert!(
            since.elapsed() < Duration::from_secs(5),
            "{:?}",
            since.elapsed()
        );
        evidence(
            "public-exec-authority-answers-during-a-workload",
            "preview",
            E2E,
            "authority-route",
        );
        // A file beneath the workspace's root (`/workspace/...` in the
        // tools' grammar): the broker stats it.
        std::fs::write(lab.workspace.join("stat-me"), b"x").unwrap();
        let since = Instant::now();
        let stat = b.tool(
            4,
            "direwolf.tool.invoke",
            Some("b-stat"),
            r#"{"fs_stat":{"path":"/workspace/stat-me"}}"#,
        );
        let stat = b.client.call(&stat).body;
        assert!(matches!(stat, DwkpBody::ToolResultV4(_)), "{stat:?}");
        assert!(
            since.elapsed() < Duration::from_secs(5),
            "{:?}",
            since.elapsed()
        );
        evidence(
            "public-exec-broker-answers-during-a-workload",
            "fs-stat",
            E2E,
            "broker-start-collect",
        );
        let body = b.exec("b-1", &call(FIXTURE, &["workload-identity"]));
        let other = sandboxed(&body);
        assert_ne!(other.environment_id.as_str(), container.as_str());
        evidence(
            "public-exec-two-runs-at-once-in-two-environments",
            "completed",
            E2E,
            "authority-environment-decision",
        );
        // The first run's key from another connection: that holder does not
        // hold the session, and nothing is decided for it.
        let mut c = Client::connect(served.path());
        c.handshake();
        let stolen = a.tool(
            5,
            "direwolf.tool.invoke",
            Some("p-long"),
            &format!(
                r#"{{"process_exec":{}}}"#,
                call(FIXTURE, &["workload-identity"])
            ),
        );
        assert_eq!(refusal(&c.call(&stolen).body), "STALE_EPOCH");
        evidence(
            "public-exec-key-from-another-holder-fenced",
            "STALE_EPOCH",
            E2E,
            "authority-lease-fence",
        );
        let long = a.answer(Duration::from_secs(120));
        let ended = sandboxed(&long);
        assert_eq!(
            ended.ending,
            dwk_proto::dwkp::sandboxops::SandboxEnding::TimedOut
        );
        assert_eq!(
            ended.residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        evidence(
            "public-exec-long-workload-timed-out-and-reaped",
            "timed-out",
            E2E,
            "broker-wall-clock",
        );

        // A key names one invocation, whatever tool asks and whenever.
        let before = rows(&lab, "SELECT count(*) FROM workload");
        let body = a.exec("p-1", &call(FIXTURE, &["mark", "/workspace/again"]));
        assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
        let stat = a.tool(
            4,
            "direwolf.tool.invoke",
            Some("p-1"),
            r#"{"fs_stat":{"path":"/workspace/stat-me"}}"#,
        );
        assert_eq!(
            refusal(&a.client.call(&stat).body),
            "IDEMPOTENCY_KEY_REUSED"
        );
        assert_eq!(rows(&lab, "SELECT count(*) FROM workload"), before);
        assert!(!lab.workspace.join("again").exists());
        evidence(
            "public-exec-key-never-runs-twice",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-idempotency",
        );
        evidence(
            "public-exec-cross-tool-key-refused",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-idempotency",
        );

        // Nothing a request can say moves it or reaches the lifecycle: a field
        // naming where it runs is no field of the call, and the environment's
        // lifecycle has no operation on the socket. Raw frames, refused by
        // the server's own decoder.
        let environments = rows(&lab, "SELECT count(*) FROM environment");
        let smuggled = format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-10-18T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"p-hostile","payload":{{"process_exec":{{"executable":"{FIXTURE}","args":[],"environment":"HOST"}}}}}}"#,
            id = id("msg", 99_000 + next_message()),
            session = a.session.as_str(),
            run = a.run.as_str(),
            epoch = a.epoch.get(),
        );
        let lifecycle = format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.environment.prepare","schema_version":1,"ts":"2026-10-18T10:00:00.000Z","payload":{{}}}}"#,
            id = id("msg", 99_000 + next_message()),
        );
        for (case, body, code) in [
            ("smuggled-environment", smuggled, ErrorCode::SchemaViolation),
            (
                "lifecycle-operation",
                lifecycle,
                ErrorCode::UnknownOperation,
            ),
        ] {
            let mut d = Client::connect(served.path());
            d.handshake();
            d.body(body.as_bytes()).unwrap();
            let message = d.recv(Duration::from_secs(10)).message();
            let DwkpBody::ProtocolError(error) = message.body else {
                panic!("{case}: {:?}", message.body)
            };
            assert_eq!(error.code, code, "{case}");
            assert!(d.recv(Duration::from_secs(10)).is_closed(), "{case}");
        }
        assert_eq!(rows(&lab, "SELECT count(*) FROM environment"), environments);
        evidence(
            "public-exec-smuggled-environment-refused",
            "SCHEMA_VIOLATION",
            E2E,
            "dwkp-schema",
        );
        evidence(
            "public-no-lifecycle-operation",
            "UNKNOWN_OPERATION",
            E2E,
            "dwkp-schema",
        );

        // An environment whose destruction is still pending is destroyed
        // before the authority next prepares one (ADR-0052 §2a). Since the
        // M5d closeout a lease's end records every reaped run's environment
        // DESTROYING and removes at most one at once (`release::`, `make
        // sandbox-release-evidence`): a second run in the session leaves one
        // pending for the reclamation.
        let first = a.run.clone();
        let n = next_message();
        let admitted = a
            .client
            .call(&super::state_support::admit_msg(
                &a.session,
                a.epoch,
                &format!("admit-1b-{n}"),
                "operator",
                &[],
                &["process.exec:*"],
                n,
            ))
            .body;
        let DwkpBody::RunGrant(grant) = admitted else {
            panic!("a second run: {admitted:?}")
        };
        a.run = grant.run_id;
        let body = a.exec("p-second", &call(FIXTURE, &["workload-identity"]));
        let second: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [sandboxed(&body).environment_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        a.run = first;
        let release = super::state_support::release_lease_msg(&a.session, a.epoch);
        let released = a.client.call(&release).body;
        assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
        let left: Vec<&String> = [&container, &second]
            .into_iter()
            .filter(|c| lab.runtime.exists(c))
            .collect();
        assert_eq!(left.len(), 1, "one removed at once, one pending: {left:?}");
        let mut c = Peer::admit(served.path(), 3, &["process.exec:*"], binder(&served));
        let body = c.exec("c-1", &call(FIXTURE, &["workload-identity"]));
        assert_eq!(
            sandboxed(&body).residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        assert!(
            !lab.runtime.exists(&container) && !lab.runtime.exists(&second),
            "the ended run's pending environment was reclaimed"
        );
        evidence(
            "public-exec-ended-runs-environment-reclaimed",
            "container-removed",
            E2E,
            "authority-reclamation",
        );
        served.stop();
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn an_uncertain_public_launch_is_unknown_and_takes_its_environment_down() {
        let mut lab = Lab::new("m5d2-unknown", WorkloadBudget::default());
        let served = lab.serve();
        let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
        let body = a.exec("u-0", &call(FIXTURE, &["workload-identity"]));
        let environment = sandboxed(&body).environment_id.clone();
        let container: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [environment.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        lab.reap_later(&container);
        a.send_exec("u-1", &call(FIXTURE, &["workload-sleep", "300"]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while lab.runtime.others(&container) < 1 {
            assert!(Instant::now() < deadline, "the workload never started");
            std::thread::sleep(Duration::from_millis(200));
        }
        // The broker dies while it runs: no collection can say how it ended.
        lab.broker.kill();
        let body = a.answer(Duration::from_secs(60));
        let DwkpBody::ToolFailedV5(failure) = &body else {
            panic!("not failed: {body:?}")
        };
        assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN");
        assert_eq!(failure.environment_destroyed, Some(true));
        assert_eq!(failure.environment_id.as_ref(), Some(&environment));
        evidence(
            "public-exec-unknown-outcome-reported",
            "OUTCOME_UNKNOWN",
            E2E,
            "authority-ledger",
        );
        // The workload outlived its broker; the destruction is durable and
        // completes when a broker answers again.
        assert!(lab.runtime.exists(&container));
        lab.restart_broker();
        let report = served
            .operate(|authority| authority.environment_reconcile().unwrap())
            .unwrap();
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert!(!lab.runtime.exists(&container));
        evidence(
            "public-exec-unknown-destroys-environment",
            "container-removed",
            E2E,
            "authority-reconciliation",
        );
        served.stop();
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn od9_a_concrete_grant_runs_only_the_manifests_bytes_in_the_image() {
        // Admitted with the environment configured: the grant is the
        // manifest's executable -- the fixture's bytes at /usr/bin/true in
        // the image, not the host's /usr/bin/true.
        let mut lab = Lab::new("m5d2-od9", WorkloadBudget::default());
        let served = lab.serve();
        let concrete = format!("process.exec:{TRUE}");
        let mut a = Peer::admit(served.path(), 1, &[&concrete], binder(&served));
        let body = a.exec("o-1", &call(TRUE, &["workload-identity"]));
        let out = sandboxed(&body);
        let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert!(
            text.contains("uid=10001"),
            "the image's executable ran: {text}"
        );
        assert_eq!(
            out.executable.sha256.as_str(),
            var("DW_SANDBOX_FIXTURE_SHA256")
        );
        let container: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [out.environment_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        lab.reap_later(&container);
        evidence(
            "od9-concrete-grant-runs-the-manifests-executable",
            "image-bytes",
            E2E,
            "authority-image-manifest",
        );
        // The grant covers that executable only.
        let body = a.exec("o-2", &call(FIXTURE, &["workload-identity"]));
        assert_eq!(plan_action(&body).decision.reason.as_str(), "NO_CAPABILITY");
        evidence(
            "od9-concrete-grant-covers-nothing-else",
            "NO_CAPABILITY",
            E2E,
            "authority-capability",
        );
        served.stop();

        // Admitted before any environment was configured: the same grant
        // means the host's file, whose digest is not the manifest's.
        let mut lab = Lab::new("m5d2-od9-host", WorkloadBudget::default());
        lab.start_detached(None);
        let host_run = {
            let n = 7;
            let authority = lab.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &WorkspaceId::new("ws").unwrap())
                .unwrap();
            let caller = authority.connect(subject(1000));
            let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(n)).unwrap() else {
                panic!("a lease")
            };
            let admitted = authority
                .admit_run(
                    &caller,
                    &admit_msg(
                        &session(n),
                        epoch,
                        "k-host",
                        "operator",
                        &[],
                        &[&concrete],
                        n,
                    ),
                )
                .unwrap();
            let Reply::Done(admission) = admitted else {
                panic!("admitted: {admitted:?}")
            };
            (caller, epoch, admission.run_id().clone())
        };
        let sandbox = lab.sandbox.clone();
        lab.authority().attach_sandbox(sandbox).unwrap();
        let (caller, epoch, run) = host_run;
        let message = decode(&format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-10-18T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"o-host","payload":{{"process_exec":{call}}}}}"#,
            id = id("msg", 95_000),
            session = session(7).as_str(),
            run = run.as_str(),
            epoch = epoch.get(),
            call = call(TRUE, &["workload-identity"]),
        ));
        let body = lab.authority().dispatch(&caller, &message).unwrap();
        assert_eq!(plan_action(&body).decision.reason.as_str(), "NO_CAPABILITY");
        assert_eq!(rows(&lab, "SELECT count(*) FROM workload"), 0);
        evidence(
            "od9-host-resolved-grant-covers-no-image-executable",
            "NO_CAPABILITY",
            OCI,
            "authority-capability",
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn a_public_launch_is_refused_by_its_budget_and_by_bytes_that_are_not_pinned() {
        let mut lab = Lab::new(
            "m5d2-budget",
            WorkloadBudget {
                workloads: 1,
                seconds: 600,
            },
        );
        let served = lab.serve();
        let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
        let body = a.exec("b-1", &call(FIXTURE, &["workload-exit", "0"]));
        let container: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [sandboxed(&body).environment_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        lab.reap_later(&container);
        let body = a.exec("b-2", &call(FIXTURE, &["mark", "/workspace/over"]));
        assert_eq!(refusal(&body), "BUDGET_EXHAUSTED");
        assert!(!lab.workspace.join("over").exists());
        evidence(
            "public-exec-budget-exhausted-refused",
            "BUDGET_EXHAUSTED",
            E2E,
            "authority-run-budget",
        );
        served.stop();

        // A manifest that pins other bytes than the image holds: the broker
        // proves the executable before anything runs, and refuses.
        let mut custom = Custom::evidence(WorkloadBudget::default());
        for (path, sha) in &mut custom.manifest {
            if path == FIXTURE {
                *sha = "e".repeat(64);
            }
        }
        let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
        custom.policy = policy(
            "m5d",
            &workload_policy(&fixture).replace(&format!("{FIXTURE}@{fixture}"), FIXTURE),
        );
        let mut lab = Lab::custom("m5d2-mismatch", custom);
        let served = lab.serve();
        let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
        let body = a.exec("m-1", &call(FIXTURE, &["mark", "/workspace/mismatch"]));
        let DwkpBody::ToolFailedV5(failure) = &body else {
            panic!("not failed: {body:?}")
        };
        assert_eq!(failure.reason.as_str(), "EXECUTABLE_CHANGED");
        assert!(!lab.workspace.join("mismatch").exists());
        let container: Option<String> = super::state_support::raw(&lab.dir.state())
            .query_row("SELECT container FROM environment LIMIT 1", [], |row| {
                row.get(0)
            })
            .ok();
        if let Some(container) = container {
            lab.reap_later(&container);
        }
        evidence(
            "public-exec-unpinned-image-bytes-refused",
            "EXECUTABLE_CHANGED",
            E2E,
            "executable-digest-pin",
        );
        served.stop();
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn the_shipped_packs_run_git_and_pytest_with_hygiene_kept_by_the_launcher() {
        let git = var("DW_SANDBOX_GIT_SHA256");
        let pytest = var("DW_SANDBOX_PYTEST_SHA256");
        for pack in ["balanced", "power"] {
            let custom = Custom {
                policy: PolicySet::shipped(pack).unwrap(),
                image: var("DW_SANDBOX_TOOLS_IMAGE"),
                manifest: vec![
                    ("/usr/bin/git".to_owned(), git.clone()),
                    ("/usr/local/bin/pytest".to_owned(), pytest.clone()),
                    ("/usr/bin/cargo".to_owned(), "c".repeat(64)),
                    (PROBE.to_owned(), var("DW_SANDBOX_PROBE_SHA256")),
                ],
                budget: WorkloadBudget::default(),
            };
            let mut lab = Lab::custom(&format!("m5d2-{pack}"), custom);
            let served = lab.serve();
            let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
            let body = a.exec(
                "g-1",
                &call("/usr/bin/git", &["init", "-q", "/workspace/repo"]),
            );
            let out = sandboxed(&body);
            assert_eq!(out.exit_code.map(|c| c.get()), Some(0), "{pack}: {out:?}");
            let action = plan_action(&body);
            assert_eq!(action.launch.as_str(), "HYGIENE", "{pack}");
            let container: String = super::state_support::raw(&lab.dir.state())
                .query_row(
                    "SELECT container FROM environment WHERE environment_id = ?1",
                    [out.environment_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            lab.reap_later(&container);
            let body = a.exec(
                "g-2",
                &call(
                    "/usr/bin/git",
                    &["-C", "/workspace/repo", "status", "--short"],
                ),
            );
            assert_eq!(
                sandboxed(&body).exit_code.map(|c| c.get()),
                Some(0),
                "{pack}"
            );
            evidence(
                &format!("shipped-{pack}-git-runs-with-hygiene"),
                "HYGIENE",
                E2E,
                "hygiene-launcher",
            );
            let body = a.exec("g-3", &call("/usr/local/bin/pytest", &["--version"]));
            let out = sandboxed(&body);
            assert_eq!(out.exit_code.map(|c| c.get()), Some(0), "{pack}: {out:?}");
            assert_eq!(
                plan_action(&body).arg_count.get(),
                3,
                "{pack}: the cache is off first"
            );
            evidence(
                &format!("shipped-{pack}-pytest-runs-with-its-cache-off"),
                "HYGIENE",
                E2E,
                "hygiene-launcher",
            );
            // Undone by its own arguments, or a tool with no evidence yet:
            // denied, and nothing runs.
            let before = rows(&lab, "SELECT count(*) FROM workload");
            for (key, executable, args) in [
                (
                    "g-4",
                    "/usr/local/bin/pytest",
                    &["-p", "cacheprovider", "--version"][..],
                ),
                ("g-5", "/usr/bin/cargo", &["build"]),
            ] {
                let body = a.exec(key, &call(executable, args));
                let DwkpBody::ToolDeniedV5(_) = &body else {
                    panic!("{pack} {executable}: not denied: {body:?}")
                };
                assert_eq!(
                    plan_action(&body).decision.reason.as_str(),
                    "OBLIGATION_UNENFORCEABLE",
                    "{pack} {executable}"
                );
            }
            assert_eq!(rows(&lab, "SELECT count(*) FROM workload"), before);
            evidence(
                &format!("shipped-{pack}-hygiene-undone-or-unevidenced-denied"),
                "OBLIGATION_UNENFORCEABLE",
                E2E,
                "authority-obligation",
            );
            served.stop();
        }
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-workload-evidence"]
    fn production_serve_prepares_its_own_environment_and_survives_its_own_death() {
        // The released binary, from the operator's file: no seam, no
        // in-process call -- only DWKP and `serve --sandbox-config`.
        let mut lab = Lab::new("m5d2-serve", WorkloadBudget::default());
        let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        lab.authority()
            .operator()
            .bind_session_workspace(&session(1), &WorkspaceId::new("ws").unwrap())
            .unwrap();
        lab.authority = None;
        let config = lab.dir.path().join("sandbox.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 1\nruntime = \"{runtime}\"\nsocket = \"{socket}\"\n\
                 image = \"{image}\"\nprobe_sha256 = \"{probe}\"\nnetwork = \"NO_NETWORK\"\n\
                 [executables]\n\"{FIXTURE}\" = \"{fixture}\"\n\
                 [workspace]\nunverified_evidence = true\n",
                runtime = var("DW_SANDBOX_RUNTIME"),
                socket = var("DW_SANDBOX_SOCKET"),
                image = var("DW_SANDBOX_WORKLOAD_IMAGE"),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policy_file = lab.dir.path().join("m5d.toml");
        std::fs::write(&policy_file, workload_policy(&fixture)).unwrap();
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
                "m5d",
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
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            let mut ceiling = super::state_support::ceiling();
            ceiling.push("process.exec:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            args
        };
        let mut server = super::transport_support::Server::start(&args(&lab));
        assert!(
            server
                .stderr()
                .contains("execution environment attached from"),
            "{}",
            server.stderr()
        );
        evidence(
            "production-serve-attaches-the-operators-environment",
            "attached",
            E2E,
            "authority-environment-decision",
        );
        let bind = |_: dwk_proto::wire::id::SessionId| {};
        let mut a = Peer::admit(&socket, 1, &["process.exec:*"], bind);
        let body = a.exec("s-1", &call(FIXTURE, &["workload-identity"]));
        let out = sandboxed(&body);
        let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert!(text.contains("uid=10001"), "{text}");
        let environment = out.environment_id.clone();
        let container: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT container FROM environment WHERE environment_id = ?1",
                [environment.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        lab.reap_later(&container);
        evidence(
            "production-serve-prepares-and-runs",
            "completed-as-10001",
            E2E,
            "authority-route",
        );

        // W9 through the released binary: killed while the broker runs it.
        a.send_exec("s-2", &call(FIXTURE, &["workload-sleep", "300"]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while lab.runtime.others(&container) < 1 {
            assert!(Instant::now() < deadline, "the workload never started");
            std::thread::sleep(Duration::from_millis(200));
        }
        server.kill();
        assert!(
            lab.runtime.exists(&container),
            "the runtime keeps an exec'd process"
        );
        // The next incarnation: the intent is UNKNOWN, the environment
        // destroyed, and the same key is never run again.
        let _server = super::transport_support::Server::start(&args(&lab));
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 's-2'",
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
            "production-crash-mid-workload-unknown-destroyed",
            "unknown-destroyed",
            E2E,
            "authority-reconciliation",
        );
        let mut b = Peer::admit(&socket, 1, &["process.exec:*"], bind);
        let body = b.exec("s-2", &call(FIXTURE, &["mark", "/workspace/rerun"]));
        assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
        assert!(!lab.workspace.join("rerun").exists());
        evidence(
            "production-replay-after-restart-refused",
            "IDEMPOTENCY_KEY_REUSED",
            E2E,
            "authority-idempotency",
        );
    }

    /// M5d.4 (ADR-0052 §§6, 10, 17; OD-3(a), OD-6): the workspace contract
    /// against the real authority, the released broker and a real runtime --
    /// `make sandbox-workspace-evidence` runs these by name.
    ///
    /// The cases an ordinary machine can run use the evidence's own scratch
    /// workspace, and say so. The others need what an operator provisions:
    /// the group `10001` with this process and the broker in it, filesystems
    /// of their own with a root of that group and mode `2770`, and `sudo` to
    /// change them. Only the hosted runner has those, made by the harness
    /// and undone after (`DW_WORKSPACE_PRIVILEGED=1`); anywhere else those
    /// cases panic NOT EXERCISED, which fails the task.
    mod workspace {
        use std::os::unix::fs::MetadataExt as _;
        use std::path::Path;

        use dwk_proto::brokerp::sandbox::{SandboxInvariant, WorkspaceQuota};
        use dwk_proto::wire::id::SessionId;
        use dwk_proto::wire::scalar::{Epoch, FsFailureReason, IdempotencyKey};
        use dwkd_authority::state::{CallerContext, EnvironmentReport, ToolReply, ToolRequest};

        use super::*;

        const WORKSPACE_SUITE: &str = "sandbox-authority-workspace";
        /// What a writing run asks for.
        const CAPABILITIES: &[&str] = &[
            "process.exec:*",
            "fs.read:/workspace",
            "fs.list:/workspace",
            "fs.stat:/workspace",
            "fs.write:/workspace",
            "fs.create:/workspace",
            "fs.delete:/workspace",
        ];
        const ENOSPC: &str = "28";
        /// The brokered write a full workspace must refuse, and then -- room
        /// made -- accept.
        const FULL_WRITE_BYTES: usize = 65_536;

        /// What a line is (M5e.1): `OCI` and `E2E` as the workloads' are --
        /// and, where it says `PRIV`, on a workspace only an
        /// operator-provisioned host has, which only
        /// `DW_WORKSPACE_PRIVILEGED=1` provisions.
        const PRIV: &str = "privileged-oci";

        fn evidence(case: &str, outcome: &str, level: &str, enforcement: &str) {
            evidence_line(WORKSPACE_SUITE, case, outcome, level, enforcement);
        }

        /// The evidence policy, with the workspace's reads and brokered
        /// changes allowed: an operator test policy, not a shipped pack.
        fn custom() -> Custom {
            let mut custom = Custom::evidence(WorkloadBudget::default());
            let marker = "[[rule]]\nid = \"never-on-the-host\"";
            let text = workload_policy(&var("DW_SANDBOX_FIXTURE_SHA256"));
            assert!(text.contains(marker));
            let text = text.replace(
                marker,
                &format!(
                    "[[rule]]\nid = \"observe-the-workspace\"\neffect = \"ALLOW\"\n\
                     when.verb = [\"fs.read\", \"fs.list\"]\n\
                     when.path_under = \"${{WORKSPACE}}\"\nwhen.max_bytes = 16777216\n\n\
                     [[rule]]\nid = \"change-the-workspace\"\neffect = \"ALLOW\"\n\
                     when.verb = [\"fs.write\", \"fs.create\", \"fs.delete\"]\n\
                     when.path_under = \"${{WORKSPACE}}\"\n\n{marker}"
                ),
            );
            custom.policy = policy("m5d", &text);
            custom
        }

        fn bounded(quota: u64) -> WorkspaceSetting {
            WorkspaceSetting::Bounded(WorkspaceQuota::new(quota).unwrap())
        }

        /// What the harness provisioned on the hosted runner.
        struct Provisioned {
            /// A `tmpfs` of the quota's size, its root this uid's, of group
            /// `10001`, mode `2770`, `nosuid,nodev`.
            tmpfs: PathBuf,
            /// Another, for another workspace.
            second: PathBuf,
            /// A loop-mounted `ext4` image of the quota's size, the same.
            ext4: PathBuf,
            /// A directory on the runner's own filesystem, provisioned as a
            /// root is but bounded by nothing of its own.
            unbounded: PathBuf,
            quota: u64,
            /// An identity outside the group.
            peer: String,
        }

        fn provisioned() -> Provisioned {
            assert!(
                std::env::var("DW_WORKSPACE_PRIVILEGED").as_deref() == Ok("1"),
                "NOT EXERCISED: this case needs an operator-provisioned workspace -- the \
                 group 10001, filesystems of their own, sudo -- which `make \
                 sandbox-workspace-evidence` provisions only where DW_WORKSPACE_PRIVILEGED=1 \
                 (the hosted runner)"
            );
            let root = |name: &str| {
                let path = PathBuf::from(var(name));
                emptied(&path);
                path
            };
            Provisioned {
                tmpfs: root("DW_WORKSPACE_TMPFS"),
                second: root("DW_WORKSPACE_SECOND"),
                ext4: root("DW_WORKSPACE_EXT4"),
                unbounded: root("DW_WORKSPACE_UNBOUNDED"),
                quota: var("DW_WORKSPACE_QUOTA").parse().unwrap(),
                peer: var("DW_WORKSPACE_PEER"),
            }
        }

        /// Remove what an earlier case left in a provisioned root: every
        /// entry is the group's to remove. An `ext4` root's `lost+found` is
        /// the filesystem's.
        fn emptied(root: &Path) {
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.file_name() == Some("lost+found".as_ref()) {
                    continue;
                }
                if path.is_dir() && !path.is_symlink() {
                    std::fs::remove_dir_all(&path).unwrap();
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
            }
        }

        fn sudo(args: &[&str]) -> Output {
            super::super::state_support::output(Command::new("sudo").arg("-n").args(args)).unwrap()
        }

        fn sudo_ok(args: &[&str]) {
            let out = sudo(args);
            assert!(
                out.status.success(),
                "sudo {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        /// Every container the runtime holds, by id.
        fn containers(runtime: &Runtime) -> Vec<String> {
            let mut ids: Vec<String> = runtime
                .ok(&["container", "ls", "--all", "--no-trunc", "--quiet"])
                .lines()
                .map(str::to_owned)
                .collect();
            ids.sort();
            ids
        }

        fn verdict(report: &EnvironmentReport, invariant: SandboxInvariant) -> Verdict {
            report
                .checks
                .iter()
                .find(|(i, _)| *i == invariant)
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("{invariant:?} was not reported"))
        }

        /// A writing run in workspace `workspace`, and what a tool call needs.
        struct Live {
            caller: CallerContext,
            session: SessionId,
            epoch: Epoch,
            run: RunId,
        }

        fn live(lab: &mut Lab, workspace: &str) -> Live {
            let n = lab.next_session;
            lab.next_session += 1;
            let authority = lab.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &WorkspaceId::new(workspace).unwrap())
                .unwrap();
            let caller = authority.connect(subject(1000));
            let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(n)).unwrap() else {
                panic!("a lease")
            };
            let admitted = authority
                .admit_run(
                    &caller,
                    &admit_msg(
                        &session(n),
                        epoch,
                        &format!("k{n}"),
                        "maintainer",
                        &[],
                        CAPABILITIES,
                        n,
                    ),
                )
                .unwrap();
            let Reply::Done(admission) = admitted else {
                panic!("admitted: {admitted:?}")
            };
            Live {
                caller,
                session: session(n),
                epoch,
                run: admission.run_id().clone(),
            }
        }

        /// A second workspace, `ws2`, bound to `root`.
        fn second_workspace(lab: &mut Lab, root: &Path) {
            let mut operator = lab.authority().operator();
            let id = WorkspaceId::new("ws2").unwrap();
            operator
                .install_workspace(&id, WorkspaceSensitivity::Private)
                .unwrap();
            operator
                .install_workspace_root(&id, root.to_str().unwrap())
                .unwrap();
        }

        /// A version-2 tool call in `l`'s run, in process.
        fn tool(lab: &mut Lab, l: &Live, payload: &str, key: &str) -> ToolReply {
            let text = format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":2,"ts":"2026-10-20T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"{key}","payload":{payload}}}"#,
                id = id("msg", 80_000 + next_message()),
                session = l.session.as_str(),
                run = l.run.as_str(),
                epoch = l.epoch.get(),
            );
            let DwkpBody::ToolInvokeV2(call) = decode(&text).body else {
                panic!("not a tool call: {text}")
            };
            let request = ToolRequest::v2(call, Some(IdempotencyKey::new(key).unwrap()));
            lab.authority()
                .tool_invoke(&l.caller, &l.session, &l.run, l.epoch, &request)
                .expect("the authority answers")
        }

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        fn write(path: &str, content: &[u8]) -> String {
            format!(
                r#"{{"fs_write":{{"path":"{path}","content":"{}"}}}}"#,
                hex(content)
            )
        }

        fn read(path: &str) -> String {
            format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":65536}}}}"#)
        }

        fn written(reply: &ToolReply) {
            assert!(
                matches!(reply, ToolReply::Done { output, .. } if output.fs_write.is_some()),
                "not written: {reply:?}"
            );
        }

        fn read_back(reply: &ToolReply) -> Vec<u8> {
            match reply {
                ToolReply::Done { output, .. } => {
                    output.fs_read.as_ref().unwrap().content.to_bytes()
                }
                other => panic!("not read: {other:?}"),
            }
        }

        fn failed(reply: &ToolReply) -> FsFailureReason {
            match reply {
                ToolReply::Failed { reason, .. } => *reason,
                other => panic!("not failed: {other:?}"),
            }
        }

        /// A workload's standard output, which must have completed.
        fn ran(lab: &mut Lab, run: &RunId, args: &[&str], key: &str) -> String {
            let reply = lab
                .authority()
                .workload_run(run, &fixture(args, key))
                .unwrap();
            let WorkloadReply::Completed(outcome) = reply else {
                panic!("not completed: {reply:?}")
            };
            String::from_utf8(outcome.stdout).unwrap()
        }

        fn field<'a>(text: &'a str, key: &str) -> &'a str {
            text.lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .unwrap_or_else(|| panic!("no {key} in:\n{text}"))
        }

        /// The broker's staging directories left in `root`.
        fn debris(root: &Path) -> Vec<PathBuf> {
            std::fs::read_dir(root)
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(".dwkd-"))
                })
                .collect()
        }

        /// Make `path` a directory the broker will change -- ADR-0044 §3
        /// refuses one every user may write, as the evidence's own is --
        /// that the workload may still write: this uid's, `0775` with uid
        /// 10001 named in its POSIX ACL, nobody else able to. The evidence's
        /// own stand-in, needing no privilege, for the group an operator
        /// provisions (§6); the unverified contract, said as such.
        fn shared_with_the_workload(path: &Path) {
            const UNDEFINED: u32 = u32::MAX;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            // ACL version 2: the owner rwx, uid 10001 rwx, the group r-x,
            // the mask rwx, others r-x.
            let mut blob = 2u32.to_le_bytes().to_vec();
            for (tag, permissions, id) in [
                (0x01_u16, 7_u16, UNDEFINED),
                (0x02, 7, 10_001),
                (0x04, 5, UNDEFINED),
                (0x10, 7, UNDEFINED),
                (0x20, 5, UNDEFINED),
            ] {
                blob.extend_from_slice(&tag.to_le_bytes());
                blob.extend_from_slice(&permissions.to_le_bytes());
                blob.extend_from_slice(&id.to_le_bytes());
            }
            rustix::fs::setxattr(
                path,
                "system.posix_acl_access",
                &blob,
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o7777, 0o775);
        }

        /// One text column of every row `sql` selects, for a diagnosis.
        fn states(state: &Path, sql: &str) -> Vec<String> {
            let conn = super::super::state_support::raw(state);
            let mut statement = conn.prepare(sql).unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }

        fn available(root: &Path) -> u64 {
            let stat = rustix::fs::statvfs(root).unwrap();
            stat.f_bavail * stat.f_frsize
        }

        // ---- what any machine can run -----------------------------------

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-workspace-evidence"]
        fn an_unprovisioned_workspace_is_refused_in_production_before_the_broker() {
            // Production's contract on the evidence's own directory: this
            // uid's, its own group, mode 0777 -- what an operator who
            // provisioned nothing has.
            let mut lab = Lab::provisioned(
                "m5d4-unprovisioned",
                custom(),
                Provision {
                    root: None,
                    setting: bounded(64 << 20),
                    writes: false,
                },
            );
            let before = containers(&lab.runtime);
            let run = lab.operator_run();
            let reply = lab.authority().environment_prepare(&run).unwrap();
            let EnvironmentReply::Failed { reason, report, .. } = reply else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_GROUP");
            assert!(report.is_none(), "nothing was measured");
            assert_eq!(containers(&lab.runtime), before, "no container was made");
            let intents = super::super::state_support::audit_records(
                &lab.dir.state(),
                "environment.intent_recorded",
            );
            let last = intents.last().unwrap();
            assert_eq!(
                super::super::state_support::text(last, "workspace_contract"),
                Some("BOUNDED")
            );
            assert_eq!(
                super::super::state_support::int(last, "workspace_quota_bytes"),
                Some(64 << 20)
            );
            evidence(
                "authority-unprovisioned-workspace-refused-before-the-broker",
                reason,
                OCI,
                "authority-workspace-contract",
            );
            // Nothing can run where no environment could be prepared.
            let reply = lab
                .authority()
                .workload_run(&run, &fixture(&["mark", "/workspace/never"], "u-1"))
                .unwrap();
            assert_eq!(reply, WorkloadReply::Refused("NO_ENVIRONMENT"));
            assert!(!lab.workspace.join("never").exists());
            evidence(
                "authority-unprovisioned-workspace-runs-nothing",
                "NO_ENVIRONMENT",
                OCI,
                "authority-environment-decision",
            );
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-workspace-evidence"]
        fn production_serve_refuses_a_workspace_it_cannot_bound() {
            // The released binary, from the operator's file, with a quota:
            // no waiver, no seam.
            let mut lab = Lab::provisioned(
                "m5d4-serve-unbounded",
                custom(),
                Provision {
                    root: None,
                    setting: bounded(64 << 20),
                    writes: false,
                },
            );
            lab.authority()
                .operator()
                .bind_session_workspace(&session(1), &WorkspaceId::new("ws").unwrap())
                .unwrap();
            lab.authority = None;
            let socket = lab.dir.path().join("ipc").join("kernel.sock");
            let mut server = super::super::transport_support::Server::start(&serve_args(
                &lab,
                &socket,
                "quota_bytes = 67108864",
            ));
            let stderr = server.stderr();
            assert!(
                stderr.contains("execution environment attached from"),
                "{stderr}"
            );
            // The evidence's shared uids are said; a waived workspace is not.
            assert!(!stderr.contains("unverified_evidence"), "{stderr}");
            let before = containers(&lab.runtime);
            let mut a = Peer::admit(&socket, 1, &["process.exec:*"], |_| {});
            let body = a.exec("p-1", &call(FIXTURE, &["mark", "/workspace/never"]));
            assert_eq!(refusal(&body), "ENVIRONMENT_UNAVAILABLE");
            assert_eq!(containers(&lab.runtime), before, "no container was made");
            assert!(!lab.workspace.join("never").exists());
            let failure: String = super::super::state_support::raw(&lab.dir.state())
                .query_row(
                    "SELECT failure FROM environment WHERE state = 'REFUSED'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(failure, "WORKSPACE_GROUP");
            evidence(
                "production-serve-unprovisioned-workspace-refused",
                "ENVIRONMENT_UNAVAILABLE",
                E2E,
                "authority-workspace-contract",
            );
            server.kill();
        }

        /// `serve --sandbox-config` for `lab`, its `[workspace]` table
        /// holding `workspace`.
        fn serve_args(lab: &Lab, socket: &Path, workspace: &str) -> Vec<String> {
            let config = lab.dir.path().join("sandbox.toml");
            std::fs::write(
                &config,
                format!(
                    "schema_version = 1\nruntime = \"{runtime}\"\nsocket = \"{runtime_socket}\"\n\
                     image = \"{image}\"\nprobe_sha256 = \"{probe}\"\nnetwork = \"NO_NETWORK\"\n\
                     [executables]\n\"{FIXTURE}\" = \"{fixture}\"\n\
                     [workspace]\n{workspace}\n",
                    runtime = var("DW_SANDBOX_RUNTIME"),
                    runtime_socket = var("DW_SANDBOX_SOCKET"),
                    image = var("DW_SANDBOX_WORKLOAD_IMAGE"),
                    probe = var("DW_SANDBOX_PROBE_SHA256"),
                    fixture = var("DW_SANDBOX_FIXTURE_SHA256"),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            let policy_file = lab.dir.path().join("m5d.toml");
            std::fs::write(
                &policy_file,
                workload_policy(&var("DW_SANDBOX_FIXTURE_SHA256")),
            )
            .unwrap();
            let mut args: Vec<String> = [
                "serve",
                "--state-dir",
                lab.dir.state().to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--policy-file",
                policy_file.to_str().unwrap(),
                "--policy-profile",
                "m5d",
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
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            let mut ceiling = super::super::state_support::ceiling();
            ceiling.push("process.exec:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            args
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-workspace-evidence"]
        fn what_a_workload_makes_takes_the_workspace_umask_and_stays_in_the_workspace() {
            // The evidence's own workspace (no group, no bound): what the
            // launcher sets, not what the root's group gives.
            let mut lab = Lab::new("m5d4-umask", WorkloadBudget::default());
            let run = lab.operator_run();
            let (_, container) = lab.ready(&run);
            let text = ran(&mut lab, &run, &["workload-make", "made"], "m-1");
            assert_eq!(field(&text, "umask"), "0007", "{text}");
            assert_eq!(field(&text, "file_mode"), "660", "{text}");
            assert_eq!(field(&text, "dir_mode"), "770", "{text}");
            assert_eq!(field(&text, "file_gid"), "10001", "{text}");
            let host = std::fs::metadata(lab.workspace.join("made.file")).unwrap();
            assert_eq!(
                (host.uid(), host.gid(), host.mode() & 0o7777),
                (10_001, 10_001, 0o660)
            );
            evidence(
                "umask-0007-through-the-direct-launcher",
                "file-660-dir-770",
                OCI,
                "direct-launcher",
            );
            // /tmp and /var/tmp are the environment's own, never the
            // workspace: nothing leaves it by name, and / is read-only.
            let text = ran(&mut lab, &run, &["workload-mounts"], "m-2");
            let size = |path: &str| field(&text, path).split('/').next().unwrap().to_owned();
            assert_ne!(size("/tmp"), size("/workspace"), "{text}");
            assert_ne!(size("/var/tmp"), size("/workspace"), "{text}");
            assert_eq!(field(&text, "root_write_errno"), "30", "EROFS: {text}");
            let text = ran(&mut lab, &run, &["workload-move-out", "made.file"], "m-3");
            for key in ["rename_tmp", "link_tmp", "link_var_tmp"] {
                assert_eq!(field(&text, key), "18", "EXDEV {key}: {text}");
            }
            assert!(lab.workspace.join("made.file").exists());
            evidence(
                "workspace-tmp-var-tmp-distinct",
                "exdev-erofs",
                OCI,
                "mount-namespace",
            );
            let _ = container;
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-workspace-evidence"]
        fn a_brokered_change_waits_while_a_workload_may_write_the_workspace() {
            let root = super::super::state_support::TempDir::new("m5d4-exclusion-ws");
            shared_with_the_workload(root.path());
            let mut lab = Lab::provisioned(
                "m5d4-exclusion",
                custom(),
                Provision {
                    root: Some(root.path().to_path_buf()),
                    setting: WorkspaceSetting::UnverifiedEvidence,
                    writes: true,
                },
            );
            let workspace = lab.workspace.clone();
            let runtime = lab.runtime.clone();
            let state = lab.dir.state();
            let served = lab.serve();
            let mut a = Peer::admit_as(
                served.path(),
                1,
                "maintainer",
                CAPABILITIES,
                binder(&served),
            );
            let body = a.exec("x-1", &call(FIXTURE, &["workload-identity"]));
            let environment = sandboxed(&body).environment_id.clone();
            let container: String = super::super::state_support::raw(&state)
                .query_row(
                    "SELECT container FROM environment WHERE environment_id = ?1",
                    [environment.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            lab.reap_later(&container);
            a.send_exec("x-2", &call(FIXTURE, &["workload-sleep", "8"]));
            runtime.awaited(
                &container,
                &format!("uid=10001 argv={FIXTURE} workload-sleep 8"),
            );
            // Another run, the same workspace: no name changes while the
            // workload may write it.
            let mut b = Peer::admit_as(
                served.path(),
                2,
                "maintainer",
                CAPABILITIES,
                binder(&served),
            );
            let message = b.tool(
                2,
                "direwolf.tool.invoke",
                Some("w-1"),
                &write("/workspace/while", b"x"),
            );
            let body = b.client.call(&message).body;
            let DwkpBody::ToolFailedV2(failure) = &body else {
                panic!("not failed: {body:?}")
            };
            assert_eq!(failure.reason.as_str(), "SHARED_DIRECTORY");
            assert!(!workspace.join("while").exists());
            // The authority's exclusion, not the broker's refusal: said so,
            // and the broker never asked.
            let failed = super::super::state_support::audit_records(&state, "tool.failed");
            let excluded: Vec<_> = failed
                .iter()
                .filter(|r| {
                    super::super::state_support::text(r, "excluded_by")
                        == Some("WORKLOAD_IN_WORKSPACE")
                })
                .collect();
            assert_eq!(excluded.len(), 1, "{failed:?}");
            assert!(debris(&workspace).is_empty());
            evidence(
                "exclusion-while-a-workload-runs",
                "SHARED_DIRECTORY",
                E2E,
                "authority-workspace-exclusion",
            );
            // Ended, and proved quiet by `reap`: the change is made.
            let answer = a.answer(Duration::from_secs(120));
            assert!(matches!(answer, DwkpBody::ToolResultV5(_)), "{answer:?}");
            let message = b.tool(
                2,
                "direwolf.tool.invoke",
                Some("w-2"),
                &write("/workspace/after", b"y"),
            );
            let body = b.client.call(&message).body;
            assert!(
                matches!(body, DwkpBody::ToolResultV2(_)),
                "{body:?}; workloads {:?}, environments {:?}",
                states(
                    &state,
                    "SELECT idempotency_key || ':' || state FROM workload"
                ),
                states(&state, "SELECT run_id || ':' || state FROM environment"),
            );
            assert_eq!(std::fs::read(workspace.join("after")).unwrap(), b"y");
            evidence(
                "exclusion-lifted-when-the-workload-ended",
                "written",
                E2E,
                "authority-workspace-exclusion",
            );
            served.stop();
        }

        // ---- what an operator provisions --------------------------------

        #[test]
        #[ignore = "needs a provisioned workspace: make sandbox-workspace-evidence"]
        fn a_bounded_workspace_is_shared_by_its_group_and_nobody_else() {
            let p = provisioned();
            let mut lab = Lab::provisioned(
                "m5d4-shared",
                custom(),
                Provision {
                    root: Some(p.tmpfs.clone()),
                    setting: bounded(p.quota),
                    writes: true,
                },
            );
            let l = live(&mut lab, "ws");
            let reply = lab.authority().environment_prepare(&l.run).unwrap();
            let EnvironmentReply::Ready { report, .. } = reply else {
                panic!("not ready: {reply:?}")
            };
            lab.reap_later(report.container.as_ref().unwrap().as_str());
            for invariant in [
                SandboxInvariant::HostWorkspaceIdentity,
                SandboxInvariant::HostWorkspaceOwnership,
                SandboxInvariant::HostWorkspaceCapacity,
                SandboxInvariant::ContainerWorkspaceGroupInherited,
            ] {
                assert_eq!(verdict(&report, invariant), Verdict::Pass, "{invariant:?}");
            }
            evidence(
                "bounded-tmpfs-accepted",
                "ready",
                PRIV,
                "workspace-contract-measured",
            );
            evidence(
                "host-and-container-identity-agree",
                "pass",
                PRIV,
                "workspace-contract-measured",
            );
            // The workload makes; the broker reads.
            let text = ran(&mut lab, &l.run, &["workload-make", "w"], "s-1");
            assert_eq!(field(&text, "file_mode"), "660", "{text}");
            assert_eq!(field(&text, "file_gid"), "10001", "{text}");
            assert_eq!(field(&text, "dir_mode"), "2770", "{text}");
            assert_eq!(field(&text, "dir_gid"), "10001", "{text}");
            let text = ran(
                &mut lab,
                &l.run,
                &["workload-modify", "/workspace/w.file", "from-the-workload"],
                "s-2",
            );
            assert_eq!(field(&text, "modified"), "17", "{text}");
            let reply = tool(&mut lab, &l, &read("/workspace/w.file"), "r-1");
            assert_eq!(read_back(&reply), b"from-the-workload");
            evidence(
                "workload-makes-broker-reads",
                "read",
                PRIV,
                "workspace-group-10001",
            );
            // The broker makes; the workload changes it in place.
            written(&tool(
                &mut lab,
                &l,
                &write("/workspace/b.txt", b"from-the-broker"),
                "w-1",
            ));
            let made = std::fs::metadata(p.tmpfs.join("b.txt")).unwrap();
            assert_eq!((made.gid(), made.mode() & 0o7777), (10_001, 0o660));
            let text = ran(
                &mut lab,
                &l.run,
                &["workload-modify", "/workspace/b.txt", "+changed"],
                "s-3",
            );
            assert_eq!(field(&text, "modified"), "8", "{text}");
            let reply = tool(&mut lab, &l, &read("/workspace/b.txt"), "r-2");
            assert_eq!(read_back(&reply), b"from-the-broker+changed");
            evidence(
                "broker-makes-workload-modifies",
                "modified",
                PRIV,
                "workspace-group-10001",
            );
            // The broker replaces what the workload made, keeping its mode
            // and group, and the workload reads the replacement.
            written(&tool(
                &mut lab,
                &l,
                &write("/workspace/w.file", b"replaced"),
                "w-2",
            ));
            let text = ran(
                &mut lab,
                &l.run,
                &["workload-read", "/workspace/w.file"],
                "s-4",
            );
            assert_eq!(field(&text, "content"), hex(b"replaced"), "{text}");
            evidence(
                "broker-replaces-workload-reads",
                "replaced",
                PRIV,
                "workspace-group-10001",
            );
            // Nobody outside the group: not to write, not to read.
            let denied = sudo(&[
                "-u",
                &p.peer,
                "touch",
                p.tmpfs.join("intruder").to_str().unwrap(),
            ]);
            assert!(!denied.status.success());
            assert!(!p.tmpfs.join("intruder").exists());
            let denied = sudo(&[
                "-u",
                &p.peer,
                "cat",
                p.tmpfs.join("b.txt").to_str().unwrap(),
            ]);
            assert!(!denied.status.success());
            assert!(denied.stdout.is_empty());
            evidence(
                "another-identity-cannot-write-or-read",
                "denied",
                PRIV,
                "workspace-root-2770",
            );
        }

        #[test]
        #[ignore = "needs a provisioned workspace: make sandbox-workspace-evidence"]
        fn a_root_not_as_the_contract_says_is_refused_and_never_repaired() {
            let p = provisioned();
            let root = p.tmpfs.to_str().unwrap().to_owned();
            let mut lab = Lab::provisioned(
                "m5d4-unsafe",
                custom(),
                Provision {
                    root: Some(p.tmpfs.clone()),
                    setting: bounded(p.quota),
                    writes: false,
                },
            );
            let own_gid = std::fs::metadata("/proc/self").unwrap().gid().to_string();
            let owner = std::fs::metadata(&p.tmpfs).unwrap().uid().to_string();
            let restore = || {
                sudo_ok(&["chown", &format!("{owner}:10001"), &root]);
                sudo_ok(&["chmod", "2770", &root]);
            };
            let before = containers(&lab.runtime);
            for (change, expected, case) in [
                (
                    vec!["chgrp", own_gid.as_str(), root.as_str()],
                    "WORKSPACE_GROUP",
                    "wrong-gid-refused",
                ),
                (
                    vec!["chmod", "g-s", root.as_str()],
                    "WORKSPACE_MODE",
                    "missing-setgid-refused",
                ),
                (
                    vec!["chmod", "2775", root.as_str()],
                    "WORKSPACE_MODE",
                    "group-only-mode-world-readable-refused",
                ),
                (
                    vec!["chmod", "2777", root.as_str()],
                    "WORKSPACE_MODE",
                    "world-writable-root-refused",
                ),
                (
                    vec!["chown", "10001", root.as_str()],
                    "WORKSPACE_OWNER",
                    "workload-owned-root-refused",
                ),
                (
                    vec!["chown", "65534", root.as_str()],
                    "WORKSPACE_OWNER",
                    "foreign-owned-root-refused",
                ),
            ] {
                sudo_ok(&change);
                let mode = std::fs::metadata(&p.tmpfs).unwrap().mode() & 0o7777;
                let run = lab.operator_run();
                let reply = lab.authority().environment_prepare(&run).unwrap();
                let EnvironmentReply::Failed { reason, .. } = reply else {
                    panic!("{case}: not refused: {reply:?}")
                };
                assert_eq!(reason, expected, "{case}");
                // Refused, not repaired: the root is as it was made.
                assert_eq!(
                    std::fs::metadata(&p.tmpfs).unwrap().mode() & 0o7777,
                    mode,
                    "{case}"
                );
                assert_eq!(containers(&lab.runtime), before, "{case}: no container");
                // No container was made: the authority's own check of the
                // root it pinned refused it.
                evidence(case, expected, PRIV, "authority-workspace-contract");
                restore();
            }
            // An authority bounded at twice the filesystem: refused too.
            let mut lab = Lab::provisioned(
                "m5d4-mismatch",
                custom(),
                Provision {
                    root: Some(p.tmpfs.clone()),
                    setting: bounded(p.quota * 2),
                    writes: false,
                },
            );
            let run = lab.operator_run();
            let reply = lab.authority().environment_prepare(&run).unwrap();
            let EnvironmentReply::Failed { reason, .. } = reply else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_QUOTA_MISMATCH");
            evidence(
                "quota-mismatch-refused",
                reason,
                PRIV,
                "authority-workspace-contract",
            );
            // A root provisioned as the contract says, on the host's own
            // filesystem: bounded by nothing of its own.
            let mut lab = Lab::provisioned(
                "m5d4-unbounded",
                custom(),
                Provision {
                    root: Some(p.unbounded.clone()),
                    setting: bounded(p.quota),
                    writes: false,
                },
            );
            let run = lab.operator_run();
            let reply = lab.authority().environment_prepare(&run).unwrap();
            let EnvironmentReply::Failed { reason, .. } = reply else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_UNBOUNDED");
            assert_eq!(containers(&lab.runtime), before);
            evidence(
                "unbounded-host-directory-refused",
                reason,
                PRIV,
                "authority-workspace-contract",
            );
            // A directory inside a bounded filesystem, provisioned as a root
            // is: the authority's own count is the filesystem's and within
            // the quota, but the mount is not the filesystem's root -- two
            // such workspaces would share one bound. The probe's mount root
            // refuses it, and the container is removed.
            let inner = p.tmpfs.join("inner");
            std::fs::create_dir(&inner).unwrap();
            std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o2770)).unwrap();
            let mut lab = Lab::provisioned(
                "m5d4-inner",
                custom(),
                Provision {
                    root: Some(inner.clone()),
                    setting: bounded(p.quota),
                    writes: false,
                },
            );
            let run = lab.operator_run();
            let reply = lab.authority().environment_prepare(&run).unwrap();
            let EnvironmentReply::Failed { reason, report, .. } = reply else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_UNBOUNDED");
            let report = report.expect("the broker measured it");
            assert_eq!(
                verdict(&report, SandboxInvariant::HostWorkspaceCapacity),
                Verdict::Fail
            );
            assert_eq!(
                containers(&lab.runtime),
                before,
                "its container was removed"
            );
            evidence(
                "subdirectory-of-a-bounded-filesystem-refused",
                reason,
                PRIV,
                "workspace-contract-measured",
            );
        }

        #[test]
        #[ignore = "needs a provisioned workspace: make sandbox-workspace-evidence"]
        fn a_workspace_changed_under_a_ready_environment_takes_it_down_first() {
            let p = provisioned();
            let root = p.tmpfs.to_str().unwrap().to_owned();
            let mut lab = Lab::provisioned(
                "m5d4-drift",
                custom(),
                Provision {
                    root: Some(p.tmpfs.clone()),
                    setting: bounded(p.quota),
                    writes: false,
                },
            );
            let size = format!("size={}", p.quota);
            let twice = format!("size={}", p.quota * 2);
            // The filesystem grown under a ready environment.
            let run = lab.operator_run();
            let (environment, container) = lab.ready(&run);
            sudo_ok(&["mount", "-o", &format!("remount,{twice}"), &root]);
            let reply = lab
                .authority()
                .workload_run(&run, &fixture(&["mark", "/workspace/grown"], "d-1"))
                .unwrap();
            sudo_ok(&["mount", "-o", &format!("remount,{size}"), &root]);
            let WorkloadReply::Failed {
                reason,
                environment_destroyed,
                ..
            } = reply
            else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_UNBOUNDED");
            assert!(environment_destroyed);
            assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
            assert!(!lab.runtime.exists(&container));
            assert!(!p.tmpfs.join("grown").exists());
            evidence(
                "capacity-drift-destroys-before-the-workload",
                reason,
                PRIV,
                "authority-workspace-contract",
            );
            // Another filesystem mounted over the root: the path names
            // another directory.
            let run = lab.operator_run();
            let (environment, container) = lab.ready(&run);
            let uid = std::fs::metadata("/proc/self").unwrap().uid();
            sudo_ok(&[
                "mount",
                "-t",
                "tmpfs",
                "-o",
                &format!("{size},mode=2770,uid={uid},gid=10001,nosuid,nodev"),
                "dw-substitute",
                &root,
            ]);
            let reply = lab
                .authority()
                .workload_run(&run, &fixture(&["mark", "/workspace/substituted"], "d-2"))
                .unwrap();
            sudo_ok(&["umount", &root]);
            let WorkloadReply::Failed {
                reason,
                environment_destroyed,
                ..
            } = reply
            else {
                panic!("not refused: {reply:?}")
            };
            assert_eq!(reason, "WORKSPACE_CHANGED");
            assert!(environment_destroyed);
            assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
            assert!(!lab.runtime.exists(&container));
            assert!(!p.tmpfs.join("substituted").exists());
            evidence(
                "mount-substitution-destroys-before-the-workload",
                reason,
                PRIV,
                "authority-workspace-contract",
            );
        }

        #[test]
        #[ignore = "needs a provisioned workspace: make sandbox-workspace-evidence"]
        fn a_full_workspace_fails_cleanly_and_borrows_from_no_other() {
            let p = provisioned();
            let mut lab = Lab::provisioned(
                "m5d4-full",
                custom(),
                Provision {
                    root: Some(p.ext4.clone()),
                    setting: bounded(p.quota),
                    writes: true,
                },
            );
            second_workspace(&mut lab, &p.second);
            let l = live(&mut lab, "ws");
            let other = live(&mut lab, "ws2");
            let reply = lab.authority().environment_prepare(&l.run).unwrap();
            let EnvironmentReply::Ready { report, .. } = reply else {
                panic!("not ready: {reply:?}")
            };
            lab.reap_later(report.container.as_ref().unwrap().as_str());
            evidence(
                "bounded-ext4-accepted",
                "ready",
                PRIV,
                "workspace-contract-measured",
            );
            let second_before = available(&p.second);
            // The workload writes until the filesystem says no -- and on,
            // until not one more block fits. Its first `ENOSPC` is not a full
            // filesystem: ext4 counts the blocks it holds preallocated for a
            // file being written as used, and frees them when the file is
            // closed (hosted run 39585235773 found room for the broker's
            // write after a workload that stopped there).
            let max = (p.quota >> 20) * 2;
            let text = ran(
                &mut lab,
                &l.run,
                &["workload-fill", "big", &max.to_string()],
                "f-1",
            );
            assert_eq!(field(&text, "errno"), ENOSPC, "{text}");
            assert_eq!(
                field(&text, "exhausted"),
                "1",
                "a block still fitted: {text}"
            );
            let filled: u64 = field(&text, "written").parse().unwrap();
            assert!(filled > 0 && filled <= p.quota, "{text}");
            assert_eq!(
                std::fs::metadata(p.ext4.join("big")).unwrap().len(),
                filled,
                "{text}"
            );
            // The precondition, measured by the kernel from the host once the
            // workload ended and its file was closed: an unprivileged writer
            // -- the broker is one -- has less room than the change needs, so
            // the kernel cannot let the change complete.
            let left = available(&p.ext4);
            assert!(
                left < u64::try_from(FULL_WRITE_BYTES).unwrap(),
                "{left} bytes still available after the fill: {text}"
            );
            evidence(
                "workload-fills-to-enospc",
                &format!("ENOSPC-exhausted-{left}-bytes-available"),
                PRIV,
                "filesystem-quota",
            );
            // The broker's change fails for want of room, with nothing
            // changed and nothing left behind.
            let reply = tool(
                &mut lab,
                &l,
                &write("/workspace/late.txt", &[0x42; FULL_WRITE_BYTES]),
                "w-1",
            );
            assert_eq!(failed(&reply), FsFailureReason::BrokerExecutionError);
            assert!(!p.ext4.join("late.txt").exists());
            assert!(debris(&p.ext4).is_empty(), "{:?}", debris(&p.ext4));
            let audited: i64 = super::super::state_support::raw(&lab.dir.state())
                .query_row(
                    "SELECT count(*) FROM tool_invocation \
                     WHERE state = 'FAILED' AND failure = 'BROKER_EXECUTION_ERROR'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(audited, 1);
            // The audit names the cause: no room, not any broker failure.
            let refusals: Vec<String> =
                super::super::state_support::audit_records(&lab.dir.state(), "tool.failed")
                    .iter()
                    .filter_map(|r| {
                        super::super::state_support::text(r, "broker_refusal").map(str::to_owned)
                    })
                    .collect();
            assert_eq!(refusals, ["NO_SPACE"]);
            assert_eq!(std::fs::metadata(p.ext4.join("big")).unwrap().len(), filled);
            evidence(
                "full-workspace-write-fails-unchanged",
                "NO_SPACE",
                PRIV,
                "filesystem-quota",
            );
            // Another workspace is its own filesystem: untouched, and usable.
            assert_eq!(available(&p.second), second_before, "no space was borrowed");
            written(&tool(
                &mut lab,
                &other,
                &write("/workspace/elsewhere.txt", b"fine"),
                "w-2",
            ));
            assert_eq!(
                std::fs::read(p.second.join("elsewhere.txt")).unwrap(),
                b"fine"
            );
            evidence(
                "other-workspace-unaffected",
                "written",
                PRIV,
                "filesystem-quota",
            );
            // Room made, the change is made.
            let text = ran(
                &mut lab,
                &l.run,
                &["workload-remove", "/workspace/big"],
                "f-2",
            );
            assert!(!text.contains("error="), "{text}");
            // The very write that was refused, now made in full.
            let late = [0x43; FULL_WRITE_BYTES];
            written(&tool(
                &mut lab,
                &l,
                &write("/workspace/late.txt", &late),
                "w-3",
            ));
            assert_eq!(std::fs::read(p.ext4.join("late.txt")).unwrap(), late);
            evidence(
                "space-recovered-after-removal",
                "written",
                PRIV,
                "filesystem-quota",
            );
            // A new incarnation on the same files: the store and its audit
            // chain are whole.
            lab.start(None);
            let ok: String = super::super::state_support::raw(&lab.dir.state())
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(ok, "ok");
            evidence(
                "durability-valid-after-a-full-workspace",
                "integrity-ok",
                PRIV,
                "authority-ledger",
            );
        }

        #[test]
        #[ignore = "needs a provisioned workspace: make sandbox-workspace-evidence"]
        fn production_serve_runs_in_a_bounded_workspace() {
            let p = provisioned();
            let mut lab = Lab::provisioned(
                "m5d4-serve-bounded",
                custom(),
                Provision {
                    root: Some(p.tmpfs.clone()),
                    setting: bounded(p.quota),
                    writes: false,
                },
            );
            lab.authority()
                .operator()
                .bind_session_workspace(&session(1), &WorkspaceId::new("ws").unwrap())
                .unwrap();
            lab.authority = None;
            let socket = lab.dir.path().join("ipc").join("kernel.sock");
            let mut server = super::super::transport_support::Server::start(&serve_args(
                &lab,
                &socket,
                &format!("quota_bytes = {}", p.quota),
            ));
            assert!(
                !server.stderr().contains("unverified_evidence"),
                "{}",
                server.stderr()
            );
            let mut a = Peer::admit(&socket, 1, &["process.exec:*"], |_| {});
            let body = a.exec("p-1", &call(FIXTURE, &["workload-make", "served"]));
            let out = sandboxed(&body);
            let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
            assert_eq!(field(&text, "file_gid"), "10001", "{text}");
            assert_eq!(field(&text, "dir_mode"), "2770", "{text}");
            let container: String = super::super::state_support::raw(&lab.dir.state())
                .query_row(
                    "SELECT container FROM environment WHERE environment_id = ?1",
                    [out.environment_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            lab.reap_later(&container);
            assert!(p.tmpfs.join("served.file").exists());
            evidence(
                "production-serve-bounded-workspace",
                "completed",
                PRIV,
                "workspace-contract-measured",
            );
            server.kill();
        }
    }

    /// M5e.2 (R11; the owner's OD-E8): the container runtime restarts under a
    /// **running** authority -- not the authority's restart, which M5a's
    /// reconciliation already covers. Hosted only: the test restarts the
    /// runner's Docker Engine, so it refuses, before anything, unless this is
    /// a disposable GitHub-hosted runner whose engine is a local systemd unit
    /// (never Docker Desktop, never a developer's daemon). What it holds is
    /// the accepted contract, not re-attach: an environment's container is
    /// `--restart no`; a workload the restart interrupts is never believed
    /// finished and never run again; reconciliation on the same incarnation
    /// destroys what stopped and measures what still runs; nothing foreign
    /// is touched; and a new authorized workload runs after. Every line is
    /// `privileged-oci`: it needs the runner's root.
    mod restart {
        use super::*;

        const RESTART_SUITE: &str = "sandbox-restart";
        /// Restarting the runtime takes privilege a workstation never grants
        /// this evidence: the hosted runner's.
        const PRIV: &str = "privileged-oci";
        /// The runtime must answer again, and reconciliation settle, within
        /// the environment deadline.
        const RECOVERY_BOUND: Duration = Duration::from_secs(120);
        const FOREIGN_LABEL: &str = "io.direwolf.test=foreign-restart";

        fn evidence(case: &str, outcome: &str, level: &str, enforcement: &str) {
            evidence_line(RESTART_SUITE, case, outcome, level, enforcement);
        }

        /// Whether this host's runtime may be restarted, and how it keeps
        /// containers across a restart: `Err` names what is missing.
        fn disposable_runner(runtime: &Runtime) -> Result<bool, String> {
            let env = |name: &str| std::env::var(name).unwrap_or_default();
            if env("DW_RUNTIME_RESTART") != "1" {
                return Err("DW_RUNTIME_RESTART is not 1".to_owned());
            }
            if env("GITHUB_ACTIONS") != "true" || env("RUNNER_ENVIRONMENT") != "github-hosted" {
                return Err("this is not a GitHub-hosted runner".to_owned());
            }
            let system = runtime.ok(&["info", "--format", "{{.OperatingSystem}}"]);
            if system.contains("Docker Desktop") {
                return Err(format!("the runtime is {}", system.trim()));
            }
            let unit = Command::new("systemctl")
                .args(["is-active", "docker"])
                .output()
                .map_err(|e| format!("no systemctl: {e}"))?;
            if String::from_utf8_lossy(&unit.stdout).trim() != "active" {
                return Err("the runtime is not the local `docker` systemd unit".to_owned());
            }
            let sudo = Command::new("sudo")
                .args(["-n", "true"])
                .status()
                .map_err(|e| format!("no sudo: {e}"))?;
            if !sudo.success() {
                return Err("sudo needs a password here".to_owned());
            }
            Ok(runtime
                .ok(&["info", "--format", "{{.LiveRestoreEnabled}}"])
                .trim()
                == "true")
        }

        /// Restart the runner's engine; how long until it answered again.
        fn restart_runtime(runtime: &Runtime) -> Duration {
            let since = Instant::now();
            let status = Command::new("sudo")
                .args(["-n", "systemctl", "restart", "docker"])
                .status()
                .unwrap();
            assert!(status.success(), "the runtime did not restart");
            loop {
                if runtime
                    .docker(&["info", "--format", "{{.ServerVersion}}"])
                    .status
                    .success()
                {
                    return since.elapsed();
                }
                assert!(
                    since.elapsed() < RECOVERY_BOUND,
                    "the runtime did not answer within {RECOVERY_BOUND:?}"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        /// A container that is not DireWolf's: created, never started, and
        /// removed by this test alone.
        struct Foreign {
            runtime: Runtime,
            id: String,
        }

        impl Drop for Foreign {
            fn drop(&mut self) {
                let _ = self
                    .runtime
                    .docker(&["container", "rm", "--force", &self.id]);
            }
        }

        fn store_containers(lab: &Lab) -> usize {
            let store = lab.reaper.store.lock().unwrap().clone().unwrap();
            lab.runtime
                .ok(&[
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    &format!("label=io.direwolf.store={store}"),
                ])
                .lines()
                .count()
        }

        #[test]
        #[ignore = "restarts the runtime: hosted only, make sandbox-restart-evidence"]
        fn the_runtime_restarts_under_a_running_authority_and_nothing_is_believed_or_replayed() {
            let runtime = Runtime::load();
            let live_restore = disposable_runner(&runtime).unwrap_or_else(|why| {
                panic!(
                    "NOT EXERCISED: {why}; the runtime is restarted only on a disposable \
                     hosted runner (make sandbox-restart-evidence, DW_RUNTIME_RESTART=1)"
                )
            });
            println!("restart: a disposable hosted runner, live-restore={live_restore}");
            let mut lab = Lab::new("m5e-restart", WorkloadBudget::default());
            // Run A: a workload in flight when the runtime restarts. Run B:
            // an environment ready and idle. And a container that is not
            // DireWolf's.
            let run_a = lab.operator_run();
            let (env_a, container_a) = lab.ready(&run_a);
            let run_b = lab.operator_run();
            let (env_b, container_b) = lab.ready(&run_b);
            let foreign = Foreign {
                runtime: lab.runtime.clone(),
                id: lab
                    .runtime
                    .ok(&[
                        "container",
                        "create",
                        "--label",
                        FOREIGN_LABEL,
                        "--entrypoint",
                        PROBE,
                        &var("DW_SANDBOX_WORKLOAD_IMAGE"),
                        "hold",
                    ])
                    .trim()
                    .to_owned(),
            };
            let owned_before = store_containers(&lab);
            let restarter = {
                let runtime = lab.runtime.clone();
                let watched = container_a.clone();
                std::thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(60);
                    while runtime.others(&watched) < 1 {
                        assert!(Instant::now() < deadline, "the workload never started");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    restart_runtime(&runtime)
                })
            };
            let reply = lab
                .authority()
                .workload_run(&run_a, &fixture(&["workload-sleep", "50"], "r-1"))
                .unwrap();
            let recovered_in = restarter.join().unwrap();
            // The interrupted workload is never believed finished: nothing
            // proves a sleep of 50 s ended well a few seconds in.
            let (settled, proved) = match &reply {
                WorkloadReply::Unknown {
                    reason,
                    environment_destroyed,
                    ..
                } => {
                    assert!(*environment_destroyed, "{reply:?}");
                    (format!("unknown:{reason}"), false)
                }
                WorkloadReply::Failed { reason, .. } => (format!("failed:{reason}"), false),
                WorkloadReply::Completed(outcome) => {
                    assert!(
                        !(outcome.ending == WorkloadEnding::Exited && outcome.exit_code == Some(0)),
                        "a workload the restart interrupted is reported finished: {outcome:?}"
                    );
                    assert_eq!(
                        outcome.environment_destroyed,
                        outcome.residue != Verdict::Pass,
                        "{outcome:?}"
                    );
                    (
                        format!("ended:{:?}", outcome.ending).to_lowercase(),
                        outcome.residue == Verdict::Pass,
                    )
                }
                other => panic!("the interrupted workload: {other:?}"),
            };
            evidence(
                "restart-in-flight-not-believed",
                &settled,
                PRIV,
                "authority-ledger",
            );
            // Reconciliation, on the same incarnation of the authority.
            let report = lab.authority().environment_reconcile().unwrap();
            assert!(!report.unobservable, "{report:?}");
            assert_eq!(report.incomplete, 0, "{report:?}");
            assert_eq!(report.ambiguous, 0, "{report:?}");
            assert!(recovered_in < RECOVERY_BOUND, "{recovered_in:?}");
            evidence(
                "restart-reconciled-within-bound",
                &format!("runtime-back-in-{}ms", recovered_in.as_millis()),
                PRIV,
                "authority-reconciliation",
            );
            // A's environment: never believed still running unless its end
            // was proved and its container measured clean again.
            let a_state = lab.state_of(&env_a);
            let a_outcome = match a_state {
                EnvironmentState::Destroyed | EnvironmentState::Lost => {
                    assert!(!lab.runtime.exists(&container_a), "{a_state:?}");
                    a_state.as_str()
                }
                EnvironmentState::Ready if live_restore && proved => {
                    assert!(lab.runtime.exists(&container_a));
                    "ready-measured-again"
                }
                other => panic!("the interrupted run's environment is {other:?}"),
            };
            evidence(
                "restart-interrupted-environment-not-believed",
                &a_outcome.to_lowercase(),
                PRIV,
                "authority-reconciliation",
            );
            // B's idle environment, as the runtime kept it: stopped is
            // destroyed by its labels; still running is measured again.
            let b_state = lab.state_of(&env_b);
            let b_outcome = if live_restore {
                assert_eq!(b_state, EnvironmentState::Ready, "{report:?}");
                assert!(report.still_running >= 1, "{report:?}");
                "ready-measured-again"
            } else {
                assert!(
                    matches!(
                        b_state,
                        EnvironmentState::Destroyed | EnvironmentState::Lost
                    ),
                    "{b_state:?}: {report:?}"
                );
                assert!(!lab.runtime.exists(&container_b), "{b_state:?}");
                "stopped-destroyed"
            };
            evidence(
                "restart-idle-environment-reconciled",
                b_outcome,
                PRIV,
                "authority-reconciliation",
            );
            // The same key again: its record, never a second run.
            let owned_after = store_containers(&lab);
            let again = lab
                .authority()
                .workload_run(&run_a, &fixture(&["workload-sleep", "50"], "r-1"))
                .unwrap();
            let WorkloadReply::Replayed(record) = &again else {
                panic!("the interrupted workload's key ran again: {again:?}")
            };
            assert_ne!(record.state, WorkloadState::Completed, "{record:?}");
            assert_ne!(record.state, WorkloadState::Launching, "{record:?}");
            assert_eq!(store_containers(&lab), owned_after);
            assert!(owned_after <= owned_before);
            evidence(
                "restart-in-flight-never-rerun",
                record.state.as_str(),
                PRIV,
                "authority-idempotency",
            );
            // The container that is not DireWolf's is still there, as made.
            assert!(lab.runtime.exists(&foreign.id));
            assert_eq!(
                lab.runtime.label(&foreign.id, "io.direwolf.test"),
                "foreign-restart"
            );
            evidence(
                "restart-foreign-untouched",
                "present",
                PRIV,
                "exact-label-ownership",
            );
            // A new authorized workload runs, in a new environment, as the
            // environment's own user -- on the same incarnation.
            let run_c = lab.operator_run();
            let (_, container_c) = lab.ready(&run_c);
            assert!(container_c != container_a && container_c != container_b);
            let served = lab
                .authority()
                .workload_run(&run_c, &fixture(&["workload-identity"], "r-2"))
                .unwrap();
            let WorkloadReply::Completed(outcome) = &served else {
                panic!("a new workload after the restart: {served:?}")
            };
            assert_eq!(outcome.ending, WorkloadEnding::Exited, "{outcome:?}");
            assert_eq!(outcome.exit_code, Some(0), "{outcome:?}");
            assert!(
                String::from_utf8_lossy(&outcome.stdout).contains("uid=10001,"),
                "{outcome:?}"
            );
            evidence(
                "restart-new-workload-served",
                "exited-0-as-10001",
                PRIV,
                "authority-ledger",
            );
            drop(foreign);
        }
    }

    /// M5d.6 (ADR-0052 §8): a run's release ends its environment -- in a
    /// **real** OCI runtime, through the released broker, the real authority
    /// and, where a runtime would ask, a **real** DWKP client. Every line says
    /// what it is and what enforced it: `dwkp-end-to-end` is a real DWKP
    /// client on the authority's socket; `real-oci` is the authority's own
    /// API -- the interleavings one DWKP connection never makes (a release
    /// while its own launch is outstanding), a crash, a broker lost -- over
    /// the same real broker and runtime. `make sandbox-release-evidence`
    /// selects these by name.
    mod release {
        use dwk_proto::wire::id::SessionId;
        use dwk_proto::wire::scalar::{Epoch, RefusalReason};
        use dwkd_authority::state::{CallerContext, Dispatched};

        use super::super::state_support::release_run_msg;
        use super::*;

        const RELEASE_SUITE: &str = "sandbox-release";
        const E2E: &str = "dwkp-end-to-end";
        const REAL: &str = "real-oci";
        /// The agent-shaped workload's processes, as `workload-procs` names
        /// them: the plan, two workers and the daemonised helper's child.
        const AGENT: [&str; 4] = [
            "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-agent 300",
            "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-agent-worker 1",
            "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-agent-worker 2",
            "uid=10001 argv=/usr/libexec/direwolf/sandbox-fixture workload-sleep 600",
        ];

        fn evidence(case: &str, outcome: &str, level: &str, enforcement: &str) {
            println!(
                "SANDBOX-EVIDENCE {{\"suite\":\"{RELEASE_SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"level\":\"{level}\",\"enforcement\":\"{enforcement}\"}}"
            );
        }

        fn one(lab: &Lab, sql: &str, param: &str) -> String {
            super::super::state_support::raw(&lab.dir.state())
                .query_row(sql, [param], |row| row.get(0))
                .unwrap()
        }

        fn container_of(lab: &Lab, environment: &EnvironmentId) -> String {
            one(
                lab,
                "SELECT container FROM environment WHERE environment_id = ?1",
                environment.as_str(),
            )
        }

        fn ended(lab: &Lab, environment: &EnvironmentId) -> String {
            one(
                lab,
                "SELECT state || ':' || COALESCE(failure, '') FROM environment \
                 WHERE environment_id = ?1",
                environment.as_str(),
            )
        }

        fn run_state(lab: &Lab, run: &RunId) -> String {
            one(lab, "SELECT state FROM run WHERE run_id = ?1", run.as_str())
        }

        fn intents(lab: &Lab) -> usize {
            audit_records(&lab.dir.state(), "environment.destroy_intent").len()
        }

        fn audit_records(state: &std::path::Path, event: &str) -> Vec<dwk_proto::json::Object> {
            super::super::state_support::audit_records(state, event)
        }

        /// Containers that are not the evidence's environments: the workload
        /// image run unlabelled, and run labelled as another store's copy of
        /// a released environment -- what a destruction by name, image or
        /// partial label would take. Removed when the test ends.
        struct Decoys {
            runtime: Runtime,
            ids: Vec<String>,
        }

        impl Decoys {
            fn new(runtime: &Runtime, labels: &[Vec<(&str, &str)>]) -> Self {
                let image = var("DW_SANDBOX_WORKLOAD_IMAGE");
                let mut ids = Vec::new();
                for set in labels {
                    let mut args: Vec<String> =
                        ["container", "run", "--detach", "--network", "none"]
                            .iter()
                            .map(|a| (*a).to_owned())
                            .collect();
                    for (key, value) in set {
                        args.push("--label".to_owned());
                        args.push(format!("{key}={value}"));
                    }
                    args.extend(
                        [image.as_str(), FIXTURE, "workload-sleep", "600"]
                            .iter()
                            .map(|a| (*a).to_owned()),
                    );
                    let words: Vec<&str> = args.iter().map(String::as_str).collect();
                    ids.push(runtime.ok(&words).trim().to_owned());
                }
                Self {
                    runtime: runtime.clone(),
                    ids,
                }
            }
        }

        impl Drop for Decoys {
            fn drop(&mut self) {
                for id in &self.ids {
                    let _ = self.runtime.docker(&["container", "rm", "--force", id]);
                }
            }
        }

        /// A run admitted in-process, with everything a DWKP request of its
        /// runtime would carry.
        fn admitted(lab: &mut Lab) -> (CallerContext, SessionId, Epoch, RunId) {
            let n = lab.next_session;
            lab.next_session += 1;
            let authority = lab.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &WorkspaceId::new("ws").unwrap())
                .unwrap();
            let caller = authority.connect(subject(1000));
            let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(n)).unwrap() else {
                panic!("a lease")
            };
            let run = again(lab, &caller, &session(n), epoch);
            (caller, session(n), epoch, run)
        }

        /// Another run in the same session, under the same lease.
        fn again(
            lab: &mut Lab,
            caller: &CallerContext,
            session: &SessionId,
            epoch: Epoch,
        ) -> RunId {
            let n = next_message();
            let admitted = lab
                .authority()
                .admit_run(
                    caller,
                    &admit_msg(
                        session,
                        epoch,
                        &format!("release-{n}"),
                        "operator",
                        &[],
                        &["process.exec:*"],
                        n,
                    ),
                )
                .unwrap();
            let Reply::Done(admission) = admitted else {
                panic!("admitted: {admitted:?}")
            };
            admission.run_id().clone()
        }

        /// A version-5 `process.exec` of `run`, as its runtime would send it.
        fn exec_message(
            (session, run, epoch): (&SessionId, &RunId, Epoch),
            key: &str,
            call: &str,
        ) -> DwkpMessage {
            decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-10-25T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"process_exec":{call}}}}}"#,
                id = id("msg", 95_000 + next_message()),
                session = session.as_str(),
                run = run.as_str(),
                epoch = epoch.get(),
            ))
        }

        fn stale(body: &DwkpBody) -> bool {
            matches!(body, DwkpBody::AuthorityRefused(r) if r.reason == RefusalReason::StaleEpoch)
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-release-evidence"]
        fn a_release_over_dwkp_destroys_its_environment_and_nothing_else() {
            let mut lab = Lab::new("m5d6-release", WorkloadBudget::default());
            let served = lab.serve();
            let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
            let mut b = Peer::admit(served.path(), 2, &["process.exec:*"], binder(&served));
            let mut idle = Peer::admit(served.path(), 3, &["process.exec:*"], binder(&served));
            let body = a.exec("a-1", &call(FIXTURE, &["workload-identity"]));
            let mine = sandboxed(&body).environment_id.clone();
            // What a run's release ends is a sandboxed launch as M5d.2 made
            // it: decided by the authority, in its measured environment,
            // the pinned image's pinned executable, as the environment's user.
            let out = sandboxed(&body);
            assert_eq!(
                out.assurance,
                dwk_proto::dwkp::sandboxops::ExecutionAssurance::ContainerIsolation
            );
            evidence(
                "sandboxed-exec-in-a-measured-environment-never-the-host",
                "CONTAINER_ISOLATION",
                E2E,
                "authority-route-no-fallback",
            );
            assert_eq!(
                out.executable.image.as_str(),
                var("DW_SANDBOX_WORKLOAD_IMAGE")
            );
            assert_eq!(out.executable.path.as_str(), FIXTURE);
            assert_eq!(
                out.executable.sha256.as_str(),
                var("DW_SANDBOX_FIXTURE_SHA256")
            );
            evidence(
                "sandboxed-exec-names-the-pinned-image-and-executable",
                "image-and-sha256-pinned",
                E2E,
                "broker-digest-proof",
            );
            let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
            assert!(text.contains("uid=10001"), "{text}");
            evidence(
                "sandboxed-exec-runs-as-the-environment-user",
                "uid-10001",
                E2E,
                "oci-environment-user",
            );
            let body = b.exec("b-1", &call(FIXTURE, &["workload-identity"]));
            let theirs = sandboxed(&body).environment_id.clone();
            let container = container_of(&lab, &mine);
            let other = container_of(&lab, &theirs);
            lab.reap_later(&container);
            let decoys = Decoys::new(
                &lab.runtime,
                &[
                    vec![],
                    vec![
                        ("io.direwolf.owner", "direwolf"),
                        ("io.direwolf.store", "0badc0de"),
                        ("io.direwolf.environment", mine.as_str()),
                        ("io.direwolf.run", a.run.as_str()),
                        ("io.direwolf.role", "environment"),
                    ],
                ],
            );

            // A fenced caller ends nothing: a stale epoch, and the run's
            // session named from a connection that is not its lease's
            // holder, are each refused before anything is looked at.
            let later = Epoch::new(a.epoch.get() + 1).unwrap();
            let refused = a
                .client
                .call(&release_run_msg(&a.session, &a.run, later))
                .body;
            assert!(stale(&refused), "{refused:?}");
            evidence(
                "release-stale-epoch-refused-nothing-destroyed",
                "STALE_EPOCH",
                E2E,
                "authority-lease-fence",
            );
            let refused = idle
                .client
                .call(&release_run_msg(&a.session, &a.run, a.epoch))
                .body;
            assert!(stale(&refused), "{refused:?}");
            evidence(
                "release-other-holder-refused-nothing-destroyed",
                "STALE_EPOCH",
                E2E,
                "authority-lease-fence",
            );
            // A run the caller does not hold, named under its own lease, is
            // acknowledged, as such a release always is -- and ends nothing.
            let acked = idle
                .client
                .call(&release_run_msg(&idle.session, &a.run, idle.epoch))
                .body;
            assert!(matches!(acked, DwkpBody::Ack(_)), "{acked:?}");
            assert!(lab.runtime.exists(&container));
            assert_eq!(run_state(&lab, &a.run), "ACTIVE");
            assert_eq!(intents(&lab), 0);
            evidence(
                "release-of-a-run-not-held-destroys-nothing",
                "ACK-container-kept",
                E2E,
                "authority-run-ownership",
            );

            // The holder's release: `Ack` -- and the environment is gone
            // when it is answered, removed by its recorded identity.
            let released = a
                .client
                .call(&release_run_msg(&a.session, &a.run, a.epoch))
                .body;
            assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
            assert!(
                !lab.runtime.exists(&container),
                "gone when the release is answered"
            );
            assert_eq!(ended(&lab, &mine), "DESTROYED:RELEASED");
            assert_eq!(run_state(&lab, &a.run), "RELEASED");
            evidence(
                "release-over-dwkp-destroys-the-environment",
                "container-removed",
                E2E,
                "authority-release-teardown",
            );
            let intent = audit_records(&lab.dir.state(), "environment.destroy_intent")
                .into_iter()
                .find(|r| {
                    super::super::state_support::text(r, "environment_id") == Some(mine.as_str())
                })
                .expect("the destruction's intent was audited");
            assert_eq!(
                super::super::state_support::text(&intent, "reason"),
                Some("RELEASED")
            );
            assert!(
                audit_records(&lab.dir.state(), "environment.destroyed")
                    .iter()
                    .any(|r| super::super::state_support::text(r, "environment_id")
                        == Some(mine.as_str()))
            );
            evidence(
                "release-audited",
                "destroy_intent-RELEASED-then-destroyed",
                E2E,
                "authority-audit",
            );

            // Nothing else: the other run's environment, an unlabelled
            // container of the same image, another store's copy of the
            // released environment's labels.
            assert!(lab.runtime.exists(&other));
            for decoy in &decoys.ids {
                assert!(lab.runtime.exists(decoy), "{decoy} was removed");
            }
            evidence(
                "release-spares-another-runs-environment",
                "container-kept",
                E2E,
                "authority-run-association",
            );
            evidence(
                "release-spares-foreign-containers",
                "unlabelled-and-another-stores-kept",
                E2E,
                "broker-exact-labels",
            );
            let body = b.exec("b-2", &call(FIXTURE, &["workload-identity"]));
            assert_eq!(sandboxed(&body).environment_id, theirs);
            assert_eq!(
                sandboxed(&body).residue,
                dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
            );
            evidence(
                "release-other-run-still-runs",
                "residue-pass",
                E2E,
                "authority-run-association",
            );

            // A repeat: `Ack`, nothing more.
            let before = intents(&lab);
            let again = a
                .client
                .call(&release_run_msg(&a.session, &a.run, a.epoch))
                .body;
            assert!(matches!(again, DwkpBody::Ack(_)), "{again:?}");
            assert_eq!(intents(&lab), before);
            assert!(lab.runtime.exists(&other));
            evidence(
                "release-repeated-over-dwkp-no-second-effect",
                "ACK-nothing-destroyed",
                E2E,
                "authority-release-idempotent",
            );
            // The released run regains nothing: its launch is refused, and
            // no environment is prepared for it.
            let environments = rows(&lab, "SELECT count(*) FROM environment");
            let body = a.exec("a-2", &call(FIXTURE, &["workload-identity"]));
            assert_eq!(refusal(&body), "UNKNOWN_RUN");
            assert_eq!(rows(&lab, "SELECT count(*) FROM environment"), environments);
            evidence(
                "released-run-launch-refused-over-dwkp",
                "UNKNOWN_RUN",
                E2E,
                "authority-run-held-check",
            );
            // A run that never had an environment: released, nothing more.
            let before = intents(&lab);
            let acked = idle
                .client
                .call(&release_run_msg(&idle.session, &idle.run, idle.epoch))
                .body;
            assert!(matches!(acked, DwkpBody::Ack(_)), "{acked:?}");
            assert_eq!(intents(&lab), before);
            assert_eq!(run_state(&lab, &idle.run), "RELEASED");
            evidence(
                "release-without-an-environment-over-dwkp",
                "ACK-nothing-destroyed",
                E2E,
                "authority-release-teardown",
            );
            lab.reap_later(&other);
            drop(decoys);
            served.stop();
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-release-evidence"]
        fn a_release_ends_an_in_flight_workload_and_every_process_it_left() {
            let mut lab = Lab::new("m5d6-inflight", WorkloadBudget::default());
            let (caller, session, epoch, run) = admitted(&mut lab);
            let message = exec_message(
                (&session, &run, epoch),
                "inflight-1",
                &call(FIXTURE, &["workload-agent", "300"]),
            );
            let Dispatched::Parked(mut parked) = lab
                .authority()
                .dispatch_parkable(&caller, &message)
                .unwrap()
            else {
                panic!("a running launch is parked")
            };
            let environment = EnvironmentId::parse(&one(
                &lab,
                "SELECT environment_id FROM environment WHERE run_id = ?1",
                run.as_str(),
            ))
            .unwrap();
            let container = container_of(&lab, &environment);
            lab.reap_later(&container);
            for line in AGENT {
                let procs = lab.runtime.awaited(&container, line);
                assert!(
                    procs.iter().all(|p| p.starts_with("uid=10001 ")),
                    "{procs:?}"
                );
            }
            evidence(
                "release-in-flight-agent-and-descendants-running",
                "plan-workers-and-daemon-as-10001",
                REAL,
                "runtime-census",
            );

            let since = Instant::now();
            let released = lab
                .authority()
                .release_run(&caller, &session, &run, epoch)
                .unwrap();
            assert!(matches!(released, Reply::Done(())), "{released:?}");
            assert!(
                !lab.runtime.exists(&container),
                "the release removed the environment the workload ran in"
            );
            assert_eq!(ended(&lab, &environment), "DESTROYED:RELEASED");
            evidence(
                "release-ends-in-flight-workload-and-descendants",
                "container-removed-with-every-process",
                REAL,
                "authority-release-teardown",
            );
            let deadline = Instant::now() + Duration::from_secs(120);
            let body = loop {
                if let Some(body) = lab.authority().resume(&mut parked).unwrap() {
                    break body;
                }
                assert!(Instant::now() < deadline, "the launch was never answered");
                std::thread::sleep(Duration::from_millis(250));
            };
            let DwkpBody::ToolFailedV5(failure) = &body else {
                panic!("not failed: {body:?}")
            };
            assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN");
            assert!(
                since.elapsed() < Duration::from_secs(120),
                "ended by the release, not by its wall clock: {:?}",
                since.elapsed()
            );
            assert_eq!(
                one(
                    &lab,
                    "SELECT state FROM workload WHERE idempotency_key = ?1",
                    "inflight-1"
                ),
                "UNKNOWN"
            );
            evidence(
                "release-in-flight-workload-settled-unknown",
                "OUTCOME_UNKNOWN",
                REAL,
                "authority-ledger",
            );
            // Never again: the key, in another run of the session.
            let next = again(&mut lab, &caller, &session, epoch);
            let workloads = workload_rows(&lab);
            let environments = rows(&lab, "SELECT count(*) FROM environment");
            let message = exec_message(
                (&session, &next, epoch),
                "inflight-1",
                &call(FIXTURE, &["workload-agent", "300"]),
            );
            let Dispatched::Answer(body) = lab
                .authority()
                .dispatch_parkable(&caller, &message)
                .unwrap()
            else {
                panic!("a replayed key was parked")
            };
            assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
            assert_eq!(workload_rows(&lab), workloads);
            assert_eq!(rows(&lab, "SELECT count(*) FROM environment"), environments);
            evidence(
                "release-in-flight-workload-never-rerun",
                "IDEMPOTENCY_KEY_REUSED",
                REAL,
                "authority-shared-idempotency-namespace",
            );
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-release-evidence"]
        fn a_release_a_crash_or_a_lost_broker_interrupts_is_completed_at_the_next_start() {
            // W12, W6 and W7 through a release: the authority stopped where a
            // crash would, then a new incarnation on the same files.
            for point in [
                CrashPoint::ReleaseAfterIntent,
                CrashPoint::EnvironmentDestroyAfterIntent,
                CrashPoint::EnvironmentDestroyAfterBroker,
            ] {
                let mut lab = Lab::new(
                    &format!("m5d6-crash-{}", point.letter()),
                    WorkloadBudget::default(),
                );
                lab.start(Some(stop_at(point)));
                let (caller, session, epoch, run) = admitted(&mut lab);
                let (environment, container) = lab.ready(&run);
                let reply = lab
                    .authority()
                    .workload_run(&run, &fixture(&["workload-identity"], "c-1"))
                    .unwrap();
                assert!(matches!(reply, WorkloadReply::Completed(_)), "{reply:?}");
                poisoned(lab.authority().release_run(&caller, &session, &run, epoch));
                assert_eq!(run_state(&lab, &run), "RELEASED", "{point}");
                assert_eq!(ended(&lab, &environment), "DESTROYING:RELEASED", "{point}");
                assert_eq!(
                    lab.runtime.exists(&container),
                    point != CrashPoint::EnvironmentDestroyAfterBroker,
                    "{point}"
                );
                let workloads = workload_rows(&lab);
                lab.start(None);
                assert!(!lab.runtime.exists(&container), "{point}");
                assert_eq!(ended(&lab, &environment), "DESTROYED:RELEASED", "{point}");
                assert_eq!(run_state(&lab, &run), "RELEASED", "{point}");
                evidence(
                    &format!("release-crash-{}-completed-at-restart", point.letter()),
                    "container-removed",
                    REAL,
                    "authority-reconciliation",
                );
                // The released run regains nothing: nothing it ran runs
                // again, and nothing new runs for it.
                let reply = lab
                    .authority()
                    .workload_run(&run, &fixture(&["workload-identity"], "c-1"))
                    .unwrap();
                assert!(
                    !matches!(reply, WorkloadReply::Completed(_)),
                    "{point}: {reply:?}"
                );
                assert_eq!(workload_rows(&lab), workloads, "{point}");
                evidence(
                    &format!("release-crash-{}-never-rerun", point.letter()),
                    "nothing-recorded-or-run",
                    REAL,
                    "authority-run-ended",
                );
            }

            // The broker lost: the release is answered, its destruction stays
            // pending -- never a false success -- and the next start, a broker
            // answering again, completes it.
            let mut lab = Lab::new("m5d6-broker-lost", WorkloadBudget::default());
            let (caller, session, epoch, run) = admitted(&mut lab);
            let (environment, container) = lab.ready(&run);
            lab.broker.kill();
            let released = lab
                .authority()
                .release_run(&caller, &session, &run, epoch)
                .unwrap();
            assert!(matches!(released, Reply::Done(())), "{released:?}");
            assert!(lab.runtime.exists(&container), "nothing could remove it");
            assert_eq!(lab.state_of(&environment), EnvironmentState::Destroying);
            assert!(
                audit_records(&lab.dir.state(), "environment.destroy_failed")
                    .iter()
                    .any(|r| super::super::state_support::text(r, "environment_id")
                        == Some(environment.as_str()))
            );
            evidence(
                "release-broker-lost-destruction-pending",
                "DESTROYING-container-kept",
                REAL,
                "authority-unconfirmed-is-pending",
            );
            lab.broker = Broker::start(&lab.broker_socket, own_uid(), &lab.broker_flags);
            lab.start(None);
            assert!(!lab.runtime.exists(&container));
            assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
            evidence(
                "release-broker-lost-completed-at-restart",
                "container-removed",
                REAL,
                "authority-reconciliation",
            );
        }

        // ---- the M5d closeout: a lease's end ends its runs' environments ----

        /// A second run in `peer`'s session, under its lease, and the
        /// container of the environment a workload of it ran in.
        fn second_run(peer: &mut Peer, lab: &Lab, key: &str) -> (RunId, String) {
            let first = peer.run.clone();
            let n = next_message();
            let admitted = peer
                .client
                .call(&admit_msg(
                    &peer.session,
                    peer.epoch,
                    &format!("second-{n}"),
                    "operator",
                    &[],
                    &["process.exec:*"],
                    n,
                ))
                .body;
            let DwkpBody::RunGrant(grant) = admitted else {
                panic!("a second run: {admitted:?}")
            };
            peer.run = grant.run_id.clone();
            let body = peer.exec(key, &call(FIXTURE, &["workload-identity"]));
            let container = container_of(lab, &sandboxed(&body).environment_id);
            peer.run = first;
            (grant.run_id, container)
        }

        fn environment_of(lab: &Lab, container: &str) -> EnvironmentId {
            EnvironmentId::parse(&one(
                lab,
                "SELECT environment_id FROM environment WHERE container = ?1",
                container,
            ))
            .unwrap()
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-release-evidence"]
        fn a_lease_end_over_dwkp_destroys_its_runs_environments_and_nothing_else() {
            let mut lab = Lab::new("m5d-lease", WorkloadBudget::default());
            let served = lab.serve();
            let mut a = Peer::admit(served.path(), 1, &["process.exec:*"], binder(&served));
            let mut b = Peer::admit(served.path(), 2, &["process.exec:*"], binder(&served));
            let body = a.exec("a-1", &call(FIXTURE, &["workload-identity"]));
            let first = container_of(&lab, &sandboxed(&body).environment_id);
            lab.reap_later(&first);
            let (second_id, second) = second_run(&mut a, &lab, "a-2");
            let body = b.exec("b-1", &call(FIXTURE, &["workload-identity"]));
            let other = container_of(&lab, &sandboxed(&body).environment_id);
            let first_env = environment_of(&lab, &first);
            let decoys = Decoys::new(
                &lab.runtime,
                &[
                    vec![],
                    vec![
                        ("io.direwolf.owner", "direwolf"),
                        ("io.direwolf.store", "0badc0de"),
                        ("io.direwolf.environment", first_env.as_str()),
                        ("io.direwolf.run", a.run.as_str()),
                        ("io.direwolf.role", "environment"),
                    ],
                ],
            );

            // A fenced caller ends nothing.
            let later = Epoch::new(a.epoch.get() + 1).unwrap();
            let refused = a
                .client
                .call(&super::super::state_support::release_lease_msg(
                    &a.session, later,
                ))
                .body;
            assert!(stale(&refused), "{refused:?}");
            evidence(
                "lease-release-over-dwkp-stale-refused",
                "STALE_EPOCH",
                E2E,
                "authority-lease-fence",
            );
            let refused = b
                .client
                .call(&super::super::state_support::release_lease_msg(
                    &a.session, a.epoch,
                ))
                .body;
            assert!(stale(&refused), "{refused:?}");
            assert!(lab.runtime.exists(&first) && lab.runtime.exists(&second));
            assert_eq!(intents(&lab), 0);
            evidence(
                "lease-release-over-dwkp-other-holder-refused",
                "STALE_EPOCH",
                E2E,
                "authority-lease-fence",
            );

            // The holder's release: both runs reaped, both environments'
            // destruction durable, one removed when it is answered.
            let released = a
                .client
                .call(&super::super::state_support::release_lease_msg(
                    &a.session, a.epoch,
                ))
                .body;
            assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
            assert_eq!(run_state(&lab, &a.run), "REAPED");
            assert_eq!(run_state(&lab, &second_id), "REAPED");
            let left: Vec<&String> = [&first, &second]
                .into_iter()
                .filter(|c| lab.runtime.exists(c))
                .collect();
            assert_eq!(left.len(), 1, "{left:?}");
            assert_eq!(
                ended(&lab, &environment_of(&lab, left[0])),
                "DESTROYING:REAPED"
            );
            evidence(
                "lease-release-over-dwkp-destroys-one-at-once",
                "1-removed-1-pending",
                E2E,
                "authority-lease-reap-teardown",
            );
            assert!(lab.runtime.exists(&other));
            for decoy in &decoys.ids {
                assert!(lab.runtime.exists(decoy), "{decoy} was removed");
            }
            evidence(
                "lease-release-over-dwkp-spares-another-session",
                "container-kept",
                E2E,
                "authority-run-association",
            );
            evidence(
                "lease-release-over-dwkp-spares-foreign-containers",
                "unlabelled-and-another-stores-kept",
                E2E,
                "broker-exact-labels",
            );
            // A retry ends nothing more; the reaped runs regain nothing.
            let before = intents(&lab);
            let again = a
                .client
                .call(&super::super::state_support::release_lease_msg(
                    &a.session, a.epoch,
                ))
                .body;
            assert!(matches!(again, DwkpBody::Ack(_)), "{again:?}");
            assert_eq!(intents(&lab), before);
            evidence(
                "lease-release-over-dwkp-repeated-no-second-effect",
                "ACK-nothing-destroyed",
                E2E,
                "authority-release-idempotent",
            );
            let environments = rows(&lab, "SELECT count(*) FROM environment");
            let body = a.exec("a-3", &call(FIXTURE, &["workload-identity"]));
            assert_eq!(refusal(&body), "STALE_EPOCH");
            assert_eq!(rows(&lab, "SELECT count(*) FROM environment"), environments);
            evidence(
                "lease-reaped-run-launch-refused-over-dwkp",
                "STALE_EPOCH",
                E2E,
                "authority-lease-fence",
            );
            // The next preparation removes the pending one.
            let mut c = Peer::admit(served.path(), 3, &["process.exec:*"], binder(&served));
            let body = c.exec("c-1", &call(FIXTURE, &["workload-identity"]));
            assert!(!lab.runtime.exists(&first) && !lab.runtime.exists(&second));
            assert!(lab.runtime.exists(&other));
            evidence(
                "lease-pending-destruction-removed-by-the-next-preparation",
                "container-removed",
                E2E,
                "authority-reclamation",
            );
            lab.reap_later(&container_of(&lab, &sandboxed(&body).environment_id));
            drop(decoys);
            served.stop();
        }

        #[test]
        #[ignore = "needs a real OCI runtime: make sandbox-release-evidence"]
        fn a_takeover_a_restart_or_a_crash_ends_a_reaped_runs_environment() {
            let mut lab = Lab::new("m5d-takeover", WorkloadBudget::default());
            // The takeover: the holder's agent runs; its lease expires; a new
            // holder acquires the session, reaping the old tenure's run.
            let (caller, session, epoch, run) = admitted(&mut lab);
            let message = exec_message(
                (&session, &run, epoch),
                "takeover-1",
                &call(FIXTURE, &["workload-agent", "300"]),
            );
            let Dispatched::Parked(mut parked) = lab
                .authority()
                .dispatch_parkable(&caller, &message)
                .unwrap()
            else {
                panic!("a running launch is parked")
            };
            let environment = EnvironmentId::parse(&one(
                &lab,
                "SELECT environment_id FROM environment WHERE run_id = ?1",
                run.as_str(),
            ))
            .unwrap();
            let container = container_of(&lab, &environment);
            lab.reap_later(&container);
            for line in AGENT {
                lab.runtime.awaited(&container, line);
            }
            evidence(
                "lease-takeover-in-flight-agent-running",
                "plan-workers-and-daemon-as-10001",
                REAL,
                "runtime-census",
            );
            lab.clock
                .advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
            let since = Instant::now();
            let taker = lab.authority().connect(subject(1000));
            let Reply::Done(taken) = lab.authority().acquire_lease(&taker, &session).unwrap()
            else {
                panic!("a takeover of an expired lease")
            };
            assert_eq!(run_state(&lab, &run), "REAPED");
            assert!(
                !lab.runtime.exists(&container),
                "the takeover removed the old tenure's environment"
            );
            assert_eq!(ended(&lab, &environment), "DESTROYED:REAPED");
            evidence(
                "lease-takeover-ends-in-flight-workload-and-descendants",
                "container-removed-with-every-process",
                REAL,
                "authority-lease-reap-teardown",
            );
            let deadline = Instant::now() + Duration::from_secs(120);
            let body = loop {
                if let Some(body) = lab.authority().resume(&mut parked).unwrap() {
                    break body;
                }
                assert!(Instant::now() < deadline, "the launch was never answered");
                std::thread::sleep(Duration::from_millis(250));
            };
            let DwkpBody::ToolFailedV5(failure) = &body else {
                panic!("not failed: {body:?}")
            };
            assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN");
            assert!(
                since.elapsed() < Duration::from_secs(120),
                "{:?}",
                since.elapsed()
            );
            evidence(
                "lease-takeover-in-flight-workload-settled-unknown",
                "OUTCOME_UNKNOWN",
                REAL,
                "authority-ledger",
            );
            // The new holder inherits nothing: the key is spent.
            let next = again(&mut lab, &taker, &session, taken);
            let workloads = workload_rows(&lab);
            let message = exec_message(
                (&session, &next, taken),
                "takeover-1",
                &call(FIXTURE, &["workload-agent", "300"]),
            );
            let Dispatched::Answer(body) =
                lab.authority().dispatch_parkable(&taker, &message).unwrap()
            else {
                panic!("a replayed key was parked")
            };
            assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
            assert_eq!(workload_rows(&lab), workloads);
            evidence(
                "lease-takeover-workload-never-rerun",
                "IDEMPOTENCY_KEY_REUSED",
                REAL,
                "authority-shared-idempotency-namespace",
            );

            // A restart reaps every run, and their READY environments with
            // them: destroyed by their labels, never measured again and kept.
            let (_, _, _, kept) = admitted(&mut lab);
            let (environment, container) = lab.ready(&kept);
            let measured = |lab: &Lab| {
                audit_records(&lab.dir.state(), "environment.measured")
                    .iter()
                    .filter(|r| {
                        super::super::state_support::text(r, "environment_id")
                            == Some(environment.as_str())
                    })
                    .count()
            };
            let before = measured(&lab);
            lab.start(None);
            assert!(!lab.runtime.exists(&container));
            assert_eq!(ended(&lab, &environment), "DESTROYED:REAPED");
            evidence(
                "restart-destroys-a-reaped-runs-ready-environment",
                "container-removed",
                REAL,
                "authority-start-teardown",
            );
            assert_eq!(measured(&lab), before);
            evidence(
                "restart-measures-no-reaped-environment",
                "not-measured",
                REAL,
                "authority-start-teardown",
            );

            // W13: the lease's end and the destruction durable, nothing sent.
            lab.start(Some(stop_at(CrashPoint::ReapAfterIntent)));
            let (caller, session, epoch, run) = admitted(&mut lab);
            let (environment, container) = lab.ready(&run);
            poisoned(lab.authority().release_lease(&caller, &session, epoch));
            assert_eq!(run_state(&lab, &run), "REAPED");
            assert_eq!(ended(&lab, &environment), "DESTROYING:REAPED");
            assert!(lab.runtime.exists(&container), "nothing was sent");
            lab.start(None);
            assert!(!lab.runtime.exists(&container));
            assert_eq!(ended(&lab, &environment), "DESTROYED:REAPED");
            evidence(
                "lease-crash-v-completed-at-restart",
                "container-removed",
                REAL,
                "authority-reconciliation",
            );
        }
    }
}
