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
    use dwkd_authority::sandbox::{SandboxConfig, WorkloadBudget};
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
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    const PROBE: &str = "/usr/libexec/direwolf/sandbox-probe";
    /// A manifest entry policy denies by default: it never reaches the broker.
    const DENIED: &str = "/usr/local/bin/denied-tool";
    /// The fixture again, at a path the host has too (OD-9).
    const TRUE: &str = "/usr/bin/true";

    fn evidence(case: &str, outcome: &str) {
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
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
            let broker = Broker::start(
                &broker_socket,
                own_uid(),
                &["--allow-shared-authority-uid", "--allow-evidence-topology"],
            );
            let workspace = dir.path().join("workspace");
            std::fs::create_dir_all(&workspace).unwrap();
            // The environment's user writes the evidence's workspace; the
            // production ownership model is M5d.4's (ADR-0052 §6).
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o777)).unwrap();
            let mut ceiling = super::state_support::ceiling();
            ceiling.push("process.exec:*".to_owned());
            ceiling.push("fs.stat:*".to_owned());
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
            self.broker = Broker::start(
                &self.broker_socket,
                own_uid(),
                &["--allow-shared-authority-uid", "--allow-evidence-topology"],
            );
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
        evidence("authority-workload-completed", "exited-0-as-10001");
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
        );
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        evidence("authority-workload-environment-kept-when-clean", "ready");

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
        evidence("authority-workload-audited", "intent-outcome-no-output");
        evidence("authority-workload-taint-raised", "local-unverified");

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
        evidence("authority-workload-no-environment-refused", "refused");
        assert!(!lab.workspace.join("bare").exists());
        assert_eq!(lab.broker.count("process_start"), 0);
        evidence("authority-workload-never-on-the-host", "no-host-launch");

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
        evidence("authority-workload-not-in-manifest-refused", "refused");
        // Out of bounds.
        let mut too_long = fixture(&[], "g-3");
        too_long.wall_clock_seconds = 601;
        assert_eq!(
            refused(&mut lab, too_long),
            WorkloadReply::Refused("WALL_CLOCK_INVALID")
        );
        evidence("authority-workload-bounds-refused", "wall-clock-invalid");
        // Policy: a manifest entry no rule allows.
        assert_eq!(
            refused(&mut lab, request(DENIED, &[], "g-4")),
            WorkloadReply::Denied("DEFAULT_DENY")
        );
        evidence("authority-workload-policy-denied", "default-deny");
        // An obligation no workload can keep (`network_deny`).
        assert_eq!(
            refused(&mut lab, request(PROBE, &["hold"], "g-5")),
            WorkloadReply::Denied("OBLIGATION_UNENFORCEABLE")
        );
        evidence(
            "authority-workload-obligation-unenforceable-denied",
            "denied",
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
        evidence("authority-workload-no-capability-denied", "denied");
        assert_eq!(
            started(&lab),
            0,
            "a refused or denied workload reached the broker"
        );
        assert_eq!(workload_rows(&lab), 0, "a refusal recorded an intent");
        evidence(
            "authority-workload-refusals-record-no-intent",
            "0-rows-0-runs",
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
        );
        // And a lower level is never accepted: no workload without a READY
        // environment at CONTAINER_ISOLATION (the only level `oci` earns).
        let reply = lab
            .authority()
            .workload_run(&run, &fixture(&["mark", "/workspace/after"], "g-8"))
            .unwrap();
        assert_eq!(reply, WorkloadReply::Refused("NO_ENVIRONMENT"));
        evidence("authority-workload-no-ready-environment-refused", "refused");
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
        evidence("authority-workload-budget-seconds-charged-whole", "refused");
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
        evidence("authority-workload-budget-count-exhausted", "refused");
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
        evidence("crash-w8-unknown", "interrupted");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence("crash-w8-environment-destroyed", "destroyed-on-restart");
        assert!(!lab.workspace.join("w8").exists());
        evidence("crash-w8-never-ran", "no-marker");

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
        assert_eq!(lab.runtime.others(&container), 1, "W9 is while it runs");
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
        );
        assert!(!marker.exists(), "a restart ran it again");
        evidence("crash-w10-never-rerun", "no-marker");

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
        // A clean residue left nothing to destroy: the environment was
        // measured again at the restart and kept.
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        evidence("crash-w11-outcome-kept", "completed");
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
        evidence("unknown-ending-recorded", reason);
        // The workload outlived its broker; the destruction is durable and
        // completes once a broker answers.
        assert!(lab.runtime.exists(&container));
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroying);
        lab.restart_broker();
        let report = lab.authority().environment_reconcile().unwrap();
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence("unknown-ending-environment-destroyed", "destroyed");
        let state: String = super::state_support::raw(&lab.dir.state())
            .query_row(
                "SELECT state FROM workload WHERE idempotency_key = 'u-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "UNKNOWN");
        evidence("unknown-ending-never-rerun", "unknown");
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
        );
        let text = String::from_utf8(out.stdout.content.to_bytes()).unwrap();
        assert!(text.contains("uid=10001"), "{text}");
        assert_eq!(out.exit_code.map(|c| c.get()), Some(0));
        evidence("public-exec-runs-as-the-sandbox-user", "uid-10001");
        // Who asked is the kernel's word for the connection, in the intent.
        let intent =
            super::state_support::audit_records(&lab.dir.state(), "workload.intent_recorded");
        let last = intent.last().unwrap();
        assert_eq!(
            super::state_support::text(last, "subject"),
            Some(format!("uid:{}", own_uid()).as_str())
        );
        assert_eq!(super::state_support::int(last, "protocol_version"), Some(5));
        evidence("public-exec-caller-from-the-transport", "uid");
        assert_eq!(lab.broker.count("process_start"), 0, "a host launch");
        evidence("public-exec-never-on-the-host", "no-host-launch");

        // Output is bounded by the call's own narrowing; every byte counted.
        let body = a.exec(
            "p-2",
            r#"{"executable":"/usr/libexec/direwolf/sandbox-fixture","args":["workload-print","5000","0"],"max_stream_bytes":1024}"#,
        );
        let out = sandboxed(&body);
        assert_eq!(out.stdout.content.to_bytes().len(), 1024);
        assert_eq!(out.stdout.observed.get(), 5000);
        assert!(out.stdout.truncated);
        evidence("public-exec-output-bounded", "1024-of-5000");
        // A daemonised grandchild is ended by the environment's init.
        let body = a.exec("p-3", &call(FIXTURE, &["workload-daemon"]));
        let out = sandboxed(&body);
        assert_eq!(
            out.residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        assert!(out.ended_processes.get() >= 1, "{out:?}");
        assert_eq!(lab.runtime.others(&container), 0);
        evidence("public-exec-detached-child-reaped", "residue-pass");

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
        evidence("public-exec-authority-answers-during-a-workload", "preview");
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
        evidence("public-exec-broker-answers-during-a-workload", "fs-stat");
        let body = b.exec("b-1", &call(FIXTURE, &["workload-identity"]));
        let other = sandboxed(&body);
        assert_ne!(other.environment_id.as_str(), container.as_str());
        evidence(
            "public-exec-two-runs-at-once-in-two-environments",
            "completed",
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
        evidence("public-exec-key-from-another-holder-fenced", "STALE_EPOCH");
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
        evidence("public-exec-key-never-runs-twice", "IDEMPOTENCY_KEY_REUSED");
        evidence(
            "public-exec-cross-tool-key-refused",
            "IDEMPOTENCY_KEY_REUSED",
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
        );
        evidence("public-no-lifecycle-operation", "UNKNOWN_OPERATION");

        // A run that ended leaves its environment idle until the authority
        // next prepares one; then it is destroyed first (ADR-0052 §2a).
        let release = super::state_support::release_run_msg(&a.session, &a.run, a.epoch);
        let released = a.client.call(&release).body;
        assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
        assert!(lab.runtime.exists(&container), "released, still idle");
        let mut c = Peer::admit(served.path(), 3, &["process.exec:*"], binder(&served));
        let body = c.exec("c-1", &call(FIXTURE, &["workload-identity"]));
        assert_eq!(
            sandboxed(&body).residue,
            dwk_proto::dwkp::sandboxops::ResidueVerdict::Pass
        );
        assert!(
            !lab.runtime.exists(&container),
            "the ended run's environment was reclaimed"
        );
        evidence(
            "public-exec-ended-runs-environment-reclaimed",
            "container-removed",
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
        evidence("public-exec-unknown-outcome-reported", "OUTCOME_UNKNOWN");
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
        );
        // The grant covers that executable only.
        let body = a.exec("o-2", &call(FIXTURE, &["workload-identity"]));
        assert_eq!(plan_action(&body).decision.reason.as_str(), "NO_CAPABILITY");
        evidence("od9-concrete-grant-covers-nothing-else", "NO_CAPABILITY");
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
        evidence("public-exec-budget-exhausted-refused", "BUDGET_EXHAUSTED");
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
            evidence(&format!("shipped-{pack}-git-runs-with-hygiene"), "HYGIENE");
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
                 [executables]\n\"{FIXTURE}\" = \"{fixture}\"\n",
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
        evidence("production-serve-prepares-and-runs", "completed-as-10001");

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
        );
        let mut b = Peer::admit(&socket, 1, &["process.exec:*"], bind);
        let body = b.exec("s-2", &call(FIXTURE, &["mark", "/workspace/rerun"]));
        assert_eq!(refusal(&body), "IDEMPOTENCY_KEY_REUSED");
        assert!(!lab.workspace.join("rerun").exists());
        evidence(
            "production-replay-after-restart-refused",
            "IDEMPOTENCY_KEY_REUSED",
        );
    }
}
