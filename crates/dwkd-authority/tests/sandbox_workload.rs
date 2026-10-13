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
//! The workload operation is an in-process authority API with no DWKP route
//! (ADR-0052 §2): this test process is the only caller, exactly as the
//! evidence harness is in the product. The policy is the evidence's own
//! operator policy — the fixture allowed in a sandbox by path and digest —
//! never described as shipped behaviour.

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
    use std::process::{Command, Output};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::brokerp::sandbox::{NetworkTopology, Verdict};
    use dwk_proto::brokerp::workload::WorkloadEnding;
    use dwk_proto::wire::id::{EnvironmentId, RunId};
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::sandbox::{SandboxConfig, WorkloadBudget};
    use dwkd_authority::state::{
        Authority, AuthorityError, CrashHook, CrashPoint, EnvironmentReply, EnvironmentState,
        HookAction, ManualClock, Mode, Reply, StartOptions, StartupConfig, WorkloadReply,
        WorkloadRequest, WorkloadState, WorkspaceId, WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::state_support::{
        START_MS, TempDir, admit_msg, audit_events, policy, profile, session, spawn_guard, subject,
    };
    use super::transport_support::own_uid;

    const SUITE: &str = "sandbox-authority-workload";
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    const PROBE: &str = "/usr/libexec/direwolf/sandbox-probe";
    /// A manifest entry policy denies by default: it never reaches the broker.
    const DENIED: &str = "/usr/local/bin/denied-tool";

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
    /// can keep yet; nothing on the host; everything else denied.
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
id = "the-probe-only-with-hygiene"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{PROBE}"]
obligations = ["workspace_exec_hygiene"]

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

    impl Lab {
        fn new(tag: &str, budget: WorkloadBudget) -> Self {
            let fixture = var("DW_SANDBOX_FIXTURE_SHA256");
            let probe = var("DW_SANDBOX_PROBE_SHA256");
            let sandbox = SandboxConfig::new(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                &var("DW_SANDBOX_WORKLOAD_IMAGE"),
                &probe,
                NetworkTopology::NoNetwork,
            )
            .unwrap()
            .with_workloads(
                &[
                    (FIXTURE, &fixture),
                    (PROBE, &probe),
                    (DENIED, &"d".repeat(64)),
                ],
                budget,
            )
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
            let config = StartupConfig::new(
                policy("m5d", &workload_policy(&fixture)),
                Mode::Balanced,
                ceiling,
            );
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
                    &["process.exec:*", "fs.read:*"],
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
            self.authority = None;
            let link: Arc<dyn EffectBroker> =
                Arc::new(UnixBroker::new(self.broker_socket.clone(), own_uid()));
            let (mut authority, _) = {
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
            authority.attach_sandbox(self.sandbox.clone()).unwrap();
            self.authority = Some(authority);
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
        // An obligation no workload can keep yet (M5d.2).
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
}
