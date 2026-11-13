//! M5a's lifecycle evidence (ADR-0047 §§11–13): the **real** authority state
//! (`kernel.db`, `audit.log`), the **released** `dwkd-broker`, and a **real**
//! OCI runtime — the authority → broker → runtime path, end to end, with its
//! crash windows exercised by stopping the authority where a crash would and
//! starting a new incarnation on the same files.
//!
//! Every test is `#[ignore]`d: it needs a runtime, the evidence image and the
//! pinned digests, which `make sandbox-foundation-evidence` provides
//! (`DW_SANDBOX_*`). Run any other way it panics `NOT EXERCISED`.
//!
//! The environment operations are an in-process authority API with no DWKP
//! route (ADR-0047 §3): this test process is the only caller, exactly as the
//! evidence harness is in the product.
//!
//! M5b (ADR-0048) adds one test, run by `make sandbox-egress-evidence`: a
//! `PROXY_ONLY` environment whose grant the authority derives from the run's
//! own `network.https` grants, used through the real relay and proxy, and
//! reconciled with its helper containers.
//!
//! F-17 (ADR-0061, Proposed) adds two, run by the same task: since F-17 a
//! tunnel is carried only while a workload holds the egress authorisation
//! the authority decided for it -- by both gates, the run's novelty and the
//! workspace's exposure -- so every tunnel here is opened by a workload the
//! real authority runs (`workload_run`), under an evidence policy whose one
//! `network.https` allow rule names exactly the hosts the cases need
//! (`when.environment = "sandbox"`, `when.host_matches`); a granted host no
//! rule allows is the standing control, refused by the proxy before its name
//! is resolved.

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
mod runtime_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use dwk_proto::brokerp::egress::EgressDisposition;
    use dwk_proto::brokerp::sandbox::{AssuranceLevel, NetworkTopology};
    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::json::{Object, Value, to_canonical_string};
    use dwk_proto::wire::id::{EnvironmentId, RunId, SessionId};
    use dwk_proto::wire::scalar::{Epoch, IdempotencyKey};
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::sandbox::{EgressConfig, SandboxConfig, WorkloadBudget, WorkspaceSetting};
    use dwkd_authority::state::{
        Authority, AuthorityError, CallerContext, CrashHook, CrashPoint, EnvironmentReply,
        EnvironmentState, HookAction, ManualClock, Mode, ReconcileReport, Reply, StartOptions,
        StartupConfig, ToolReply, ToolRequest, WorkloadReply, WorkloadRequest, WorkspaceId,
        WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::state_support::{
        START_MS, TempDir, admit_msg, audit_events, audit_records, balanced, ceiling, decode, id,
        install_fixtures, int, policy, profile, raw, session, spawn_guard, subject, text,
    };
    use super::transport_support::own_uid;

    const SUITE: &str = "sandbox-authority";
    /// Where the evidence image carries the test-only workload fixture.
    const FIXTURE: &str = "/usr/libexec/direwolf/sandbox-fixture";
    /// What every line of this file is (M5e.1): the real authority's own
    /// environment API -- it has no DWKP route (ADR-0047 §3) -- over the
    /// released broker and a real runtime.
    const LEVEL: &str = "real-oci";

    /// One line of `suite`'s evidence, printed only after the assertions
    /// before it held: the case, how it ended, and what enforced or observed
    /// it (M5e.1, OD-E1) -- canonical JSON, so no outcome can break the line.
    fn evidence_line(suite: &str, case: &str, outcome: &str, enforcement: &str) {
        let mut fields = Object::new();
        for (key, value) in [
            ("suite", suite),
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

    fn evidence(case: &str, outcome: &str, enforcement: &str) {
        evidence_line(SUITE, case, outcome, enforcement);
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-foundation-evidence`, which \
                 builds the evidence images and pins their digests"
            )
        })
    }

    /// The runtime client, as this test uses it directly: to look at what
    /// exists, and to make the containers the product never would.
    #[derive(Clone)]
    struct Runtime {
        client: PathBuf,
        socket: String,
    }

    /// Containers this test made itself, removed when its test ends.
    static CREATED: Mutex<Vec<String>> = Mutex::new(Vec::new());

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

        /// Every container labelled as `environment`, by id.
        fn labelled(&self, environment: &EnvironmentId) -> Vec<String> {
            self.ok(&[
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                &format!("label=io.direwolf.environment={}", environment.as_str()),
            ])
            .lines()
            .map(str::to_owned)
            .collect()
        }

        /// Whether the runtime holds `id`: a listing of exactly its id,
        /// never an inspection's failure (`runtime_support`).
        fn exists(&self, id: &str) -> bool {
            super::runtime_support::exists(|args| self.docker(args), id)
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

        /// A container this test makes itself, holding, with these labels.
        fn create(&self, name: &str, image: &str, labels: &[(&str, &str)]) -> String {
            let mut argv: Vec<String> = vec!["create".into(), "--name".into(), name.into()];
            for (key, value) in labels {
                argv.push("--label".into());
                argv.push(format!("{key}={value}"));
            }
            for word in [
                "--network",
                "none",
                "--entrypoint",
                "/usr/libexec/direwolf/sandbox-probe",
                image,
                "hold",
            ] {
                argv.push(word.into());
            }
            let words: Vec<&str> = argv.iter().map(String::as_str).collect();
            let id = self.ok(&words).trim().to_owned();
            CREATED.lock().unwrap().push(id.clone());
            id
        }

        fn remove(&self, id: &str) {
            let _ = self.docker(&["container", "rm", "--force", "--volumes", id]);
        }
    }

    /// Everything a test made or had made, removed when it ends — passing
    /// or failing: every container labelled with its store, and the ones it
    /// created itself.
    struct Reaper {
        runtime: Runtime,
        store: Mutex<Option<String>>,
    }

    impl Drop for Reaper {
        fn drop(&mut self) {
            let mut ids: Vec<String> = CREATED
                .lock()
                .map(|mut c| std::mem::take(&mut *c))
                .unwrap_or_default();
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
                ids.extend(
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .map(str::to_owned),
                );
            }
            for id in ids {
                self.runtime.remove(&id);
            }
        }
    }

    /// A real authority on a fresh store, a real broker, and a workspace.
    struct Lab {
        dir: TempDir,
        clock: Arc<ManualClock>,
        config: StartupConfig,
        broker_socket: PathBuf,
        _broker: Broker,
        authority: Option<Authority>,
        sandbox: SandboxConfig,
        workspace: WorkspaceId,
        next_session: u64,
        runtime: Runtime,
        reaper: Reaper,
        /// The profile every run is admitted under.
        profile: &'static str,
        /// Workloads run so far: each its own idempotency key.
        workloads: u64,
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
        fn new(tag: &str, image: &str, probe: &str) -> Self {
            let sandbox = SandboxConfig::new(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                image,
                probe,
                NetworkTopology::NoNetwork,
                WorkspaceSetting::UnverifiedEvidence,
            )
            .unwrap();
            Self::with(
                tag,
                &[
                    "--allow-shared-authority-uid",
                    "--allow-evidence-topology",
                    "--allow-unverified-workspace",
                ],
                sandbox,
                balanced(),
            )
        }

        /// A lab whose sandbox is `PROXY_ONLY` (M5b), its broker resolving
        /// egress names from `fixture` — the evidence's, never production's —
        /// its workloads the fixture by digest, and its policy `policy_text`
        /// (F-17: every tunnel is a workload's, decided by that policy).
        fn proxy_only(
            tag: &str,
            (image, probe, relay): (&str, &str, &str),
            fixture: &str,
            policy_text: &str,
        ) -> Self {
            let fixture_sha = var("DW_SANDBOX_FIXTURE_SHA256");
            let sandbox = SandboxConfig::proxy_only(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                image,
                probe,
                EgressConfig::new(relay, 4, 1 << 20, 1 << 20).unwrap(),
                WorkspaceSetting::UnverifiedEvidence,
            )
            .unwrap()
            .with_workloads(
                &[(FIXTURE, fixture_sha.as_str())],
                WorkloadBudget::default(),
            )
            .unwrap();
            let mut ceiling = ceiling();
            ceiling.push("process.exec:*".to_owned());
            // F-01: a run holding external content writes the workspace.
            ceiling.push("fs.write:*".to_owned());
            ceiling.push("fs.create:*".to_owned());
            let config =
                StartupConfig::new(policy("m5b-egress", policy_text), Mode::Balanced, ceiling);
            let mut lab = Self::with(
                tag,
                &[
                    "--allow-shared-authority-uid",
                    "--allow-evidence-egress",
                    fixture,
                    // The evidence's own workspace (M5d.4): acknowledged.
                    "--allow-unverified-workspace",
                ],
                sandbox,
                config,
            );
            // The researcher's grants, and the fixture as a workload.
            lab.authority()
                .operator()
                .install_agent_profile(&profile(
                    "egress-agent",
                    &[
                        "process.exec:*",
                        "network.https:*.example.com",
                        "network.https:github.com",
                        "network.http:*",
                    ],
                    &[],
                    PrivacyClass::Any,
                ))
                .unwrap();
            lab.profile = "egress-agent";
            lab
        }

        /// Run the fixture with `args` as one of `run`'s workloads, decided
        /// by the real authority (F-17): its line.
        fn fixture(&mut self, run: &RunId, args: &[&str]) -> String {
            let request = WorkloadRequest {
                executable: FIXTURE.to_owned(),
                args: args.iter().map(|a| (*a).to_owned()).collect(),
                stream_limit: 65_536,
                wall_clock_seconds: 60,
                key: format!("f17-{}", self.workloads),
            };
            self.workloads += 1;
            let reply = self.authority().workload_run(run, &request).unwrap();
            let WorkloadReply::Completed(outcome) = reply else {
                panic!("{args:?} did not complete: {reply:?}")
            };
            String::from_utf8(outcome.stdout.clone())
                .unwrap()
                .trim()
                .to_owned()
        }

        fn with(
            tag: &str,
            broker_args: &[&str],
            sandbox: SandboxConfig,
            config: StartupConfig,
        ) -> Self {
            let runtime = Runtime::load();
            let reaper = Reaper {
                runtime: runtime.clone(),
                store: Mutex::new(None),
            };
            let dir = TempDir::new(tag);
            let broker_socket = dir.path().join("broker").join("broker.sock");
            let broker = Broker::start(&broker_socket, own_uid(), broker_args);
            let root = dir.path().join("workspace");
            std::fs::create_dir_all(&root).unwrap();
            // The environment's user writes the evidence's workspace; the
            // production ownership model is M5d's.
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
            let mut lab = Self {
                dir,
                clock: Arc::new(ManualClock::new(START_MS)),
                config,
                broker_socket,
                _broker: broker,
                authority: None,
                sandbox,
                workspace: WorkspaceId::new("ws").unwrap(),
                next_session: 1,
                runtime,
                reaper,
                profile: "researcher",
                workloads: 0,
            };
            lab.start(None);
            let authority = lab.authority();
            install_fixtures(authority);
            let mut operator = authority.operator();
            operator
                .install_workspace(
                    &WorkspaceId::new("ws").unwrap(),
                    WorkspaceSensitivity::Private,
                )
                .unwrap();
            operator
                .install_workspace_root(&WorkspaceId::new("ws").unwrap(), root.to_str().unwrap())
                .unwrap();
            lab
        }

        /// A new incarnation on the same files, with the sandbox attached:
        /// what reconciliation did.
        fn start(&mut self, hook: Option<CrashHook>) -> ReconcileReport {
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
            let report = authority.attach_sandbox(self.sandbox.clone()).unwrap();
            self.authority = Some(authority);
            report
        }

        fn authority(&mut self) -> &mut Authority {
            self.authority.as_mut().unwrap()
        }

        /// A new active run, in a new session bound to the workspace.
        fn admit(&mut self) -> RunId {
            self.admit_with(&[])
        }

        /// A new active run that requested `capabilities`.
        fn admit_with(&mut self, capabilities: &[&str]) -> RunId {
            let n = self.next_session;
            self.next_session += 1;
            let workspace = self.workspace.clone();
            let profile = self.profile;
            let authority = self.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &workspace)
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

        /// The one environment id the store holds a `PREPARING` or
        /// `DESTROYING` row for, read by an observer's own connection.
        fn row(&self, state: &str) -> EnvironmentId {
            let conn = raw(&self.dir.state());
            let id: String = conn
                .query_row(
                    "SELECT environment_id FROM environment WHERE state = ?1",
                    [state],
                    |row| row.get(0),
                )
                .unwrap();
            EnvironmentId::parse(&id).unwrap()
        }
    }

    fn poisoned<T: std::fmt::Debug>(result: Result<T, AuthorityError>) {
        assert!(
            matches!(result, Err(AuthorityError::Poisoned(_))),
            "{result:?}"
        );
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn the_lifecycle_is_durable_before_every_effect() {
        let image = var("DW_SANDBOX_IMAGE");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        let mut lab = Lab::new("m5a-life", &image, &probe);

        // W2: the intent is durable and the broker has been told nothing.
        lab.start(Some(stop_at(CrashPoint::EnvironmentAfterIntent)));
        let run = lab.admit();
        poisoned(lab.authority().environment_prepare(&run));
        let intended = lab.row("PREPARING");
        assert!(
            lab.runtime.labelled(&intended).is_empty(),
            "nothing was created before the intent was acted on"
        );
        evidence(
            "prepare-intent-durable-before-broker",
            "preparing-row-no-container",
            "authority-ledger-intent-first",
        );
        let report = lab.start(None);
        assert!(report.missing >= 1, "{report:?}");
        assert_eq!(lab.state_of(&intended), EnvironmentState::Lost);
        evidence(
            "crash-w2-after-intent-lost",
            "unknown-then-lost",
            "authority-reconciliation",
        );

        // The whole path: intent, broker, runtime, measurement, outcome.
        let run = lab.admit();
        let (environment, container) = lab.ready(&run);
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        assert!(lab.runtime.exists(&container));
        evidence("prepare-ready-recorded", "ready", "authority-ledger");
        let measured = lab.authority().environment_measure(&environment).unwrap();
        let EnvironmentReply::Clean(report) = measured else {
            panic!("not clean: {measured:?}")
        };
        assert_eq!(
            report.judgement.declared.0,
            AssuranceLevel::ContainerIsolation
        );
        assert_eq!(
            report.judgement.measured.0,
            AssuranceLevel::ContainerIsolation
        );
        assert_eq!(
            report.judgement.effective.0,
            AssuranceLevel::ContainerIsolation
        );
        evidence(
            "effective-assurance-container-isolation",
            "declared-measured-effective",
            "authority-environment-judgement",
        );
        evidence("measure-clean", "clean", "authority-environment-judgement");
        assert_eq!(
            lab.authority().environment_prepare(&run).unwrap(),
            EnvironmentReply::Refused("ENVIRONMENT_EXISTS")
        );
        evidence(
            "one-environment-per-run",
            "environment-exists",
            "authority-environment-decision",
        );

        // A restart reaps the run, and since the M5d closeout its READY
        // environment with it (ADR-0052 §8, amending ADR-0047 §12's W5, which
        // measured it again and kept it): destroyed by its labels.
        let report = lab.start(None);
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));

        // W6: the destruction is durable, the broker told nothing.
        lab.start(Some(stop_at(CrashPoint::EnvironmentDestroyAfterIntent)));
        let run = lab.admit();
        let (environment, container) = lab.ready(&run);
        poisoned(lab.authority().environment_destroy(&environment));
        assert_eq!(lab.row("DESTROYING"), environment);
        assert!(lab.runtime.exists(&container), "not yet removed");
        evidence(
            "destroy-intent-durable-before-broker",
            "destroying-row-container-present",
            "authority-ledger-intent-first",
        );
        let report = lab.start(None);
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence(
            "crash-w6-destroy-intent-completed",
            "destroyed-on-restart",
            "authority-reconciliation",
        );

        // An ordinary destruction, and a second one.
        let run = lab.admit();
        let (environment, container) = lab.ready(&run);
        let destroyed = lab.authority().environment_destroy(&environment).unwrap();
        assert!(
            matches!(
                destroyed,
                EnvironmentReply::Destroyed {
                    already_gone: false,
                    ..
                }
            ),
            "{destroyed:?}"
        );
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence("destroy-recorded", "destroyed", "authority-ledger");
        assert_eq!(
            lab.authority().environment_destroy(&environment).unwrap(),
            EnvironmentReply::Refused("ENVIRONMENT_ENDED")
        );
        evidence(
            "destroy-idempotent",
            "ended-refused-nothing-sent",
            "authority-ledger",
        );

        let events = audit_events(&lab.dir.state());
        for event in [
            "environment.intent_recorded",
            "environment.outcome_unknown",
            "environment.lost",
            "environment.ready",
            "environment.measured",
            "environment.destroy_intent",
            "environment.destroyed",
            "environment.reconciled",
        ] {
            assert!(events.iter().any(|e| e == event), "{event} missing");
        }
        evidence("audit-lifecycle", "8-events", "authority-audit");
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn reconciliation_after_crashes_reaps_exactly_and_spares_foreign_containers() {
        let image = var("DW_SANDBOX_IMAGE");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        let mut lab = Lab::new("m5a-reconcile", &image, &probe);
        let rt = lab.runtime.clone();

        // A READY environment, which a copy of its labels will make
        // ambiguous.
        let first_run = lab.admit();
        let (ready, ready_container) = lab.ready(&first_run);
        let store = rt.label(&ready_container, "io.direwolf.store");
        let exact = |environment: &str, run: &str| {
            vec![
                ("io.direwolf.owner", "direwolf".to_owned()),
                ("io.direwolf.schema", "2".to_owned()),
                ("io.direwolf.store", store.clone()),
                ("io.direwolf.environment", environment.to_owned()),
                ("io.direwolf.run", run.to_owned()),
                ("io.direwolf.profile", "oci-strict".to_owned()),
                ("io.direwolf.role", "environment".to_owned()),
            ]
        };
        let pairs =
            |labels: &[(&'static str, String)]| -> Vec<(&'static str, String)> { labels.to_vec() };
        let create = |name: &str, labels: &[(&'static str, String)]| {
            let refs: Vec<(&str, &str)> = labels.iter().map(|(k, v)| (*k, v.as_str())).collect();
            rt.create(name, &image, &refs)
        };
        let tag = std::process::id();
        // The twin exists before any restart: a restart reaps the READY
        // environment's run, and its destruction (the M5d closeout) must meet
        // the ambiguity, not run before it.
        let twin = create(
            &format!("dw-m5a-twin-{tag}"),
            &pairs(&exact(ready.as_str(), first_run.as_str())),
        );

        // W4: the broker created, measured and kept a container; the
        // authority stopped before recording it.
        lab.start(Some(stop_at(CrashPoint::EnvironmentAfterBroker)));
        let run = lab.admit();
        poisoned(lab.authority().environment_prepare(&run));
        let unrecorded_outcome = lab.row("PREPARING");
        let made = rt.labelled(&unrecorded_outcome);
        assert_eq!(made.len(), 1, "the broker made it");

        // Containers the authority must not touch.
        let unrelated = create(&format!("dw-m5a-unrelated-{tag}"), &[]);
        let copied_env = EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF").unwrap();
        let copied = create(
            &format!("dw-m5a-copied-{tag}"),
            &pairs(&exact(copied_env.as_str(), run.as_str())),
        );
        // A copy naming a recorded environment of another run.
        let copied_run = create(
            &format!("dw-m5a-copied-run-{tag}"),
            &pairs(&exact(
                unrecorded_outcome.as_str(),
                "run_01M24BB8G3E0A851TRWE3M8FZF",
            )),
        );

        let report = lab.start(None);
        // The one the broker made and the authority never recorded the
        // outcome of: UNKNOWN at start, then removed by its labels.
        assert!(!rt.exists(&made[0]), "{report:?}");
        assert_eq!(
            lab.state_of(&unrecorded_outcome),
            EnvironmentState::Destroyed
        );
        assert!(report.pending_destroyed >= 1, "{report:?}");
        evidence(
            "crash-w4-after-broker-reaped",
            "unknown-then-destroyed",
            "authority-reconciliation",
        );
        assert!(rt.exists(&unrelated));
        evidence(
            "foreign-unrelated-survive",
            "present",
            "exact-label-ownership",
        );
        assert!(rt.exists(&copied), "a copied label is never reaped");
        assert!(rt.exists(&copied_run), "a copied run label is never reaped");
        assert!(report.foreign >= 2, "{report:?}");
        evidence(
            "foreign-copied-labels-survive",
            "copied-env-and-copied-run-present",
            "exact-label-ownership",
        );
        // Its run was reaped, so its destruction is recorded; the twin makes
        // it ambiguous, and nothing is removed under an ambiguity.
        assert!(rt.exists(&twin) && rt.exists(&ready_container));
        assert_eq!(lab.state_of(&ready), EnvironmentState::Destroying);
        assert!(report.ambiguous >= 1, "{report:?}");
        evidence(
            "ambiguous-twins-untouched",
            "both-present-record-untouched",
            "authority-reconciliation",
        );
        rt.remove(&twin);

        // An orphan: an environment the store recorded and ended, whose
        // container nonetheless exists — removed, exactly.
        let orphan = create(
            &format!("dw-m5a-orphan-{tag}"),
            &pairs(&exact(
                unrecorded_outcome.as_str(),
                lab.authority()
                    .environment_record(&unrecorded_outcome)
                    .unwrap()
                    .unwrap()
                    .run
                    .as_str(),
            )),
        );
        let report = lab.authority().environment_reconcile().unwrap();
        assert!(!rt.exists(&orphan), "{report:?}");
        assert_eq!(report.orphans_reaped, 1, "{report:?}");
        assert!(rt.exists(&unrelated) && rt.exists(&copied) && rt.exists(&copied_run));
        evidence(
            "orphan-ended-record-reaped",
            "removed-exactly",
            "authority-reconciliation",
        );
        for id in [&unrelated, &copied, &copied_run] {
            rt.remove(id);
        }
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-foundation-evidence"]
    fn drift_found_by_the_authority_destroys_the_environment() {
        let image = var("DW_SANDBOX_IMAGE");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        let mut lab = Lab::new("m5a-drift", &image, &probe);
        let run = lab.admit();
        let (environment, container) = lab.ready(&run);
        lab.runtime
            .ok(&["container", "update", "--pids-limit", "4096", &container]);
        let reply = lab.authority().environment_measure(&environment).unwrap();
        let EnvironmentReply::Drifted {
            reason,
            destroyed,
            report,
            ..
        } = reply
        else {
            panic!("not drift: {reply:?}")
        };
        assert_eq!(reason, "RESOURCE_LIMIT_FAILED");
        assert!(destroyed);
        let report = report.unwrap();
        assert_eq!(report.judgement.effective.0, AssuranceLevel::None);
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence(
            "drift-destroyed",
            "resource-limit-failed-effective-none",
            "authority-environment-judgement",
        );
    }

    // ---- M5b: PROXY_ONLY, granted from the run --------------------------

    const EGRESS_SUITE: &str = "sandbox-authority-egress";

    fn egress_evidence(case: &str, outcome: &str, enforcement: &str) {
        evidence_line(EGRESS_SUITE, case, outcome, enforcement);
    }

    /// A loopback origin: counts connections, answers five bytes.
    fn origin() -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                count.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 4096];
                    let mut replied = false;
                    while let Ok(n) = stream.read(&mut buffer) {
                        if n == 0 {
                            break;
                        }
                        if !replied {
                            let _ = stream.write_all(b"rrrrr");
                            replied = true;
                        }
                    }
                });
            }
        });
        (port, accepted)
    }

    fn strings(object: &dwk_proto::json::Object, key: &str) -> Vec<String> {
        match object.get(key) {
            Some(dwk_proto::json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    dwk_proto::json::Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The capabilities a `run.admitted` record says were granted, as text.
    fn granted_capabilities(admitted: &dwk_proto::json::Object) -> Vec<String> {
        let Some(dwk_proto::json::Value::Array(grants)) = admitted.get("granted") else {
            return Vec::new();
        };
        grants
            .iter()
            .filter_map(|grant| match grant {
                dwk_proto::json::Value::Object(grant) => {
                    text(grant, "capability").map(str::to_owned)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn a_proxy_only_environment_reaches_exactly_the_runs_https_hosts() {
        let image = var("DW_EGRESS_IMAGE_FIXTURE");
        let probe = var("DW_SANDBOX_PROBE_SHA256");
        let relay = var("DW_EGRESS_RELAY_SHA256");
        let (port, accepted) = origin();
        let fixture_dir = TempDir::new("m5b-fixture");
        let fixture = fixture_dir.path().join("egress-fixture.txt");
        std::fs::write(
            &fixture,
            "resolve origin.example.com 127.0.0.1\nresolve api.example.com 127.0.0.1\n\
             resolve methods.example.com 127.0.0.1\nresolve counted.example.com 127.0.0.1\n\
             allow 127.0.0.1\n",
        )
        .unwrap();
        let mut lab = Lab::proxy_only(
            "m5b-egress",
            (&image, &probe, &relay),
            fixture.to_str().unwrap(),
            &egress_policy(),
        );
        let rt = lab.runtime.clone();

        // The run asks for one exact host on the origin's port, one exact
        // host on 443, a wildcard, and plain HTTP -- and for three grants
        // that carry a constraint: two of hosts nothing else names, one of
        // the destination its unconstrained grant already gives.
        let exact = format!("network.https:origin.example.com:{port}");
        let methods = format!("network.https:methods.example.com:{port}?methods=GET");
        let counted = format!("network.https:counted.example.com:{port}?max_requests=1");
        let both = format!("network.https:origin.example.com:{port}?methods=GET&max_requests=1");
        let run = lab.admit_with(&[
            &exact,
            "network.https:github.com",
            "network.https:*.example.com",
            "network.http:*",
            &methods,
            &counted,
            &both,
            // F-17: the tunnels are workloads' (ADR-0061, Proposed).
            "process.exec:*",
        ]);
        let (environment, _container) = lab.ready(&run);
        let intent = audit_records(&lab.dir.state(), "environment.intent_recorded")
            .pop()
            .unwrap();
        let mut targets = strings(&intent, "egress_targets");
        targets.sort();
        let mut expected = vec![
            format!("origin.example.com:{port}"),
            "github.com:443".to_owned(),
        ];
        expected.sort();
        assert_eq!(targets, expected, "{intent:?}");
        assert_eq!(text(&intent, "relay_sha256"), Some(relay.as_str()));
        assert_eq!(text(&intent, "network"), Some("PROXY_ONLY"));
        assert_eq!(int(&intent, "egress_max_tunnels"), Some(4));
        egress_evidence(
            "grant-from-run-exact-https",
            &targets.join("+"),
            "authority-grant-derivation",
        );
        egress_evidence(
            "grant-wildcard-and-plain-http-not-destinations",
            "absent",
            "authority-grant-derivation",
        );
        // The three constrained grants were granted -- the admission's own
        // record names each -- and none is a destination: an opaque tunnel
        // could keep neither `methods` nor `max_requests` (ADR-0060). The
        // origin's destination is there once, from its unconstrained grant.
        let admitted = audit_records(&lab.dir.state(), "run.admitted")
            .pop()
            .unwrap();
        let granted = granted_capabilities(&admitted);
        for constrained in [&methods, &counted, &both] {
            assert!(
                granted.contains(constrained),
                "{constrained} was not granted: {granted:?}"
            );
        }
        egress_evidence(
            "grant-constrained-https-not-destinations",
            "granted-and-absent",
            "authority-grant-derivation",
        );
        egress_evidence(
            "audit-intent-records-grant",
            "targets+relay+budgets",
            "authority-audit",
        );

        // Through the real relay and proxy, from workloads the authority runs
        // and decides (F-17): the exact host is reached; a name the wildcard
        // covers, but no exact grant names, is not.
        let p = port.to_string();
        let line = lab.fixture(
            &run,
            &[
                "egress-connect",
                "origin.example.com",
                &p,
                "origin.example.com",
                "100",
            ],
        );
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        egress_evidence(
            "tunnel-through-authority-prepared-environment",
            "200-and-reached",
            "relay-and-connect-proxy-grant",
        );
        let line = lab.fixture(
            &run,
            &[
                "egress-connect",
                "api.example.com",
                &p,
                "api.example.com",
                "0",
            ],
        );
        assert!(line.contains("TARGET_NOT_GRANTED"), "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        egress_evidence(
            "wildcard-covered-name-not-granted",
            "target-not-granted",
            "connect-proxy:grant",
        );
        // Nor is a name only a constrained grant names: the proxy refuses it,
        // and the origin that name resolves to is not reached.
        for host in ["methods.example.com", "counted.example.com"] {
            let line = lab.fixture(&run, &["egress-connect", host, &p, host, "0"]);
            assert!(line.contains("TARGET_NOT_GRANTED"), "{host}: {line}");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        egress_evidence(
            "constrained-grant-name-not-granted",
            "target-not-granted",
            "connect-proxy:grant",
        );

        // Measured: clean, its counters audited.
        let measured = lab.authority().environment_measure(&environment).unwrap();
        let EnvironmentReply::Clean(report) = measured else {
            panic!("not clean: {measured:?}")
        };
        let counters = report.egress.unwrap();
        assert!(counters.count(EgressDisposition::TargetNotGranted) >= 1);
        let record = audit_records(&lab.dir.state(), "environment.measured")
            .pop()
            .unwrap();
        assert!(
            int(&record, "egress_bytes_upstream").unwrap() > 0,
            "{record:?}"
        );
        egress_evidence(
            "audit-measured-counters",
            "dispositions+bytes",
            "authority-audit",
        );

        // Destroyed: every role gone, the counters audited.
        let destroyed = lab.authority().environment_destroy(&environment).unwrap();
        let EnvironmentReply::Destroyed { egress, .. } = destroyed else {
            panic!("not destroyed: {destroyed:?}")
        };
        let egress = egress.unwrap();
        assert!(egress.count(EgressDisposition::Closed) >= 1, "{egress:?}");
        assert!(rt.labelled(&environment).is_empty());
        let record = audit_records(&lab.dir.state(), "environment.destroyed")
            .pop()
            .unwrap();
        assert!(int(&record, "egress_bytes_upstream").unwrap() > 0);
        let dispositions = strings(&record, "egress_dispositions");
        assert!(
            dispositions.iter().any(|d| d.starts_with("CLOSED=")),
            "{dispositions:?}"
        );
        assert!(
            !format!("{record:?}").contains("origin.example.com"),
            "the destruction's record names a destination"
        );
        egress_evidence(
            "audit-destroyed-counters",
            &dispositions.join("+"),
            "authority-audit-at-destruction",
        );

        // A relay left behind for an ended environment is an orphan: reaped
        // through the environment's destruction, exactly.
        let store = lab.reaper.store.lock().unwrap().clone().unwrap();
        let relay_left = rt.create(
            &format!("dw-m5b-orphan-relay-{}", std::process::id()),
            &image,
            &[
                ("io.direwolf.owner", "direwolf"),
                ("io.direwolf.schema", "2"),
                ("io.direwolf.store", &store),
                ("io.direwolf.environment", environment.as_str()),
                ("io.direwolf.run", run.as_str()),
                ("io.direwolf.profile", "oci-strict"),
                ("io.direwolf.role", "relay"),
            ],
        );
        let report = lab.authority().environment_reconcile().unwrap();
        assert_eq!(report.orphans_reaped, 1, "{report:?}");
        assert!(!rt.exists(&relay_left));
        egress_evidence(
            "reconcile-helper-orphan-reaped",
            "removed-exactly",
            "authority-reconciliation",
        );
    }

    // ---- F-17: each workload's egress, decided by the real authority ------

    /// The F-17 evidence policy (ADR-0061, Proposed): the fixture as a
    /// sandbox workload; HTTPS in a sandbox to exactly the hosts the cases
    /// reach; a tainted run's novel destination for approval and one host
    /// always for approval -- each refused, nobody being there to approve
    /// (the shipped `balanced` rule and postcondition, verbatim); any other
    /// granted host, the standing control, denied by the default.
    fn egress_policy() -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5b-egress"

[[rule]]
id = "the-fixture-in-a-sandbox"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{FIXTURE}@{fixture}"]
obligations = ["max_output_bytes=65536"]

[[rule]]
id = "never-on-the-host"
effect = "DENY"
reason = "HOST_EXECUTION_DISABLED"
when.verb = "process.exec"
when.environment = "host"

{tainted}
[[rule]]
id = "approve-the-review-origin"
effect = "REQUIRE_APPROVAL"
reason = "UNTRUSTED_CONTENT_IN_RUN"
when.verb = "network.https"
when.environment = "sandbox"
when.host_matches = "review.example.com"
approval.scope    = "exact_action"
approval.ttl      = "10m"
approval.max_uses = 1

[[rule]]
id = "https-to-the-evidence-origins"
effect = "ALLOW"
when.verb = "network.https"
when.environment = "sandbox"
when.host_matches = ["origin.example.com", "second.example.com"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"

{unattended}"#,
            fixture = var("DW_SANDBOX_FIXTURE_SHA256"),
            tainted = shipped("balanced", TAINTED_RULE),
            unattended = shipped("balanced", UNATTENDED_POSTCONDITION),
        )
    }

    /// `balanced`'s rule for a tainted run's novel destination.
    const TAINTED_RULE: &str = r#"[[rule]]
id     = "approve-egress-when-tainted"
effect = "REQUIRE_APPROVAL"
reason = "UNTRUSTED_CONTENT_IN_RUN"
when.verb              = ["network.http", "network.https", "channel.send"]
when.taint_level       = ["EXTERNAL_UNTRUSTED"]
when.destination_novel = true
approval.scope    = "exact_action"
approval.ttl      = "10m"
approval.max_uses = 1
"#;

    /// `balanced`'s unattended postcondition.
    const UNATTENDED_POSTCONDITION: &str = r#"[[postcondition]]
id     = "deny-approval-needed-when-unattended"
effect = "DENY"
reason = "NO_HUMAN_AVAILABLE"
when.provisional_effect = ["REQUIRE_APPROVAL"]
when.origin             = ["scheduled", "channel", "subagent", "api"]
unless.standing_grant   = true
"#;

    /// `power`'s address rule.
    const POWER_INTERNAL_RANGES: &str = r#"[[rule]]
id     = "deny-internal-ranges"
effect = "DENY"
reason = "SANDBOX_ESCAPE_VECTOR"
when.verb  = ["network.http", "network.https", "network.tcp"]
when.ip_in = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "0.0.0.0/8",
              "0000:0000:0000:0000:0000:0000:0000:0001/128",
              "fc00:0000:0000:0000:0000:0000:0000:0000/7",
              "fe80:0000:0000:0000:0000:0000:0000:0000/10"]
"#;

    /// `block`, proved to be the shipped pack `pack`'s own text, verbatim.
    fn shipped(pack: &str, block: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../policy")
            .join(format!("{pack}.toml"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(block),
            "not verbatim from {}:\n{block}",
            path.display()
        );
        block.to_owned()
    }

    /// The POWER evidence policy: `power`'s address rule verbatim before the
    /// same narrow allow rule -- every evidence origin is the host's
    /// loopback, which that rule denies.
    fn power_policy() -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5b-egress"

[[rule]]
id = "the-fixture-in-a-sandbox"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{FIXTURE}@{fixture}"]
obligations = ["max_output_bytes=65536"]

[[rule]]
id = "never-on-the-host"
effect = "DENY"
reason = "HOST_EXECUTION_DISABLED"
when.verb = "process.exec"
when.environment = "host"

{ranges}
[[rule]]
id = "https-to-the-evidence-origins"
effect = "ALLOW"
when.verb = "network.https"
when.environment = "sandbox"
when.host_matches = ["origin.example.com"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#,
            fixture = var("DW_SANDBOX_FIXTURE_SHA256"),
            ranges = shipped("power", POWER_INTERNAL_RANGES),
        )
    }

    /// A PROXY_ONLY lab under `policy_text`, its resolver naming `names`.
    fn egress_lab(tag: &str, names: &[&str], policy_text: &str) -> (Lab, TempDir) {
        let fixture_dir = TempDir::new(&format!("{tag}-fixture"));
        let fixture = fixture_dir.path().join("egress-fixture.txt");
        let mut lines: String = names
            .iter()
            .map(|n| format!("resolve {n} 127.0.0.1\n"))
            .collect();
        lines.push_str("allow 127.0.0.1\n");
        std::fs::write(&fixture, lines).unwrap();
        let lab = Lab::proxy_only(
            tag,
            (
                &var("DW_EGRESS_IMAGE_FIXTURE"),
                &var("DW_SANDBOX_PROBE_SHA256"),
                &var("DW_EGRESS_RELAY_SHA256"),
            ),
            fixture.to_str().unwrap(),
            policy_text,
        );
        (lab, fixture_dir)
    }

    /// `host`:`port` through the run's next workload: the fixture's line.
    fn tunnel(lab: &mut Lab, run: &RunId, host: &str, port: u16) -> String {
        let p = port.to_string();
        lab.fixture(run, &["egress-connect", host, &p, host, "0"])
    }

    /// The `key=value` field of a fixture's line.
    fn field<'a>(line: &'a str, key: &str) -> &'a str {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} in {line}"))
    }

    /// The last workload intent's record.
    fn last_intent(lab: &Lab) -> Object {
        audit_records(&lab.dir.state(), "workload.intent_recorded")
            .pop()
            .unwrap()
    }

    /// The last intent's decision line for `destination`.
    fn decision(lab: &Lab, destination: &str) -> String {
        let intent = last_intent(lab);
        strings(&intent, "egress_decisions")
            .into_iter()
            .find(|line| line.starts_with(&format!("{destination} ")))
            .unwrap_or_else(|| panic!("no decision for {destination}: {intent:?}"))
    }

    fn exposed_at_start(intent: &Object) -> bool {
        matches!(
            intent.get("egress_exposed_at_start"),
            Some(Value::Bool(true))
        )
    }

    fn count_rows(lab: &Lab, sql: &str) -> i64 {
        raw(&lab.dir.state())
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    /// F-17 through the real authority: each workload's egress decided by
    /// both gates for every destination of its environment's grant -- the
    /// standing control refused before resolution, a host the policy wants
    /// approved refused with nobody there to approve, a tainted run's novel
    /// destination refused while a destination it has reached is reached
    /// again, and a sibling run on the same workspace root launched exposed.
    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn the_authority_decides_each_workloads_egress_by_both_gates_and_exposure() {
        let (port, accepted) = origin();
        let (mut lab, _fixture) = egress_lab(
            "f17-egress",
            // The standing control, `refused.example.com`, is not in the
            // file: had the proxy asked its resolver, it would have failed.
            &[
                "origin.example.com",
                "second.example.com",
                "review.example.com",
            ],
            &egress_policy(),
        );
        let grants: Vec<String> = ["origin", "second", "review", "refused"]
            .iter()
            .map(|h| format!("network.https:{h}.example.com:{port}"))
            .collect();
        let mut asked: Vec<&str> = grants.iter().map(String::as_str).collect();
        asked.push("process.exec:*");
        let run = lab.admit_with(&asked);
        let (environment, _container) = lab.ready(&run);

        // The standing control: granted, no rule allows it.
        let line = tunnel(&mut lab, &run, "refused.example.com", port);
        assert!(line.contains("403"), "{line}");
        assert_eq!(field(&line, "decision"), "POLICY_DENIED", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        let control = decision(&lab, &format!("refused.example.com:{port}"));
        assert!(control.contains("np=0/2[default]"), "{control}");
        egress_evidence(
            "policy-denied-before-resolution",
            "403-POLICY_DENIED-no-resolution-no-origin",
            "connect-proxy:workload-authorisation",
        );
        let intent = last_intent(&lab);
        assert!(text(&intent, "egress_sha256").is_some(), "{intent:?}");
        assert!(
            text(&intent, "egress_context_sha256").is_some(),
            "{intent:?}"
        );
        assert_eq!(strings(&intent, "egress_decisions").len(), 4, "{intent:?}");
        assert!(!exposed_at_start(&intent));
        egress_evidence(
            "decision-recorded-with-the-intent",
            "4-destinations-4-cells-digests",
            "authority-audit",
        );

        // Unattended: the policy wants a human to approve, and every run
        // admitted here is unattended -- refused in every cell.
        let line = tunnel(&mut lab, &run, "review.example.com", port);
        assert_eq!(field(&line, "decision"), "POLICY_DENIED", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        let review = decision(&lab, &format!("review.example.com:{port}"));
        assert!(
            review.contains("np=0/2[deny-approval-needed-when-unattended]"),
            "{review}"
        );
        egress_evidence(
            "approval-needed-refused-unattended",
            &review,
            "authority-egress-decision",
        );

        // Reached: the first origin byte exposes the workspace, durably.
        let line = tunnel(&mut lab, &run, "origin.example.com", port);
        assert_eq!(field(&line, "received"), "5", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            count_rows(&lab, "SELECT count(*) FROM workspace_exposure"),
            1
        );
        assert_eq!(
            count_rows(&lab, "SELECT count(*) FROM tunnel_reach WHERE certain = 1"),
            1
        );
        // F-01 (ADR-0062, Proposed): the run received what the origin sent;
        // its taint follows, from the broker's report of its workload.
        assert_eq!(
            taint_of(&lab, &run),
            (
                2,
                vec![
                    "tool_result:LOCAL_CONTENT:0>1".to_owned(),
                    "workload_reached:ORIGIN_BYTES:1>2".to_owned()
                ]
            )
        );
        // The next workload starts exposed: what it has reached it reaches
        // again; a novel destination is a tainted run's, for approval, and
        // refused.
        let line = tunnel(&mut lab, &run, "origin.example.com", port);
        assert_eq!(field(&line, "received"), "5", "{line}");
        assert!(exposed_at_start(&last_intent(&lab)));
        let seen = decision(&lab, &format!("origin.example.com:{port}"));
        assert!(seen.contains(" SEEN "), "{seen}");
        let line = tunnel(&mut lab, &run, "second.example.com", port);
        assert_eq!(field(&line, "decision"), "POLICY_DENIED", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        let novel = decision(&lab, &format!("second.example.com:{port}"));
        assert!(
            novel.contains("ne=0/2[deny-approval-needed-when-unattended]"),
            "{novel}"
        );
        // F-01: the run itself now holds what an origin sent, so its own
        // cells are its exposed ones -- the novel destination is refused by
        // both (stricter than F-17 alone). That the exposed cell, not the
        // run's taint, decides on an exposed root is shown below, at a
        // fresh run's first launch (`taint-fresh-run-decided-by-the-exposed-cell`).
        assert!(
            novel.contains("np=0/2[deny-approval-needed-when-unattended]"),
            "{novel}"
        );
        egress_evidence(
            "tainted-novel-refused-seen-reached",
            "seen-200+novel-POLICY_DENIED",
            "authority-egress-decision",
        );
        egress_evidence(
            "exposure-durable-before-the-next-launch",
            "exposure-row+certain-reach+exposed-at-start",
            "authority-ledger",
        );

        // A sibling run on the same root: novel everywhere, launched
        // exposed, so even the host its sibling reached is refused it.
        match lab.authority().environment_destroy(&environment).unwrap() {
            EnvironmentReply::Destroyed { .. } => {}
            other => panic!("not destroyed: {other:?}"),
        }
        // ADR-0061's A8: the proxy's counts hold every workload's report.
        let destroyed = audit_records(&lab.dir.state(), "environment.destroyed")
            .pop()
            .unwrap();
        assert_eq!(
            destroyed.get("egress_reports_within_counters"),
            Some(&Value::Bool(true)),
            "{destroyed:?}"
        );
        assert_eq!(int(&destroyed, "egress_workload_reports"), Some(5));
        let sibling = lab.admit_with(&asked);
        let (sibling_environment, _) = lab.ready(&sibling);
        let line = tunnel(&mut lab, &sibling, "origin.example.com", port);
        assert_eq!(field(&line, "decision"), "POLICY_DENIED", "{line}");
        assert!(exposed_at_start(&last_intent(&lab)));
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        egress_evidence(
            "exposure-from-a-sibling-run-on-the-shared-root",
            &line,
            "authority-egress-decision",
        );
        // F-01: F-17's guarantee the same-run case no longer shows, shown
        // where it still holds -- a fresh run on the exposed root, its own
        // taint NONE when it launched: its pristine cell for a novel
        // destination allows, its exposed cell refuses, and the broker held
        // it to the exposed one. Its outcome, from the exposed root, is then
        // external.
        let intent = last_intent(&lab);
        assert_eq!(
            text(&intent, "taint_at_decision"),
            Some("NONE"),
            "{intent:?}"
        );
        let fresh = decision(&lab, &format!("second.example.com:{port}"));
        assert!(
            fresh.contains("np=2/2[https-to-the-evidence-origins]"),
            "{fresh}"
        );
        assert!(
            fresh.contains("ne=0/2[deny-approval-needed-when-unattended]"),
            "{fresh}"
        );
        assert_eq!(
            taint_of(&lab, &sibling),
            (2, vec!["root_exposed:ORIGIN_BYTES:0>2".to_owned()])
        );
        egress_evidence(
            "taint-fresh-run-decided-by-the-exposed-cell",
            &fresh,
            "authority-egress-decision",
        );
        lab.authority()
            .environment_destroy(&sibling_environment)
            .unwrap();
    }

    /// F-17 through the real authority: `power`'s internal ranges, verbatim,
    /// refuse a granted host at the address it resolves to; and a workload
    /// interrupted by the authority's crash is settled uncertain and exposed
    /// on restart -- no recovery restores a less restrictive authorisation.
    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn ranges_refuse_at_the_address_and_an_interrupted_workload_exposes_its_root() {
        let (port, accepted) = origin();
        let (mut lab, _fixture) =
            egress_lab("f17-ranges", &["origin.example.com"], &power_policy());
        let grant = format!("network.https:origin.example.com:{port}");
        let asked = [grant.as_str(), "process.exec:*"];
        let run = lab.admit_with(&asked);
        lab.ready(&run);
        let line = tunnel(&mut lab, &run, "origin.example.com", port);
        assert!(line.contains("403"), "{line}");
        assert_eq!(field(&line, "decision"), "POLICY_ADDRESS_DENIED", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        let ranged = decision(&lab, &format!("origin.example.com:{port}"));
        assert!(ranged.contains("deny-internal-ranges"), "{ranged}");
        assert!(ranged.contains("https-to-the-evidence-origins"), "{ranged}");
        egress_evidence(
            "power-internal-ranges-refused-at-the-address",
            &line,
            "connect-proxy:workload-authorisation-address",
        );
        assert_eq!(
            count_rows(&lab, "SELECT count(*) FROM workspace_exposure"),
            0
        );

        // The authority dies while a workload runs: on restart its egress is
        // settled UNCERTAIN, the root exposed and its destinations' reach
        // uncertain -- never back to pristine.
        lab.start(Some(stop_at(CrashPoint::WorkloadAfterStart)));
        let interrupted = lab.admit_with(&asked);
        lab.ready(&interrupted);
        let request = WorkloadRequest {
            executable: FIXTURE.to_owned(),
            args: vec!["workload-sleep".to_owned(), "300".to_owned()],
            stream_limit: 65_536,
            wall_clock_seconds: 300,
            key: "f17-interrupted".to_owned(),
        };
        let crashed = lab.authority().workload_run(&interrupted, &request);
        assert!(
            matches!(crashed, Err(AuthorityError::Poisoned(_))),
            "{crashed:?}"
        );
        lab.start(None);
        let settled: (String, i64) = raw(&lab.dir.state())
            .query_row(
                "SELECT e.settled, e.exposed FROM workload_egress e \
                 JOIN workload w ON w.invocation_id = e.invocation_id \
                 WHERE w.idempotency_key = 'f17-interrupted'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(settled, ("UNCERTAIN".to_owned(), 1));
        assert_eq!(
            count_rows(&lab, "SELECT count(*) FROM workspace_exposure"),
            1
        );
        assert!(count_rows(&lab, "SELECT count(*) FROM tunnel_reach WHERE certain = 0") >= 1);
        // F-01: the run the restart reaped holds, in its history, what its
        // workload may have brought -- uncertainly, never as received.
        assert_eq!(
            taint_of(&lab, &interrupted),
            (2, vec!["workload_interrupted:UNCERTAIN:0>2".to_owned()])
        );
        egress_evidence(
            "restart-settles-an-interrupted-workload-uncertain",
            "UNCERTAIN+exposed+uncertain-reach",
            "authority-reconciliation",
        );
        let next = lab.admit_with(&asked);
        lab.ready(&next);
        let line = tunnel(&mut lab, &next, "origin.example.com", port);
        assert_eq!(field(&line, "decision"), "POLICY_ADDRESS_DENIED", "{line}");
        assert!(exposed_at_start(&last_intent(&lab)));
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        egress_evidence(
            "restart-never-restores-a-pristine-root",
            "exposed-at-start-after-restart",
            "authority-reconciliation",
        );
        // F-01: what the next run receives from that root is external, on
        // an uncertain basis -- said as such.
        assert_eq!(
            taint_of(&lab, &next),
            (2, vec!["root_exposed:UNCERTAIN:0>2".to_owned()])
        );
        egress_evidence(
            "taint-interrupted-workload-on-restart",
            "reaped-run-uncertain+next-run-uncertain",
            "authority-taint",
        );
    }

    // ---- F-01: taint that follows what each run receives ------------------

    /// `run`'s stored taint, and its evidence rows, `cause:basis:from>to`.
    fn taint_of(lab: &Lab, run: &RunId) -> (i64, Vec<String>) {
        let conn = raw(&lab.dir.state());
        let taint: i64 = conn
            .query_row(
                "SELECT taint FROM run_policy_input WHERE run_id = ?1",
                [run.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let mut statement = conn
            .prepare(
                "SELECT cause || ':' || basis || ':' || from_taint || '>' || to_taint \
                 FROM run_taint_evidence WHERE run_id = ?1 ORDER BY seq",
            )
            .unwrap();
        let rows = statement
            .query_map([run.as_str()], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap();
        (taint, rows)
    }

    /// The F-01 evidence policy: F-17's, with one destination whose
    /// per-tunnel bound is three bytes, and the workspace's files readable and
    /// writable.
    fn taint_policy() -> String {
        let marker = "[[rule]]\nid = \"default\"";
        let base = egress_policy();
        assert!(base.contains(marker));
        base.replace(
            marker,
            &format!(
                r#"[[rule]]
id = "capped-origin"
effect = "ALLOW"
when.verb = "network.https"
when.environment = "sandbox"
when.host_matches = "capped.example.com"
obligations = ["max_output_bytes=3"]

[[rule]]
id = "workspace-files"
effect = "ALLOW"
when.verb = ["fs.read", "fs.write", "fs.create"]

{marker}"#
            ),
        )
    }

    /// A run that calls tools in process, and what a call needs.
    struct Held {
        caller: CallerContext,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
    }

    static NEXT_TOOL_MESSAGE: AtomicU64 = AtomicU64::new(0);

    impl Lab {
        /// A new active run that requested `capabilities`, and its caller.
        fn admit_holding(&mut self, capabilities: &[&str]) -> Held {
            let n = self.next_session;
            self.next_session += 1;
            let workspace = self.workspace.clone();
            let profile = self.profile;
            let authority = self.authority();
            authority
                .operator()
                .bind_session_workspace(&session(n), &workspace)
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
            Held {
                caller,
                session: session(n),
                epoch,
                run: admission.run_id().clone(),
            }
        }

        /// A version-2 tool call in `held`'s run, in process.
        fn tool(&mut self, held: &Held, payload: &str, key: &str) -> ToolReply {
            let text = format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":2,"ts":"2026-10-20T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"{key}","payload":{payload}}}"#,
                id = id(
                    "msg",
                    90_000 + NEXT_TOOL_MESSAGE.fetch_add(1, Ordering::SeqCst)
                ),
                session = held.session.as_str(),
                run = held.run.as_str(),
                epoch = held.epoch.get(),
            );
            let DwkpBody::ToolInvokeV2(call) = decode(&text).body else {
                panic!("not a tool call: {text}")
            };
            let request = ToolRequest::v2(call, Some(IdempotencyKey::new(key).unwrap()));
            self.authority()
                .tool_invoke(&held.caller, &held.session, &held.run, held.epoch, &request)
                .expect("the authority answers")
        }
    }

    fn read_file(path: &str) -> String {
        format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":65536}}}}"#)
    }

    fn write_file(path: &str, content: &[u8]) -> String {
        let hex: String = content.iter().map(|b| format!("{b:02x}")).collect();
        format!(r#"{{"fs_write":{{"path":"{path}","content":"{hex}"}}}}"#)
    }

    fn read_back(reply: &ToolReply) -> Vec<u8> {
        match reply {
            ToolReply::Done { output, .. } => output.fs_read.as_ref().unwrap().content.to_bytes(),
            other => panic!("not read: {other:?}"),
        }
    }

    fn written(reply: &ToolReply) {
        assert!(
            matches!(reply, ToolReply::Done { output, .. } if output.fs_write.is_some()),
            "not written: {reply:?}"
        );
    }

    /// F-01 through the real authority, the released broker and a real
    /// runtime: a run's taint follows what it receives. Permission, a refused
    /// CONNECT and a failed dial bring no external content; an output-less,
    /// incomplete download does, and so does the file it left -- to the run
    /// that fetched it and to another run on the same root, read through the
    /// brokered `fs.read`; and a run holding external content marks the root
    /// it writes, so that even a run that received nothing else reads what
    /// it wrote as external.
    #[test]
    #[ignore = "needs a real OCI runtime: make sandbox-egress-evidence"]
    fn the_taint_follows_what_each_run_receives() {
        let (port, accepted) = origin();
        // A port nothing listens on: the dial fails after the proxy's 200.
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let (mut lab, _fixture) = egress_lab(
            "f01-taint",
            &["origin.example.com", "capped.example.com"],
            &taint_policy(),
        );
        lab.authority()
            .operator()
            .install_agent_profile(&profile(
                "taint-agent",
                &[
                    "process.exec:*",
                    "network.https:*.example.com",
                    "fs.read:*",
                    "fs.write:*",
                    "fs.create:*",
                ],
                &[],
                PrivacyClass::Any,
            ))
            .unwrap();
        lab.profile = "taint-agent";
        let grants = [
            format!("network.https:origin.example.com:{port}"),
            format!("network.https:origin.example.com:{closed}"),
            format!("network.https:capped.example.com:{port}"),
            format!("network.https:refused.example.com:{port}"),
        ];
        let mut asked: Vec<&str> = grants.iter().map(String::as_str).collect();
        asked.extend(["process.exec:*", "fs.read:*", "fs.write:*", "fs.create:*"]);

        // Permission, a refusal and a failed dial, on a pristine root: no
        // origin byte reached anything -- never external.
        let permitted = lab.admit_holding(&asked);
        lab.ready(&permitted.run);
        let line = lab.fixture(&permitted.run, &["workload-exit", "0"]);
        assert_eq!(line, "");
        assert_eq!(
            taint_of(&lab, &permitted.run),
            (0, Vec::new()),
            "network permission is not content"
        );
        let line = tunnel(&mut lab, &permitted.run, "refused.example.com", port);
        assert_eq!(field(&line, "decision"), "POLICY_DENIED", "{line}");
        let line = tunnel(&mut lab, &permitted.run, "origin.example.com", closed);
        assert!(line.contains("200"), "{line}");
        assert_eq!(field(&line, "received"), "0", "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        assert_eq!(
            taint_of(&lab, &permitted.run),
            (1, vec!["tool_result:LOCAL_CONTENT:0>1".to_owned()])
        );
        assert_eq!(
            count_rows(&lab, "SELECT count(*) FROM workspace_exposure"),
            0
        );
        egress_evidence(
            "taint-permission-refusal-failed-dial-not-external",
            "none+POLICY_DENIED+dial-failed:local-only",
            "authority-taint",
        );

        // An output-less, incomplete download: the origin sends five bytes,
        // the tunnel carries three and is cut at its bound, and the workload
        // keeps them in a file and prints nothing.
        let fetcher = lab.admit_holding(&asked);
        lab.ready(&fetcher.run);
        let p = port.to_string();
        let line = lab.fixture(
            &fetcher.run,
            &[
                "egress-quiet",
                "capped.example.com",
                &p,
                "capped.example.com",
                "/workspace/downloaded.bin",
            ],
        );
        assert_eq!(line, "", "nothing printed");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        let kept = std::fs::read(lab.dir.path().join("workspace").join("downloaded.bin")).unwrap();
        assert_eq!(
            kept, b"rrr",
            "three of five bytes: cut at the tunnel's bound"
        );
        assert_eq!(
            taint_of(&lab, &fetcher.run),
            (2, vec!["workload_reached:ORIGIN_BYTES:0>2".to_owned()])
        );
        let outcome = audit_records(&lab.dir.state(), "workload.outcome")
            .pop()
            .unwrap();
        assert_eq!(text(&outcome, "taint_basis"), Some("ORIGIN_BYTES"));
        assert_eq!(int(&outcome, "stdout_bytes"), Some(0));
        egress_evidence(
            "taint-download-no-output-external",
            "stdout-0+external:workload_reached:ORIGIN_BYTES",
            "authority-taint",
        );
        egress_evidence(
            "taint-partial-transfer-external",
            "3-of-5-bytes+external",
            "authority-taint",
        );

        // The run reads what it kept: external already, and said so.
        let reply = lab.tool(&fetcher, &read_file("/workspace/downloaded.bin"), "f01-r1");
        assert_eq!(read_back(&reply), b"rrr");
        assert_eq!(taint_of(&lab, &fetcher.run).0, 2);

        // Another run on the same root, which received nothing yet: its
        // first read of the downloaded file is external.
        let reader = lab.admit_holding(&asked);
        assert_eq!(taint_of(&lab, &reader.run), (0, Vec::new()));
        let reply = lab.tool(&reader, &read_file("/workspace/downloaded.bin"), "f01-r2");
        assert_eq!(read_back(&reply), b"rrr");
        assert_eq!(
            taint_of(&lab, &reader.run),
            (2, vec!["root_exposed:ORIGIN_BYTES:0>2".to_owned()])
        );
        let completed = audit_records(&lab.dir.state(), "tool.completed")
            .pop()
            .unwrap();
        assert_eq!(text(&completed, "taint_basis"), Some("ORIGIN_BYTES"));
        egress_evidence(
            "taint-downloaded-file-read-by-another-run",
            "external:root_exposed:ORIGIN_BYTES",
            "authority-taint",
        );

        // That run, holding external content, writes the workspace: the root
        // is marked, before the broker writes; and the earlier run, which
        // received nothing external, reads what it wrote as external. (The
        // broker changes no name in a directory others can write -- the
        // evidence's root is open to the workload's uid -- so the write goes
        // to a directory of the root that only the broker's uid writes.)
        std::fs::create_dir(lab.dir.path().join("workspace").join("notes")).unwrap();
        let reply = lab.tool(
            &reader,
            &write_file("/workspace/notes/notes.txt", b"n"),
            "f01-w1",
        );
        written(&reply);
        assert_eq!(
            count_rows(
                &lab,
                "SELECT count(*) FROM workspace_taint WHERE tool = 'fs.write'"
            ),
            1
        );
        assert_eq!(
            audit_records(&lab.dir.state(), "workspace.tainted").len(),
            1
        );
        let reply = lab.tool(
            &permitted,
            &read_file("/workspace/notes/notes.txt"),
            "f01-r3",
        );
        assert_eq!(read_back(&reply), b"n");
        assert_eq!(taint_of(&lab, &permitted.run).0, 2);
        egress_evidence(
            "taint-tainted-writer-marks-root",
            "workspace_taint+external-read",
            "authority-taint",
        );
    }
}
