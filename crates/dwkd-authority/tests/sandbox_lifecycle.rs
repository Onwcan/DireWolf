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

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use dwk_proto as _;
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
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use dwk_proto::brokerp::egress::EgressDisposition;
    use dwk_proto::brokerp::sandbox::{AssuranceLevel, NetworkTopology};
    use dwk_proto::wire::id::{EnvironmentId, RunId};
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::sandbox::{EgressConfig, SandboxConfig};
    use dwkd_authority::state::{
        Authority, AuthorityError, CrashHook, CrashPoint, EnvironmentReply, EnvironmentState,
        HookAction, ManualClock, ReconcileReport, Reply, StartOptions, StartupConfig, WorkspaceId,
        WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::state_support::{
        START_MS, TempDir, admit_msg, audit_events, audit_records, balanced, install_fixtures, int,
        raw, session, spawn_guard, subject, text,
    };
    use super::transport_support::own_uid;

    const SUITE: &str = "sandbox-authority";

    fn evidence(case: &str, outcome: &str) {
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
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
            )
            .unwrap();
            Self::with(
                tag,
                &["--allow-shared-authority-uid", "--allow-evidence-topology"],
                sandbox,
            )
        }

        /// A lab whose sandbox is `PROXY_ONLY` (M5b), its broker resolving
        /// egress names from `fixture` — the evidence's, never production's.
        fn proxy_only(tag: &str, image: &str, probe: &str, relay: &str, fixture: &str) -> Self {
            let sandbox = SandboxConfig::proxy_only(
                &var("DW_SANDBOX_RUNTIME"),
                &var("DW_SANDBOX_SOCKET"),
                image,
                probe,
                EgressConfig::new(relay, 4, 1 << 20, 1 << 20).unwrap(),
            )
            .unwrap();
            Self::with(
                tag,
                &[
                    "--allow-shared-authority-uid",
                    "--allow-evidence-egress",
                    fixture,
                ],
                sandbox,
            )
        }

        fn with(tag: &str, broker_args: &[&str], sandbox: SandboxConfig) -> Self {
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
                config: balanced(),
                broker_socket,
                _broker: broker,
                authority: None,
                sandbox,
                workspace: WorkspaceId::new("ws").unwrap(),
                next_session: 1,
                runtime,
                reaper,
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
                        "researcher",
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
        );
        let report = lab.start(None);
        assert!(report.missing >= 1, "{report:?}");
        assert_eq!(lab.state_of(&intended), EnvironmentState::Lost);
        evidence("crash-w2-after-intent-lost", "unknown-then-lost");

        // The whole path: intent, broker, runtime, measurement, outcome.
        let run = lab.admit();
        let (environment, container) = lab.ready(&run);
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        assert!(lab.runtime.exists(&container));
        evidence("prepare-ready-recorded", "ready");
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
        );
        evidence("measure-clean", "clean");
        assert_eq!(
            lab.authority().environment_prepare(&run).unwrap(),
            EnvironmentReply::Refused("ENVIRONMENT_EXISTS")
        );
        evidence("one-environment-per-run", "environment-exists");

        // W6: the destruction is durable, the broker told nothing.
        lab.start(Some(stop_at(CrashPoint::EnvironmentDestroyAfterIntent)));
        // A restart ends the run but not the environment: it is measured again
        // and kept (the reconciliation of a READY, running one).
        assert_eq!(lab.state_of(&environment), EnvironmentState::Ready);
        poisoned(lab.authority().environment_destroy(&environment));
        assert_eq!(lab.row("DESTROYING"), environment);
        assert!(lab.runtime.exists(&container), "not yet removed");
        evidence(
            "destroy-intent-durable-before-broker",
            "destroying-row-container-present",
        );
        let report = lab.start(None);
        assert!(report.pending_destroyed >= 1, "{report:?}");
        assert_eq!(lab.state_of(&environment), EnvironmentState::Destroyed);
        assert!(!lab.runtime.exists(&container));
        evidence("crash-w6-destroy-intent-completed", "destroyed-on-restart");

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
        evidence("destroy-recorded", "destroyed");
        assert_eq!(
            lab.authority().environment_destroy(&environment).unwrap(),
            EnvironmentReply::Refused("ENVIRONMENT_ENDED")
        );
        evidence("destroy-idempotent", "ended-refused-nothing-sent");

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
        evidence("audit-lifecycle", "8-events");
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
        let twin = create(
            &format!("dw-m5a-twin-{tag}"),
            &pairs(&exact(ready.as_str(), first_run.as_str())),
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
        evidence("crash-w4-after-broker-reaped", "unknown-then-destroyed");
        assert!(rt.exists(&unrelated));
        evidence("foreign-unrelated-survive", "present");
        assert!(rt.exists(&copied), "a copied label is never reaped");
        assert!(rt.exists(&copied_run), "a copied run label is never reaped");
        assert!(report.foreign >= 2, "{report:?}");
        evidence(
            "foreign-copied-labels-survive",
            "copied-env-and-copied-run-present",
        );
        assert!(rt.exists(&twin) && rt.exists(&ready_container));
        assert_eq!(lab.state_of(&ready), EnvironmentState::Ready);
        assert!(report.ambiguous >= 1, "{report:?}");
        evidence("ambiguous-twins-untouched", "both-present-record-ready");
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
        evidence("orphan-ended-record-reaped", "removed-exactly");
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
        evidence("drift-destroyed", "resource-limit-failed-effective-none");
    }

    // ---- M5b: PROXY_ONLY, granted from the run --------------------------

    const EGRESS_SUITE: &str = "sandbox-authority-egress";

    fn egress_evidence(case: &str, outcome: &str) {
        println!(
            "SANDBOX-EVIDENCE {{\"suite\":\"{EGRESS_SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
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
             allow 127.0.0.1\n",
        )
        .unwrap();
        let mut lab = Lab::proxy_only(
            "m5b-egress",
            &image,
            &probe,
            &relay,
            fixture.to_str().unwrap(),
        );
        let rt = lab.runtime.clone();

        // The run asks for one exact host on the origin's port, one exact
        // host on 443, a wildcard, and plain HTTP.
        let exact = format!("network.https:origin.example.com:{port}");
        let run = lab.admit_with(&[
            &exact,
            "network.https:github.com",
            "network.https:*.example.com",
            "network.http:*",
        ]);
        let (environment, container) = lab.ready(&run);
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
        egress_evidence("grant-from-run-exact-https", &targets.join("+"));
        egress_evidence("grant-wildcard-and-plain-http-not-destinations", "absent");
        egress_evidence("audit-intent-records-grant", "targets+relay+budgets");

        // Through the real relay and proxy: the exact host is reached; a name
        // the wildcard covers, but no exact grant names, is not.
        let exec = |args: &[&str]| {
            let mut words = vec![
                "container",
                "exec",
                container.as_str(),
                "/usr/libexec/direwolf/sandbox-fixture",
            ];
            words.extend_from_slice(args);
            rt.ok(&words).trim().to_owned()
        };
        let p = port.to_string();
        let line = exec(&[
            "egress-connect",
            "origin.example.com",
            &p,
            "origin.example.com",
            "100",
        ]);
        assert!(line.contains("HTTP/1.1 200"), "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        egress_evidence(
            "tunnel-through-authority-prepared-environment",
            "200-and-reached",
        );
        let line = exec(&[
            "egress-connect",
            "api.example.com",
            &p,
            "api.example.com",
            "0",
        ]);
        assert!(line.contains("TARGET_NOT_GRANTED"), "{line}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        egress_evidence("wildcard-covered-name-not-granted", "target-not-granted");

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
        egress_evidence("audit-measured-counters", "dispositions+bytes");

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
        egress_evidence("audit-destroyed-counters", &dispositions.join("+"));

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
        egress_evidence("reconcile-helper-orphan-reaped", "removed-exactly");
    }
}
