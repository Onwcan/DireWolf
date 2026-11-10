//! M5e.5's evidence (ADR-0054 §8, ADR-0055 §9; the plan's §10, "M5e.5's
//! sequencing"): **npm and pip under their proposed profiles**, which no
//! production configuration keeps, against M5e.3's fixture registries --
//! run as a runtime runs a workload: a real DWKP client on the **released**
//! `dwkd-authority serve --allow-unaccepted-hygiene-profile npm
//! --allow-unaccepted-hygiene-profile pip`, the **released** broker, the
//! runner's Docker Engine, and a fresh measured `PROXY_ONLY` environment and
//! workspace for every case.
//!
//! What is a fixture here, and what is not:
//!
//! * The **registries** are M5e.3's, generated from one seed with the
//!   origins' fixed ports in every URL, on this runner's loopback under the
//!   task's PKI, named through the broker's evidence-only resolver file.
//! * The **image** is `make sandbox-hygiene-evidence`'s, built from the
//!   registry tools image's checked rootfs: the run's anchor at both proposed
//!   trust paths (`/etc/direwolf/npm-ca.pem`, `/etc/direwolf/pip-ca.pem`, the
//!   preparation handoff's D3), a third authority in the image's system store,
//!   an image `pip.conf` asking for the ungranted index and source builds,
//!   and a `pip` started by the pinned interpreter by absolute path. A second
//!   image is the same without the two trust files.
//! * The **profiles and the boundary** are not fixtures: the authority's
//!   decision and plan, the launcher's variables, the operator's file, the
//!   environment's measurement, the namespace, the relay, the proxy's grant,
//!   the release's teardown.
//!
//! **The proxy's count includes the boundary measuring itself** (as M5e.4's
//! suite learned, run 42296614431): every measurement of an environment asks
//! the proxy a question no grant can hold. A case reads the refusals its
//! workloads caused as the destruction's count less those questions.
//!
//! **Nothing here is accepted.** Every case is ADR-0054's or ADR-0055's,
//! required by name; a case that does not hold leaves npm and pip as they are
//! in production, and the ADR is revised, never accepted without it. Every
//! test is `#[ignore]`d and runs only on a disposable GitHub-hosted runner
//! (`DW_HYGIENE_EVIDENCE=1`): anywhere else it panics NOT EXERCISED.

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
mod runtime_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dwk_proto::dwkp::sandboxops::{
        ExecutionAssurance, ResidueVerdict, SandboxEnding, SandboxedExecResult,
    };
    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::json::{self, ParseOptions, Value};
    use dwk_proto::wire::id::{AnyId, RunId, SessionId};
    use dwk_proto::wire::scalar::Epoch;
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::state::PolicySet;
    use dwkd_authority::state::{
        MAX_LEASE_TTL_MS, ManualClock, Mode, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::net_support::Origin;
    use super::state_support::{
        START_MS, TempDir, acquire_msg, admit_msg, audit_records, ceiling, decode, id,
        install_fixtures, policy, profile, raw, release_run_msg, session,
    };
    use super::transport_support::{Client, PROMPT, Server, handshake, own_uid};

    const SUITE: &str = "sandbox-hygiene";
    const LEVEL: &str = "dwkp-end-to-end";
    const GRANTED: &str = "granted-registry.test";
    const UNGRANTED: &str = "ungranted-registry.test";
    const GRANTED_PORT: u16 = 18443;
    const UNGRANTED_PORT: u16 = 18444;
    const ROGUE_PORT: u16 = 18445;
    /// The granted name under the authority only the image's system store
    /// trusts (ADR-0055 §9, `pip-os-trust-store-not-used`).
    const SYSTEM_PORT: u16 = 18446;
    const SEED: &str = "m5e4-registry";
    const INSPECT: &str = "/workspace/tools/registry_inspect.py";
    const TARGETS: &str = "/workspace/t";
    /// An address no environment has a route to (RFC 5737's TEST-NET-1).
    const UNROUTED: &str = "192.0.2.1";
    const RULE: &str = "hygiene-tools-in-a-sandbox";
    const PROBE_INVARIANT: &str = "CONTAINER_PROXY_REACHABLE";
    const WALL: u32 = 180;
    const MAX_TUNNELS: usize = 16;
    const MAX_UPLOAD: usize = 512 * 1024;
    const MAX_DOWNLOAD: usize = 8 * 1024 * 1024;
    /// The most runs (and so workspaces) one lab admits.
    const RUNS: u64 = 48;
    /// npm's prefix and pip's, as ADR-0054 §2 and ADR-0055 §2 propose them.
    const NPM_PREFIX: [&str; 5] = [
        "--ignore-scripts",
        "--strict-ssl",
        "--no-audit",
        "--no-fund",
        "--no-update-notifier",
    ];
    const PIP_PREFIX: [&str; 7] = [
        "--only-binary=:all:",
        "--no-cache-dir",
        "--no-input",
        "--disable-pip-version-check",
        "--use-deprecated=legacy-certs",
        "--cert",
        "/etc/direwolf/pip-ca.pem",
    ];
    /// A direct connection from inside the environment, bypassing every proxy
    /// variable: what only the namespace's topology refuses. Prints its errno.
    const DIRECT: &str = "import socket, sys\n\
        s = socket.socket()\n\
        s.settimeout(5)\n\
        try:\n    s.connect((sys.argv[1], int(sys.argv[2])))\n    print('connected')\n\
        except OSError as e:\n    print(f'errno={e.errno}')\n";

    fn evidence(case: &str, outcome: &str, enforcement: &str) {
        use dwk_proto::json::{Object, to_canonical_string};
        let mut fields = Object::new();
        for (key, value) in [
            ("suite", SUITE),
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

    /// The task's refusal, again, before anything starts.
    fn hosted() {
        let said = |name: &str| std::env::var(name).unwrap_or_default();
        assert!(
            said("DW_HYGIENE_EVIDENCE") == "1"
                && said("GITHUB_ACTIONS") == "true"
                && said("RUNNER_ENVIRONMENT") == "github-hosted",
            "NOT EXERCISED: the hygiene evidence runs only on a disposable GitHub-hosted runner \
             (DW_HYGIENE_EVIDENCE=1, the manual `sandbox-hygiene` job)"
        );
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-hygiene-evidence`, which \
                 builds the hygiene images and pins their digests"
            )
        })
    }

    fn mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn next() -> u64 {
        NEXT.fetch_add(1, Ordering::SeqCst)
    }

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

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

    fn member<'a>(object: &'a json::Object, key: &str) -> &'a json::Object {
        match object.get(key) {
            Some(Value::Object(inner)) => inner,
            other => panic!("{key} is not an object: {other:?}"),
        }
    }

    fn flag(object: &json::Object, key: &str) -> bool {
        matches!(object.get(key), Some(Value::Bool(true)))
    }

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

    fn counted(dispositions: &[String], disposition: &str) -> u64 {
        dispositions
            .iter()
            .find_map(|d| d.strip_prefix(&format!("{disposition}=")))
            .map_or(0, |n| n.parse::<u64>().unwrap())
    }

    /// The refusals beyond the environment's own probe's questions (M5e.4's
    /// `beyond_the_probe`, run 42296614431).
    fn beyond_the_probe(dispositions: &[String], probe_questions: u64) -> u64 {
        let refused = counted(dispositions, "TARGET_NOT_GRANTED");
        refused.checked_sub(probe_questions).unwrap_or_else(|| {
            panic!(
                "{refused} TARGET_NOT_GRANTED counted, fewer than the {probe_questions} \
                 question(s) the environment's own probe asked: {dispositions:?}"
            )
        })
    }

    /// The ways a tunnel the proxy accepted can end (ADR-0048): each one
    /// counted at destruction is a `CONNECT` that was carried.
    const ACCEPTED: [&str; 6] = [
        "CLOSED",
        "UPLOAD_BUDGET",
        "DOWNLOAD_BUDGET",
        "IDLE_TIMEOUT",
        "LIFETIME_EXCEEDED",
        "ENVIRONMENT_CLOSED",
    ];

    /// How many tunnels the proxy carried for the environment: none, when a
    /// tool failed closed before it connected -- a failed TLS handshake
    /// over a carried tunnel looks the same from the tool's exit status.
    fn tunnels(dispositions: &[String]) -> u64 {
        ACCEPTED.iter().map(|way| counted(dispositions, way)).sum()
    }

    /// Node.js's certificate-verification error codes, as npm prints them
    /// (`npm error code …`) when its own TLS refuses an issuer.
    const NODE_TLS_REFUSALS: [&str; 7] = [
        "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        "UNABLE_TO_GET_ISSUER_CERT",
        "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        "SELF_SIGNED_CERT_IN_CHAIN",
        "DEPTH_ZERO_SELF_SIGNED_CERT",
        "CERT_SIGNATURE_FAILURE",
        "CERT_UNTRUSTED",
    ];

    const TAIL: usize = 4096;

    /// Output for a failure's report: key material and credential headers
    /// withheld, then its last [`TAIL`] bytes.
    fn bounded(text: &str) -> String {
        let mut kept = String::new();
        let mut material = false;
        for line in text.lines() {
            if line.contains("-----BEGIN ") {
                material = true;
                kept.push_str("[key or certificate material withheld]\n");
            }
            if material {
                material = !line.contains("-----END ");
                continue;
            }
            if line.to_ascii_lowercase().contains("authorization") {
                kept.push_str("[a credential header withheld]\n");
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        let from = kept.len().saturating_sub(TAIL);
        let from = (from..=kept.len())
            .find(|&at| kept.is_char_boundary(at))
            .unwrap_or(kept.len());
        kept[from..].to_owned()
    }

    fn host_json(script: &str, args: &[&str]) -> json::Object {
        let out = super::state_support::output(
            Command::new("python3")
                .arg("-I")
                .arg(repo().join(script))
                .args(args)
                .stdin(Stdio::null()),
        )
        .expect("python3 runs");
        assert!(
            out.status.success(),
            "{script} {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        object(&String::from_utf8(out.stdout).unwrap())
    }

    // ---- what the evidence task built ---------------------------------------

    /// The images and digests `make sandbox-hygiene-evidence` pinned.
    struct Pins {
        runtime: String,
        socket: String,
        image: String,
        image_no_trust: String,
        probe: String,
        relay: String,
        python: String,
        python_sha: String,
        npm: String,
        npm_sha: String,
        npx: String,
        npx_sha: String,
        pip: String,
        pip_sha: String,
        pki: PathBuf,
    }

    impl Pins {
        fn load() -> Self {
            Self {
                runtime: var("DW_SANDBOX_RUNTIME"),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_HYGIENE_IMAGE"),
                image_no_trust: var("DW_HYGIENE_IMAGE_NO_TRUST"),
                probe: var("DW_SANDBOX_PROBE_SHA256"),
                relay: var("DW_EGRESS_RELAY_SHA256"),
                python: var("DW_REGISTRY_PYTHON"),
                python_sha: var("DW_REGISTRY_PYTHON_SHA256"),
                npm: var("DW_REGISTRY_NPM"),
                npm_sha: var("DW_REGISTRY_NPM_SHA256"),
                npx: var("DW_HYGIENE_NPX"),
                npx_sha: var("DW_HYGIENE_NPX_SHA256"),
                pip: var("DW_HYGIENE_PIP"),
                pip_sha: var("DW_HYGIENE_PIP_SHA256"),
                pki: PathBuf::from(var("DW_HYGIENE_PKI")),
            }
        }
    }

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

        fn containers(&self, filters: &[String]) -> BTreeSet<String> {
            let mut args = vec!["container", "ls", "--all", "--no-trunc", "--quiet"];
            for filter in filters {
                args.push("--filter");
                args.push(filter);
            }
            self.ok(&args).lines().map(str::to_owned).collect()
        }

        fn role(&self, environment: &str, role: &str) -> BTreeSet<String> {
            self.containers(&[
                format!("label=io.direwolf.environment={environment}"),
                format!("label=io.direwolf.role={role}"),
            ])
        }

        /// What changed in a container's own filesystem, outside its mounts
        /// (`docker container diff`): nothing, on a read-only root.
        fn changed(&self, container: &str) -> Vec<String> {
            self.ok(&["container", "diff", container])
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    struct Reaper {
        runtime: Runtime,
        stores: Mutex<BTreeSet<String>>,
    }

    impl Reaper {
        fn note(&self, container: &str) {
            let store = self.runtime.label(container, "io.direwolf.store");
            assert!(!store.is_empty(), "{container} carries no store label");
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

    // ---- a runtime's run ----------------------------------------------------

    fn heartbeat(session: &SessionId, epoch: Epoch) -> DwkpMessage {
        decode(&format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-11-07T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
            id = id("msg", 980_000 + next()),
            session = session.as_str(),
            epoch = epoch.get(),
        ))
    }

    struct Peer {
        client: Client,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
        renewed: Instant,
        outstanding: Option<String>,
    }

    impl Peer {
        fn admit(mut client: Client, n: u64, capabilities: &[&str]) -> Self {
            let session = session(n);
            client.send(&handshake(1, 1, 1));
            let answer = client.recv(PROMPT).message();
            assert!(
                matches!(answer.body, DwkpBody::HandshakeAccepted(_)),
                "{answer:?}"
            );
            let asked = Instant::now();
            client.send(&acquire_msg(&session));
            let granted = client.recv(PROMPT).message();
            let DwkpBody::LeaseGrant(lease) = granted.body else {
                panic!("a lease: {granted:?}")
            };
            let epoch = lease.epoch;
            let message = next();
            client.send(&admit_msg(
                &session,
                epoch,
                &format!("admit-{n}-{message}"),
                "agent",
                &[],
                capabilities,
                message,
            ));
            let admitted = client.recv(PROMPT).message();
            let DwkpBody::RunGrant(grant) = admitted.body else {
                panic!("a run: {admitted:?}")
            };
            Self {
                client,
                session,
                epoch,
                run: grant.run_id,
                renewed: asked,
                outstanding: None,
            }
        }

        fn send(&mut self, message: &DwkpMessage) {
            assert!(self.outstanding.is_none(), "a request is outstanding");
            self.outstanding = Some(message.header.id.as_str().to_owned());
            self.client.send(message);
        }

        fn answer(&mut self, wait: Duration) -> DwkpBody {
            let asked = self.outstanding.take().expect("no request is outstanding");
            let answer = self.client.recv(wait).message();
            assert_eq!(
                answer.header.causation_id.as_ref().map(AnyId::as_str),
                Some(asked.as_str()),
                "an answer to another request: {answer:?}"
            );
            answer.body
        }

        fn renew(&mut self) {
            let unrenewed = self.renewed.elapsed();
            let asked = Instant::now();
            let message = heartbeat(&self.session, self.epoch);
            self.send(&message);
            match self.answer(PROMPT) {
                DwkpBody::Ack(_) => self.renewed = asked,
                other => panic!(
                    "the lease was not renewed after {unrenewed:?} (TTL {:?}): {other:?}",
                    Duration::from_millis(MAX_LEASE_TTL_MS)
                ),
            }
        }

        fn release(&mut self) {
            self.renew();
            let message = release_run_msg(&self.session, &self.run, self.epoch);
            self.send(&message);
            let released = self.answer(PROMPT);
            assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
        }

        fn exec(&mut self, executable: &str, args: &[&str]) -> DwkpBody {
            self.renew();
            let key = format!("h-{}", next());
            let message = decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-11-07T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"process_exec":{call}}}}}"#,
                id = id("msg", 990_000 + next()),
                session = self.session.as_str(),
                run = self.run.as_str(),
                epoch = self.epoch.get(),
                call = call(executable, args),
            ));
            self.send(&message);
            self.answer(Duration::from_secs(u64::from(WALL) + 240))
        }
    }

    /// A `process_exec` call's JSON. Each string through the protocol's own
    /// encoder, so a multi-line program argument is escaped (run
    /// 42858621579: a hand-made quote left its newlines raw, and the request
    /// was refused as invalid JSON).
    fn call(executable: &str, args: &[&str]) -> String {
        let quote = |s: &str| json::to_canonical_string(&Value::String(s.to_owned()));
        let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
        format!(
            r#"{{"executable":{},"args":[{}],"timeout_seconds":{WALL}}}"#,
            quote(executable),
            args.join(","),
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

    /// The authority's denial of a workload in a run that has no environment
    /// yet: its reason and rule, and that no environment was named.
    fn denied(body: &DwkpBody) -> (String, String) {
        denied_in(body, None)
    }

    /// The authority's denial of a workload, nothing prepared for it: its
    /// reason and rule. The plan may name the run's live environment when an
    /// earlier workload made one (`environment`), and never another; with
    /// none, it names none (run 42846068083: `balanced` ran `npm ci`, then
    /// denied `pip install` in the same run, its plan naming the environment
    /// `npm ci` had made). The caller proves no environment was made.
    fn denied_in(body: &DwkpBody, environment: Option<&str>) -> (String, String) {
        let DwkpBody::ToolDeniedV5(denied) = body else {
            panic!("not denied: {body:?}")
        };
        let action = denied.plan.actions.as_slice()[0].workload.as_ref().unwrap();
        let named = action.environment_id.as_ref().map(|e| e.as_str());
        assert!(
            named.is_none() || named == environment,
            "the denial names {named:?}, the run's live environment being {environment:?}: \
             {action:?}"
        );
        (
            action.decision.reason.as_str().to_owned(),
            action.decision.rule_id.as_str().to_owned(),
        )
    }

    /// A test's groups of cases, each run on its own: a group that does not
    /// hold is kept and the next one still runs, so one hosted run reports
    /// every group that fails, not only a test's first (run 42846068083
    /// showed one failure per test). The test fails at its end when any
    /// group did, and the task judges no evidence line of a run whose tests
    /// did not all pass: nothing is weakened.
    #[derive(Default)]
    struct Groups {
        failed: Vec<String>,
    }

    impl Groups {
        fn run(&mut self, name: &str, group: impl FnOnce()) {
            let held = std::panic::catch_unwind(std::panic::AssertUnwindSafe(group));
            if let Err(cause) = held {
                let said = cause
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| cause.downcast_ref::<&str>().copied())
                    .unwrap_or("a panic without a message");
                eprintln!("GROUP FAILED: {name}");
                self.failed.push(format!("{name}: {}", bounded(said)));
            }
        }

        fn end(self) {
            assert!(
                self.failed.is_empty(),
                "{} group(s) did not hold:\n{}",
                self.failed.len(),
                self.failed.join("\n")
            );
        }
    }

    #[derive(Debug)]
    struct Ran {
        environment: String,
        exit: Option<u8>,
        stdout: String,
        stderr: String,
        invocation: String,
    }

    impl Ran {
        fn of(body: &DwkpBody, invocation: String) -> Self {
            let out = sandboxed(body);
            assert_eq!(out.assurance, ExecutionAssurance::ContainerIsolation);
            assert_eq!(out.residue, ResidueVerdict::Pass, "{out:?}");
            assert!(!out.environment_destroyed, "{out:?}");
            assert!(
                matches!(out.ending, SandboxEnding::Exited),
                "an ending other than an exit: {out:?}"
            );
            Self {
                environment: out.environment_id.as_str().to_owned(),
                exit: out.exit_code.map(|c| c.get()),
                stdout: String::from_utf8_lossy(&out.stdout.content.to_bytes()).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr.content.to_bytes()).into_owned(),
                invocation,
            }
        }

        fn said(&self, needle: &str) -> bool {
            self.stdout.contains(needle) || self.stderr.contains(needle)
        }

        /// Whether npm reported Node.js's own refusal of a certificate --
        /// not merely a failure, which npm's configuration refusing to load
        /// is too (run 42858621579).
        fn tls_refused(&self) -> bool {
            NODE_TLS_REFUSALS.iter().any(|code| self.said(code))
        }

        fn failed(&self) -> bool {
            !matches!(self.exit, Some(0))
        }
    }

    // ---- the lab ------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Policy {
        /// The evidence's own operator policy: the image's tools, by digest,
        /// under the shipped packs' obligation, without their `argv_safe`.
        Evidence,
        /// A shipped pack, as an operator would start it.
        Shipped(&'static str),
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Setup {
        /// Whether `serve` is given the evidence-only option for both profiles.
        profiles: bool,
        policy: Policy,
        /// Whether the image carries the two trust files.
        trusted: bool,
    }

    const AS_PROPOSED: Setup = Setup {
        profiles: true,
        policy: Policy::Evidence,
        trusted: true,
    };

    struct Lab {
        dir: TempDir,
        pins: Pins,
        runtime: Runtime,
        reaper: Reaper,
        fixtures: PathBuf,
        plan: json::Object,
        granted: Origin,
        ungranted: Origin,
        rogue: Origin,
        system: Origin,
        broker: Option<Broker>,
        server: Option<Server>,
        socket: PathBuf,
        /// Every container the runtime held before the lab made any.
        before: BTreeSet<String>,
    }

    fn policy_text(pins: &Pins) -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5e5"

[[rule]]
id = "{RULE}"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{python}@{python_sha}", "{npm}@{npm_sha}", "{npx}@{npx_sha}", "{pip}@{pip_sha}"]
obligations = ["workspace_exec_hygiene", "max_output_bytes=524288"]

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
            python = pins.python,
            python_sha = pins.python_sha,
            npm = pins.npm,
            npm_sha = pins.npm_sha,
            npx = pins.npx,
            npx_sha = pins.npx_sha,
            pip = pins.pip,
            pip_sha = pins.pip_sha,
        )
    }

    impl Lab {
        fn new(tag: &str, setup: Setup) -> Self {
            hosted();
            let pins = Pins::load();
            let runtime = Runtime {
                client: PathBuf::from(&pins.runtime),
                socket: pins.socket.clone(),
            };
            let before = runtime.containers(&[]);
            let reaper = Reaper {
                runtime: runtime.clone(),
                stores: Mutex::new(BTreeSet::new()),
            };
            let dir = TempDir::new(tag);
            let pki = pins.pki.clone();

            let fixtures = dir.path().join("fixtures");
            host_json(
                "tests/sandbox/registry_fixtures.py",
                &[
                    SEED,
                    fixtures.to_str().unwrap(),
                    "--granted-port",
                    &GRANTED_PORT.to_string(),
                    "--ungranted-port",
                    &UNGRANTED_PORT.to_string(),
                ],
            );
            let plan = host_json(
                "tests/sandbox/registry_inspect.py",
                &["plan", fixtures.to_str().unwrap()],
            );
            assert_eq!(text(&plan, "marker_dir"), "/workspace");
            let manifest = fixtures.join("manifest.json");
            let granted =
                Origin::registry(&pki, "registry-granted", &manifest, "granted", GRANTED_PORT);
            let ungranted = Origin::registry(
                &pki,
                "registry-ungranted",
                &manifest,
                "ungranted",
                UNGRANTED_PORT,
            );
            let rogue = Origin::registry(&pki, "registry-rogue", &manifest, "granted", ROGUE_PORT);
            let system =
                Origin::registry(&pki, "registry-system", &manifest, "granted", SYSTEM_PORT);

            let egress = dir.path().join("egress.fixture");
            std::fs::write(
                &egress,
                format!(
                    "# The M5e.5 evidence's names.\n\
                     resolve {GRANTED} 127.0.0.1\n\
                     resolve {UNGRANTED} 127.0.0.1\n\
                     allow 127.0.0.1\n"
                ),
            )
            .unwrap();
            mode(&egress, 0o644);

            // One workspace per run (the preparation handoff's D2): a run's
            // project sits at its own workspace's root, where `npm ci` reads
            // it, and nothing one case leaves reaches another.
            let state = dir.state();
            let text = policy_text(&pins);
            let set = match setup.policy {
                Policy::Evidence => policy("m5e5", &text),
                Policy::Shipped(name) => PolicySet::shipped(name).expect("the pack ships"),
            };
            let mode_of = match setup.policy {
                Policy::Shipped("power") => Mode::Power,
                _ => Mode::Balanced,
            };
            {
                let config = StartupConfig::new(set, mode_of, {
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
                for n in 1..=RUNS {
                    let root = dir.path().join(format!("workspace-{n}"));
                    std::fs::create_dir(&root).unwrap();
                    mode(&root, 0o777);
                    let tools = root.join("tools");
                    std::fs::create_dir(&tools).unwrap();
                    mode(&tools, 0o755);
                    let inspect = tools.join("registry_inspect.py");
                    std::fs::copy(repo().join("tests/sandbox/registry_inspect.py"), &inspect)
                        .unwrap();
                    mode(&inspect, 0o644);
                    let ws = WorkspaceId::new(&format!("ws{n}")).unwrap();
                    operator
                        .install_workspace(&ws, WorkspaceSensitivity::Private)
                        .unwrap();
                    operator
                        .install_workspace_root(&ws, root.to_str().unwrap())
                        .unwrap();
                    operator.bind_session_workspace(&session(n), &ws).unwrap();
                }
            }
            let policy_file = dir.path().join("m5e5.toml");
            std::fs::write(&policy_file, &text).unwrap();
            mode(&policy_file, 0o600);
            let image = if setup.trusted {
                &pins.image
            } else {
                &pins.image_no_trust
            };
            let config = dir.path().join("sandbox.toml");
            std::fs::write(
                &config,
                format!(
                    "schema_version = 1\nruntime = \"{runtime}\"\nsocket = \"{socket}\"\n\
                     image = \"{image}\"\nprobe_sha256 = \"{probe}\"\nnetwork = \"PROXY_ONLY\"\n\
                     [egress]\nrelay_sha256 = \"{relay}\"\nmax_tunnels = {MAX_TUNNELS}\n\
                     max_upload_bytes = {MAX_UPLOAD}\nmax_download_bytes = {MAX_DOWNLOAD}\n\
                     [budget]\nworkloads = 400\nseconds = 72000\n\
                     [executables]\n\"{python}\" = \"{python_sha}\"\n\"{npm}\" = \"{npm_sha}\"\n\
                     \"{npx}\" = \"{npx_sha}\"\n\"{pip}\" = \"{pip_sha}\"\n\
                     [workspace]\nunverified_evidence = true\n",
                    runtime = pins.runtime,
                    socket = pins.socket,
                    probe = pins.probe,
                    relay = pins.relay,
                    python = pins.python,
                    python_sha = pins.python_sha,
                    npm = pins.npm,
                    npm_sha = pins.npm_sha,
                    npx = pins.npx,
                    npx_sha = pins.npx_sha,
                    pip = pins.pip,
                    pip_sha = pins.pip_sha,
                ),
            )
            .unwrap();
            mode(&config, 0o600);

            let broker_socket = dir.path().join("broker").join("broker.sock");
            let egress_flag = egress.display().to_string();
            let broker = Broker::start(
                &broker_socket,
                own_uid(),
                &[
                    "--allow-evidence-egress",
                    &egress_flag,
                    "--allow-unverified-workspace",
                    "--allow-shared-authority-uid",
                ],
            );
            let socket = dir.path().join("ipc").join("kernel.sock");
            // The longest lease the authority allows: a client cannot renew
            // while its one request is in flight, and npm retries a refused
            // connection for over a minute (run 42858621579: a 72 s `npm ci`
            // outlived the default 60 s lease).
            let ttl = MAX_LEASE_TTL_MS.to_string();
            let mut args: Vec<String> = [
                "serve",
                "--lease-ttl-ms",
                &ttl,
                "--state-dir",
                state.to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--mode",
                match setup.policy {
                    Policy::Shipped("power") => "power",
                    _ => "balanced",
                },
                "--broker-socket",
                broker_socket.to_str().unwrap(),
                "--sandbox-config",
                config.to_str().unwrap(),
                "--allow-uid",
                &own_uid().to_string(),
                "--allow-authority-uid",
                "--broker-uid",
                &own_uid().to_string(),
                "--allow-shared-broker-uid",
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            match setup.policy {
                Policy::Evidence => args.extend([
                    "--policy-file".to_owned(),
                    policy_file.to_str().unwrap().to_owned(),
                    "--policy-profile".to_owned(),
                    "m5e5".to_owned(),
                ]),
                Policy::Shipped(name) => {
                    args.extend(["--policy-shipped".to_owned(), name.to_owned()]);
                }
            }
            if setup.profiles {
                for name in ["npm", "pip"] {
                    args.extend([
                        "--allow-unaccepted-hygiene-profile".to_owned(),
                        name.to_owned(),
                    ]);
                }
            }
            let mut ceiling = ceiling();
            ceiling.push("process.exec:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            let server = Server::start(&args);
            let said = server.stderr();
            assert!(
                said.contains("execution environment attached from"),
                "{said}"
            );
            // The option says so at start, or is absent.
            assert_eq!(
                said.contains("REDUCED ASSURANCE: --allow-unaccepted-hygiene-profile npm pip"),
                setup.profiles,
                "{said}"
            );
            Self {
                dir,
                pins,
                runtime,
                reaper,
                fixtures,
                plan,
                granted,
                ungranted,
                rogue,
                system,
                broker: Some(broker),
                server: Some(server),
                socket,
                before,
            }
        }

        /// Run `n`'s workspace root on the host.
        fn workspace(&self, n: u64) -> PathBuf {
            self.dir.path().join(format!("workspace-{n}"))
        }

        /// A file of the fixtures', put at `name` in run `n`'s workspace.
        fn place(&self, n: u64, fixture: &str, name: &str) {
            let to = self.workspace(n).join(name);
            std::fs::copy(self.fixtures.join(fixture), &to).unwrap();
            mode(&to, 0o644);
        }

        /// A file of the run's PKI, put at `name` in run `n`'s workspace.
        fn place_pki(&self, n: u64, file: &str, name: &str) {
            let to = self.workspace(n).join(name);
            std::fs::copy(self.pins.pki.join(file), &to).unwrap();
            mode(&to, 0o644);
        }

        /// The fixtures' npm project at the workspace's root (D2).
        fn npm_project(&self, n: u64) {
            for name in ["package.json", "package-lock.json"] {
                self.place(n, &format!("workspace/npm/{name}"), name);
            }
        }

        fn marker(&self, n: u64, what: &str) -> PathBuf {
            let name = text(member(&self.plan, "markers"), what);
            assert!(!name.is_empty(), "no marker {what}");
            self.workspace(n).join(name)
        }

        /// Every marker the fixtures write whose key starts with `prefix`, in
        /// run `n`'s workspace.
        fn markers(&self, n: u64, prefix: &str) -> Vec<PathBuf> {
            member(&self.plan, "markers")
                .iter()
                .filter(|(what, _)| what.starts_with(prefix))
                .map(|(what, _)| self.marker(n, what))
                .collect()
        }

        fn npm_package(&self, role: &str) -> (String, String) {
            let npm = member(&self.plan, "npm");
            let package = member(member(npm, "packages"), role);
            (text(package, "name"), text(package, "version"))
        }

        fn project(&self, role: &str) -> (String, String, String) {
            let project = member(member(&self.plan, "projects"), role);
            (
                text(project, "name"),
                text(project, "version"),
                text(project, "file"),
            )
        }

        fn peer(&self, n: u64, extra: &[String]) -> Peer {
            assert!(n <= RUNS, "more runs than the lab has workspaces");
            let mut grants = vec![
                "process.exec:*".to_owned(),
                "fs.read:/workspace".to_owned(),
                format!("network.https:{GRANTED}:{GRANTED_PORT}"),
            ];
            grants.extend_from_slice(extra);
            let refs: Vec<&str> = grants.iter().map(String::as_str).collect();
            Peer::admit(Client::connect(&self.socket), n, &refs)
        }

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

        fn rows(&self, sql: &str, run: &RunId) -> i64 {
            raw(&self.dir.state())
                .query_row(sql, [run.as_str()], |row| row.get(0))
                .unwrap()
        }

        fn last_events(&self) -> String {
            let events = self.broker.as_ref().map_or_else(Vec::new, Broker::events);
            let from = events.len().saturating_sub(24);
            events[from..].join("\n")
        }

        /// A failure's report, bounded.
        fn why(&self, what: &str, ran: Option<&Ran>) -> String {
            let mut report = format!("{what}\n");
            if let Some(ran) = ran {
                report.push_str(&format!(
                    "workload: {}\nexit: {:?}; environment {}\nstdout:\n{}stderr:\n{}",
                    ran.invocation,
                    ran.exit,
                    ran.environment,
                    bounded(&ran.stdout),
                    bounded(&ran.stderr)
                ));
            }
            for (name, origin) in [
                ("granted", &self.granted),
                ("ungranted", &self.ungranted),
                ("rogue", &self.rogue),
                ("system", &self.system),
            ] {
                report.push_str(&format!(
                    "the {name} origin: {} request(s)\n",
                    origin.requests().len()
                ));
            }
            report.push_str(&format!(
                "the broker's last events:\n{}\n",
                self.last_events()
            ));
            report
        }

        /// A workload of `executable`, run in the peer's environment.
        fn run(&self, peer: &mut Peer, executable: &str, args: &[&str]) -> Ran {
            let body = peer.exec(executable, args);
            assert!(
                matches!(body, DwkpBody::ToolResultV5(_)),
                "the workload did not run: {body:?}\n{}",
                self.why("not run", None)
            );
            Ran::of(&body, format!("{executable} {}", args.join(" ")))
        }

        fn npm(&self, peer: &mut Peer, args: &[&str]) -> Ran {
            self.run(peer, &self.pins.npm.clone(), args)
        }

        fn pip(&self, peer: &mut Peer, args: &[&str]) -> Ran {
            self.run(peer, &self.pins.pip.clone(), args)
        }

        fn python(&self, peer: &mut Peer, args: &[&str]) -> Ran {
            self.run(peer, &self.pins.python.clone(), args)
        }

        /// What `path` holds inside the environment, as the inspection's
        /// JSON: `{"exists": .., "files": {..}}`.
        fn tree(&self, peer: &mut Peer, path: &str) -> json::Object {
            let ran = self.python(peer, &["-I", INSPECT, "tree", path]);
            assert_eq!(ran.exit, Some(0), "{}", self.why("tree", Some(&ran)));
            object(&ran.stdout)
        }

        fn files(&self, peer: &mut Peer, path: &str) -> usize {
            match self.tree(peer, path).get("files") {
                Some(Value::Object(files)) => files.len(),
                _ => 0,
            }
        }

        /// pip's target holds exactly `roles`' wheels (`registry_inspect.py
        /// check`), with what pip compiles from them by default
        /// (`--compiled`: under the profile no invocation says
        /// `--no-compile`, as M5e.4's did; run 42846068083): how many files.
        fn installed(&self, peer: &mut Peer, target: &str, roles: &[&str]) -> usize {
            let measured = self.tree(peer, &format!("{TARGETS}/{target}"));
            let file = self
                .dir
                .path()
                .join(format!("tree-{target}-{}.json", next()));
            std::fs::write(&file, json::to_canonical_string(&Value::Object(measured))).unwrap();
            let verdict = host_json(
                "tests/sandbox/registry_inspect.py",
                &[
                    "check",
                    self.fixtures.to_str().unwrap(),
                    &roles.join(","),
                    file.to_str().unwrap(),
                    "--compiled",
                ],
            );
            assert!(flag(&verdict, "ok"), "{target}: {verdict:?}");
            match verdict.get("files") {
                Some(Value::Number(json::Number::Int(n))) => usize::try_from(*n).unwrap(),
                other => panic!("no count: {other:?}"),
            }
        }

        /// The probe's questions to the proxy for `environment`.
        fn probe_questions(&self, environment: &str) -> u64 {
            let state = self.dir.state();
            let of = |event: &str| -> Vec<json::Object> {
                audit_records(&state, event)
                    .into_iter()
                    .filter(|r| {
                        super::state_support::text(r, "environment_id") == Some(environment)
                    })
                    .collect()
            };
            let ready = of("environment.ready");
            assert_eq!(ready.len(), 1, "{environment} was not made ready once");
            for list in ["failed", "unobservable"] {
                assert!(!texts(&ready[0], list).iter().any(|i| i == PROBE_INVARIANT));
            }
            1 + u64::try_from(of("environment.measured").len()).unwrap()
        }

        /// End the run: its environment's destruction record, and the proxy
        /// refusals its workloads caused.
        fn release(&self, peer: &mut Peer, environment: &str) -> u64 {
            peer.release();
            beyond_the_probe(
                &self.destroyed(environment),
                self.probe_questions(environment),
            )
        }

        /// End a run whose tool refused a certificate itself: the proxy
        /// carried at least one tunnel -- the refusal was the tool's, past
        /// the grant -- and refused nothing beyond the probe's questions.
        fn release_tunnelled(&self, peer: &mut Peer, environment: &str) {
            peer.release();
            let dispositions = self.destroyed(environment);
            assert!(
                tunnels(&dispositions) >= 1,
                "the proxy carried no tunnel: {dispositions:?}"
            );
            assert_eq!(
                beyond_the_probe(&dispositions, self.probe_questions(environment)),
                0,
                "{dispositions:?}"
            );
        }

        /// A destroyed environment, its containers gone: the proxy's
        /// dispositions its destruction recorded.
        fn destroyed(&self, environment: &str) -> Vec<String> {
            for role in ["environment", "relay", "setup"] {
                assert!(
                    self.runtime.role(environment, role).is_empty(),
                    "a {role} container of the destroyed environment remains"
                );
            }
            let destroyed = audit_records(&self.dir.state(), "environment.destroyed")
                .into_iter()
                .find(|r| super::state_support::text(r, "environment_id") == Some(environment))
                .expect("the destruction was audited");
            texts(&destroyed, "egress_dispositions")
        }

        /// The plan the authority recorded for the run's last workload of
        /// `executable`: its launch, the obligation's arguments and the
        /// argv. By executable, not merely the last: a case measures with
        /// the interpreter after the tool, and that is a workload too (run
        /// 42858621579 read the measurement's plan, `HYGIENE`, for pip's).
        fn recorded_plan(
            &self,
            run: &RunId,
            executable: &str,
        ) -> (String, Vec<String>, Vec<String>) {
            let record = audit_records(&self.dir.state(), "workload.intent_recorded")
                .into_iter()
                .rev()
                .find(|r| {
                    super::state_support::text(r, "run_id") == Some(run.as_str())
                        && texts(r, "argv").first().map(String::as_str) == Some(executable)
                })
                .unwrap_or_else(|| panic!("no intent of {executable} was audited"));
            (
                super::state_support::text(&record, "launch")
                    .unwrap_or_default()
                    .to_owned(),
                texts(&record, "hygiene_args"),
                texts(&record, "argv"),
            )
        }

        /// pip told to install `base` from the granted name served on
        /// `port` under an issuer it must not trust (`origin`'s): the proxy
        /// carries the granted tunnel and pip's own verification ends it.
        fn untrusted_issuer(&self, n: u64, case: &str, origin: &str, port: u16, base: &str) {
            let mut a = self.peer(n, &[format!("network.https:{GRANTED}:{port}")]);
            let target = format!("{TARGETS}/{origin}");
            let ran = self.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &index(GRANTED, port),
                    "--target",
                    &target,
                    base,
                ],
            );
            assert!(ran.failed(), "{}", self.why(case, Some(&ran)));
            assert!(
                ran.said("CERTIFICATE_VERIFY_FAILED") || ran.said("certificate verify failed"),
                "{}",
                self.why("no verification failure", Some(&ran))
            );
            self.container(&a.run);
            assert_eq!(self.files(&mut a, &target), 0);
            let reached = if origin == "rogue" {
                self.rogue.requests().len()
            } else {
                self.system.requests().len()
            };
            assert_eq!(reached, 0, "{case}: a request reached the origin");
            assert_eq!(self.release(&mut a, &ran.environment), 0);
            evidence(
                case,
                &format!("refused:nothing-installed;{origin}-issuer;certificate-verify-failed"),
                "workload-tls-verification",
            );
        }

        /// The census at a lab's end: every environment its store made gone
        /// by its labels, and every container that predates it still there.
        fn census(&self) -> String {
            let stores = self.reaper.stores.lock().unwrap().clone();
            for store in &stores {
                let left = self
                    .runtime
                    .containers(&[format!("label=io.direwolf.store={store}")]);
                assert!(left.is_empty(), "the store's containers remain: {left:?}");
            }
            let now = self.runtime.containers(&[]);
            assert!(
                self.before.is_subset(&now),
                "a container that predates the lab is gone"
            );
            format!("{}-stores-clean", stores.len())
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            if let Some(mut server) = self.server.take() {
                server.kill();
            }
            if let Some(mut broker) = self.broker.take() {
                broker.kill();
            }
        }
    }

    fn index(host: &str, port: u16) -> String {
        format!("https://{host}:{port}/simple/")
    }

    fn registry(host: &str, port: u16) -> String {
        format!("https://{host}:{port}/npm/")
    }

    // ---- npm, as ADR-0054 proposes ------------------------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-hygiene-evidence on a disposable GitHub-hosted runner"]
    fn npm_under_its_proposed_profile() {
        let lab = Lab::new("m5e5n", AS_PROPOSED);
        let granted = registry(GRANTED, GRANTED_PORT);
        let (plain, _) = lab.npm_package("plain");
        let mut groups = Groups::default();
        let mut changed: Option<Vec<String>> = None;
        let mut n = 0;

        // 1. `npm ci`: the lockfile's packages, scripts off.
        n += 1;
        groups.run("npm-ci-granted-registry-installs", || {
            lab.npm_project(n);
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["ci", "--registry", &granted]);
            assert_eq!(ran.exit, Some(0), "{}", lab.why("npm ci", Some(&ran)));
            let container = lab.container(&a.run);
            let modules = lab.files(&mut a, "/workspace/node_modules");
            assert!(modules >= 4, "{modules} files in node_modules");
            let markers = lab.markers(n, "npm-");
            assert!(markers.len() >= 8, "{markers:?}");
            let run_markers: Vec<&PathBuf> = markers.iter().filter(|m| m.exists()).collect();
            assert!(run_markers.is_empty(), "a script ran: {run_markers:?}");
            changed = Some(lab.runtime.changed(&container));
            let (launch, prefix, argv) = lab.recorded_plan(&a.run, &lab.pins.npm);
            let refused = lab.release(&mut a, &ran.environment);
            assert_eq!(refused, 0, "{}", lab.why("a refusal", Some(&ran)));
            evidence(
                "npm-ci-granted-registry-installs",
                &format!("installed:{modules}-files-in-node_modules;lockfile"),
                "relay-and-connect-proxy-grant",
            );
            evidence(
                "npm-lifecycle-scripts-not-run",
                &format!(
                    "not-run:{}-markers-absent;root-and-dependency",
                    markers.len()
                ),
                "hygiene-launcher",
            );
            // `changed` is judged last, with the other measured-not-assumed
            // cases, so a first run's surprise there hides no other case.
            assert_eq!(launch, "HYGIENE_NPM");
            assert_eq!(prefix, NPM_PREFIX);
            assert_eq!(&argv[1..=NPM_PREFIX.len()], NPM_PREFIX, "{argv:?}");
            evidence(
                "npm-plan-records-prefix-and-profile",
                &format!("recorded:launch-{launch};prefix-{}", prefix.join(" ")),
                "authority-ledger",
            );
        });

        // 2. `npm install` of one registry name.
        n += 1;
        groups.run("npm-install-granted-registry-installs", || {
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["install", "--registry", &granted, &plain]);
            assert_eq!(ran.exit, Some(0), "{}", lab.why("npm install", Some(&ran)));
            lab.container(&a.run);
            let modules = lab.files(&mut a, &format!("/workspace/node_modules/{plain}"));
            assert!(modules >= 2, "{modules}");
            assert_eq!(lab.release(&mut a, &ran.environment), 0);
            evidence(
                "npm-install-granted-registry-installs",
                &format!("installed:{modules}-files;{plain}"),
                "relay-and-connect-proxy-grant",
            );
        });

        // 3-5. The ungranted registry, a tarball on the ungranted host, and a
        // packument redirected there: each refused at CONNECT.
        for (case, role) in [
            ("npm-ungranted-registry-refused", None),
            (
                "npm-tarball-on-ungranted-host-refused",
                Some("offsite-parent"),
            ),
            ("npm-redirect-to-ungranted-host-refused", Some("redirected")),
        ] {
            n += 1;
            groups.run(case, || {
                let served = lab.ungranted.requests().len();
                let args = match role {
                    None => vec![
                        "install".to_owned(),
                        "--registry".to_owned(),
                        registry(UNGRANTED, UNGRANTED_PORT),
                        plain.clone(),
                    ],
                    Some(role) => vec![
                        "install".to_owned(),
                        "--registry".to_owned(),
                        granted.clone(),
                        lab.npm_package(role).0,
                    ],
                };
                let mut a = lab.peer(n, &[]);
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                let ran = lab.npm(&mut a, &refs);
                assert!(ran.failed(), "{}", lab.why(case, Some(&ran)));
                lab.container(&a.run);
                let left = lab.files(&mut a, "/workspace/node_modules");
                assert_eq!(left, 0, "{case}: something was installed");
                let refused = lab.release(&mut a, &ran.environment);
                assert!(refused >= 1, "{}", lab.why(case, Some(&ran)));
                assert_eq!(
                    lab.ungranted.requests().len(),
                    served,
                    "{case}: the ungranted origin"
                );
                evidence(
                    case,
                    &format!("refused:nothing-installed;TARGET_NOT_GRANTED={refused}"),
                    "connect-proxy:grant",
                );
            });
        }

        // 7-8. A workspace `.npmrc` asking for scripts, TLS off and its own
        // trust, and naming a user and a global configuration in the
        // workspace. `npm_config_userconfig` outranks the project's choice:
        // the user file says `offline=true`, so were it read, `npm ci` would
        // fail at once (`ENOTCACHED`). The global file is another matter
        // (ADR-0054 §2, revised for F-NPM-CONFIG): npm 11 keeps a
        // `globalconfig` from the environment on its lowest, default layer,
        // so the project's choice of that file wins and npm reads it -- as
        // global configuration, below the project file itself and below
        // every pin. It asks for scripts and for TLS off again: scripts stay
        // off and the image's trust stays in force all the same.
        n += 1;
        groups.run("npm-project-npmrc-cannot-reenable-scripts", || {
            lab.npm_project(n);
            lab.place(n, "workspace/npm-hostile.npmrc", ".npmrc");
            let hostile =
                std::fs::read_to_string(lab.fixtures.join("workspace/npm-hostile.npmrc")).unwrap();
            let mut written = 0;
            for (key, says) in [
                ("userconfig=", "offline=true\n"),
                ("globalconfig=", "ignore-scripts=false\nstrict-ssl=false\n"),
            ] {
                let named = hostile
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .unwrap_or_else(|| panic!("the hostile .npmrc names no {key}"));
                let file = named
                    .strip_prefix("/workspace/")
                    .unwrap_or_else(|| panic!("{key} names {named}, outside the workspace"));
                let at = lab.workspace(n).join(file);
                std::fs::write(&at, says).unwrap();
                mode(&at, 0o644);
                written += 1;
            }
            assert_eq!(written, 2);
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["ci", "--registry", &granted]);
            assert_eq!(
                ran.exit,
                Some(0),
                "{}",
                lab.why("npm ci, hostile .npmrc", Some(&ran))
            );
            lab.container(&a.run);
            let markers = lab.markers(n, "npm-");
            assert!(
                markers.iter().all(|m| !m.exists()),
                "a script ran: {markers:?}"
            );
            lab.release(&mut a, &ran.environment);
            evidence(
                "npm-project-npmrc-cannot-reenable-scripts",
                &format!(
                    "not-run:{}-markers-absent;hostile-npmrc;user-config-unread;global-below-pins",
                    markers.len()
                ),
                "hygiene-launcher",
            );
        });

        // 9. `strict-ssl=false` in the workspace: the untrusted issuer still refused.
        n += 1;
        groups.run("npm-project-npmrc-cannot-disable-tls", || {
            lab.place(n, "workspace/npm-hostile.npmrc", ".npmrc");
            let mut a = lab.peer(n, &[format!("network.https:{GRANTED}:{ROGUE_PORT}")]);
            let ran = lab.npm(
                &mut a,
                &[
                    "install",
                    "--registry",
                    &registry(GRANTED, ROGUE_PORT),
                    &plain,
                ],
            );
            assert!(
                ran.failed(),
                "{}",
                lab.why("rogue under a hostile .npmrc", Some(&ran))
            );
            assert!(
                ran.tls_refused(),
                "{}",
                lab.why("no certificate refusal of npm's own", Some(&ran))
            );
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, "/workspace/node_modules"), 0);
            assert!(
                lab.rogue.requests().is_empty(),
                "a request reached the rogue origin"
            );
            lab.release_tunnelled(&mut a, &ran.environment);
            evidence(
                "npm-project-npmrc-cannot-disable-tls",
                "refused:nothing-installed;untrusted-issuer;strict-ssl-false-in-npmrc",
                "workload-tls-verification",
            );
        });

        // 10. A workspace `.npmrc` naming its own CA (the rogue authority's):
        // the granted registry, trusted only through the image's file, installs.
        n += 1;
        groups.run("npm-project-npmrc-cannot-replace-ca", || {
            lab.place_pki(n, "rogue.pem", "own-ca.pem");
            std::fs::write(
                lab.workspace(n).join(".npmrc"),
                "cafile=/workspace/own-ca.pem\n",
            )
            .unwrap();
            mode(&lab.workspace(n).join(".npmrc"), 0o644);
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["install", "--registry", &granted, &plain]);
            assert_eq!(
                ran.exit,
                Some(0),
                "{}",
                lab.why("own CA in .npmrc", Some(&ran))
            );
            lab.container(&a.run);
            assert!(lab.files(&mut a, &format!("/workspace/node_modules/{plain}")) >= 2);
            lab.release(&mut a, &ran.environment);
            evidence(
                "npm-project-npmrc-cannot-replace-ca",
                "installed:image-trust-file-in-force;npmrc-cafile-ignored",
                "hygiene-launcher",
            );
        });

        // 12. A git dependency: nothing fetched, nothing prepared.
        n += 1;
        groups.run("npm-git-dependency-not-prepared", || {
            let (git_parent, _) = lab.npm_package("git-parent");
            let served = lab.ungranted.requests().len();
            let asked = lab.granted.to(&format!("/npm/{git_parent}")).len();
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["install", "--registry", &granted, &git_parent]);
            assert!(ran.failed(), "{}", lab.why("git dependency", Some(&ran)));
            // npm got as far as the parent: it asked the granted registry
            // for it, so what stopped it was the git dependency, not npm
            // failing before it began (run 42858621579 counted that).
            assert!(
                lab.granted.to(&format!("/npm/{git_parent}")).len() > asked,
                "{}",
                lab.why("npm never asked for the parent", Some(&ran))
            );
            lab.container(&a.run);
            assert!(
                !lab.marker(n, "npm-git-dep-prepare").exists(),
                "prepare ran"
            );
            assert_eq!(
                lab.ungranted.requests().len(),
                served,
                "the git host was reached"
            );
            lab.release(&mut a, &ran.environment);
            evidence(
                "npm-git-dependency-not-prepared",
                "not-prepared:no-prepare-marker;no-git-fetch",
                "workload-effects-measured",
            );
        });

        // 13. The granted name under an issuer npm must not trust.
        n += 1;
        groups.run("npm-untrusted-issuer-refused", || {
            let mut a = lab.peer(n, &[format!("network.https:{GRANTED}:{ROGUE_PORT}")]);
            let ran = lab.npm(
                &mut a,
                &[
                    "install",
                    "--registry",
                    &registry(GRANTED, ROGUE_PORT),
                    &plain,
                ],
            );
            assert!(ran.failed(), "{}", lab.why("rogue", Some(&ran)));
            assert!(
                ran.tls_refused(),
                "{}",
                lab.why("no certificate refusal of npm's own", Some(&ran))
            );
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, "/workspace/node_modules"), 0);
            assert!(
                lab.rogue.requests().is_empty(),
                "a request reached the rogue origin"
            );
            lab.release_tunnelled(&mut a, &ran.environment);
            evidence(
                "npm-untrusted-issuer-refused",
                "refused:nothing-installed;untrusted-issuer;tunnel-granted",
                "workload-tls-verification",
            );
        });

        // 14. A tarball tampered against its packument's integrity.
        n += 1;
        groups.run("npm-tampered-tarball-refused", || {
            let (tampered, _) = lab.npm_package("tampered");
            let mut a = lab.peer(n, &[]);
            let ran = lab.npm(&mut a, &["install", "--registry", &granted, &tampered]);
            assert!(ran.failed(), "{}", lab.why("tampered", Some(&ran)));
            assert!(
                ran.said("EINTEGRITY"),
                "{}",
                lab.why("not EINTEGRITY", Some(&ran))
            );
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, "/workspace/node_modules"), 0);
            lab.release(&mut a, &ran.environment);
            evidence(
                "npm-tampered-tarball-refused",
                "refused:EINTEGRITY;nothing-installed",
                "workload-integrity-verification",
            );
        });

        // 16-19. Refused before an intent, each by the authority.
        n += 1;
        groups.run(
            "npm-undoing-arguments-refused and the other refusals",
            || {
                let mut a = lab.peer(n, &[]);
                let before_runs =
                    lab.rows("SELECT count(*) FROM environment WHERE run_id = ?1", &a.run);
                let mut undoing = 0;
                for undo in [
                    "--ignore-scripts=false",
                    "--no-ignore-scripts",
                    "--userconfig=/workspace/x",
                    "--globalconfig=/workspace/x",
                    "--strict-ssl=false",
                    "--no-strict-ssl",
                    "-g",
                    "--global",
                    "--location=global",
                    "--prefix=/workspace/p",
                    "--script-shell=/bin/sh",
                    "--node-options=--require=/workspace/x",
                    "--foreground-scripts",
                    "--cafile=/workspace/ca.pem",
                    "--ca=x",
                ] {
                    let (reason, rule) = denied(&a.exec(&lab.pins.npm, &["install", undo, &plain]));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{undo}");
                    assert_eq!(rule, RULE, "{undo}");
                    undoing += 1;
                }
                evidence(
                    "npm-undoing-arguments-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{undoing}-arguments;no-intent"),
                    "authority-obligation",
                );
                let mut subcommands = 0;
                for sub in [
                    "run", "test", "start", "exec", "rebuild", "publish", "config", "i",
                ] {
                    let (reason, _) = denied(&a.exec(&lab.pins.npm, &[sub]));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{sub}");
                    subcommands += 1;
                }
                evidence(
                    "npm-other-subcommands-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{subcommands}-subcommands"),
                    "authority-obligation",
                );
                let mut specs = 0;
                for spec in [
                    "https://granted-registry.test:18443/x.tgz",
                    "./local",
                    "/abs/path",
                    "x.tgz",
                    "git+https://h/x.git",
                    "github:user/repo",
                    "user/repo",
                    "file:../x",
                    "link:../x",
                    "alias@npm:real",
                ] {
                    let (reason, _) = denied(&a.exec(&lab.pins.npm, &["install", spec]));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{spec}");
                    specs += 1;
                }
                let (reason, _) = denied(&a.exec(&lab.pins.npm, &["install", "--", &plain]));
                assert_eq!(reason, "OBLIGATION_UNENFORCEABLE");
                evidence(
                    "npm-non-registry-specs-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{specs}-specs-and-the-separator"),
                    "authority-obligation",
                );
                let (reason, _) = denied(&a.exec(&lab.pins.npx, &["cowsay"]));
                assert_eq!(reason, "OBLIGATION_UNENFORCEABLE");
                evidence(
                    "npx-still-refused",
                    "refused:OBLIGATION_UNENFORCEABLE;npx-with-the-npm-profile-on",
                    "authority-obligation",
                );
                assert_eq!(
                    lab.rows("SELECT count(*) FROM environment WHERE run_id = ?1", &a.run),
                    before_runs,
                    "a refusal prepared an environment"
                );
                a.release();
            },
        );

        // Last, the cases measured rather than assumed, so that a first
        // run's surprise in one hides no other case.
        // 6. npm told to go around its proxy: only the topology answers.
        n += 1;
        groups.run("npm-direct-route-refused", || {
            let mut a = lab.peer(n, &[]);
            let unrouted = format!("https://{UNROUTED}:{GRANTED_PORT}/npm/");
            let ran = lab.npm(
                &mut a,
                &[
                    "install",
                    &format!("--noproxy={UNROUTED}"),
                    "--registry",
                    &unrouted,
                    &plain,
                ],
            );
            assert!(ran.failed(), "{}", lab.why("direct npm", Some(&ran)));
            assert!(
                ran.said("ENETUNREACH"),
                "{}",
                lab.why("not ENETUNREACH", Some(&ran))
            );
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, "/workspace/node_modules"), 0);
            lab.release(&mut a, &ran.environment);
            evidence(
                "npm-direct-route-refused",
                "refused:nothing-installed;ENETUNREACH",
                "topology-no-route",
            );
        });

        // 15. What `npm ci` changed in its container's own filesystem, read
        // in the first case: nothing, its writes all under the workspace's
        // and the temporary directories' mounts.
        groups.run("npm-writes-only-workspace-and-tmp", || {
            let changed = changed.expect("the first case never measured npm ci's container");
            assert!(
                changed.is_empty(),
                "the container's own files changed: {changed:?}"
            );
            evidence(
                "npm-writes-only-workspace-and-tmp",
                "contained:no-change-outside-workspace-and-tmp",
                "read-only-root",
            );
        });
        groups.run("the census", || {
            lab.census();
        });
        groups.end();
    }

    // ---- pip, as ADR-0055 proposes ------------------------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-hygiene-evidence on a disposable GitHub-hosted runner"]
    fn pip_under_its_proposed_profile() {
        let lab = Lab::new("m5e5p", AS_PROPOSED);
        let granted = index(GRANTED, GRANTED_PORT);
        let (base, base_version, base_file) = lab.project("base");
        let mut groups = Groups::default();
        let mut changed: Option<Vec<String>> = None;
        let mut n = 0;

        // 1. A named wheel from the granted index, byte for byte.
        n += 1;
        groups.run("pip-install-granted-index-installs", || {
            let mut a = lab.peer(n, &[]);
            let target = format!("{TARGETS}/granted");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &granted,
                    "--target",
                    &target,
                    &base,
                ],
            );
            assert_eq!(ran.exit, Some(0), "{}", lab.why("pip install", Some(&ran)));
            let container = lab.container(&a.run);
            let files = lab.installed(&mut a, "granted", &["base"]);
            changed = Some(lab.runtime.changed(&container));
            let (launch, prefix, argv) = lab.recorded_plan(&a.run, &lab.pins.pip);
            assert_eq!(lab.release(&mut a, &ran.environment), 0);
            evidence(
                "pip-install-granted-index-installs",
                &format!("installed:{files}-files-as-the-fixture;{base}=={base_version}"),
                "relay-and-connect-proxy-grant",
            );
            // `changed` is judged last, with the other measured-not-assumed cases.
            assert_eq!(launch, "HYGIENE_PIP");
            assert_eq!(prefix, PIP_PREFIX);
            // After the subcommand: `pip install <prefix> <the invocation's rest>`.
            assert_eq!(argv[1], "install", "{argv:?}");
            assert_eq!(&argv[2..2 + PIP_PREFIX.len()], PIP_PREFIX, "{argv:?}");
            evidence(
                "pip-plan-records-prefix-and-profile",
                &format!(
                    "recorded:launch-{launch};prefix-after-install;{}-arguments",
                    prefix.len()
                ),
                "authority-ledger",
            );
        });

        // 2. A dependency resolved from the same index.
        n += 1;
        groups.run("pip-install-dependency-resolved-from-granted-index", || {
            let (dependent, _, _) = lab.project("dependent");
            let fetched = lab.granted.to(&format!("/files/{base_file}")).len();
            let mut a = lab.peer(n, &[]);
            let target = format!("{TARGETS}/dependency");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &granted,
                    "--target",
                    &target,
                    &dependent,
                ],
            );
            assert_eq!(ran.exit, Some(0), "{}", lab.why("dependency", Some(&ran)));
            lab.container(&a.run);
            let files = lab.installed(&mut a, "dependency", &["dependent", "base"]);
            assert_eq!(
                lab.granted.to(&format!("/files/{base_file}")).len(),
                fetched + 1
            );
            assert_eq!(lab.release(&mut a, &ran.environment), 0);
            evidence(
                "pip-install-dependency-resolved-from-granted-index",
                &format!("installed:{files}-files-as-the-fixture;{dependent}+{base}"),
                "relay-and-connect-proxy-grant",
            );
        });

        // 3-5. Refused at CONNECT.
        for (case, role, at) in [
            (
                "pip-ungranted-index-refused",
                "base",
                index(UNGRANTED, UNGRANTED_PORT),
            ),
            (
                "pip-file-on-ungranted-host-refused",
                "offsite",
                granted.clone(),
            ),
            (
                "pip-redirect-to-ungranted-host-refused",
                "redirected",
                granted.clone(),
            ),
        ] {
            n += 1;
            groups.run(case, || {
                let served = lab.ungranted.requests().len();
                let (name, _, _) = lab.project(role);
                let mut a = lab.peer(n, &[]);
                let target = format!("{TARGETS}/{role}");
                let ran = lab.pip(
                    &mut a,
                    &["install", "--index-url", &at, "--target", &target, &name],
                );
                assert!(ran.failed(), "{}", lab.why(case, Some(&ran)));
                assert!(ran.said("403"), "{}", lab.why("no 403", Some(&ran)));
                lab.container(&a.run);
                assert_eq!(
                    lab.files(&mut a, &target),
                    0,
                    "{case}: something was installed"
                );
                let refused = lab.release(&mut a, &ran.environment);
                assert!(refused >= 1, "{}", lab.why(case, Some(&ran)));
                assert_eq!(
                    lab.ungranted.requests().len(),
                    served,
                    "{case}: the ungranted origin"
                );
                evidence(
                    case,
                    &format!("refused:nothing-installed;TARGET_NOT_GRANTED={refused}"),
                    "connect-proxy:grant",
                );
            });
        }

        // 6. pip has no way around its proxy under the profile (`--proxy`
        // and `--isolated` are refused); the environment has none either.
        n += 1;
        groups.run("pip-direct-route-refused", || {
            let mut a = lab.peer(n, &[]);
            let target = format!("{TARGETS}/direct");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &index(UNROUTED, GRANTED_PORT),
                    "--target",
                    &target,
                    &base,
                ],
            );
            assert!(ran.failed(), "{}", lab.why("unrouted", Some(&ran)));
            lab.container(&a.run);
            let direct = lab.python(
                &mut a,
                &["-I", "-c", DIRECT, UNROUTED, &GRANTED_PORT.to_string()],
            );
            assert!(
                direct.said("errno=101"),
                "{}",
                lab.why("not ENETUNREACH", Some(&direct))
            );
            assert_eq!(lab.files(&mut a, &target), 0);
            lab.release(&mut a, &ran.environment);
            evidence(
                "pip-direct-route-refused",
                "refused:nothing-installed;ENETUNREACH",
                "topology-no-route",
            );
        });

        // 7-8. The source distribution, never built -- and still not when the
        // image's `pip.conf` asks for source builds (`no-binary = :all:`).
        n += 1;
        groups.run("pip-sdist-never-built", || {
            let (sdist, _, _) = lab.project("sdist");
            let mut a = lab.peer(n, &[]);
            let target = format!("{TARGETS}/sdist");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &granted,
                    "--target",
                    &target,
                    &sdist,
                ],
            );
            assert!(ran.failed(), "{}", lab.why("sdist", Some(&ran)));
            // pip found nothing it may install -- binaries only -- rather
            // than failing before it looked.
            assert!(
                ran.said("No matching distribution found"),
                "{}",
                lab.why("not pip's binary-only refusal", Some(&ran))
            );
            lab.container(&a.run);
            assert!(
                !lab.marker(n, "pip-build-backend").exists(),
                "the backend ran"
            );
            assert_eq!(lab.files(&mut a, &target), 0);
            lab.release(&mut a, &ran.environment);
            evidence(
                "pip-sdist-never-built",
                "not-built:backend-marker-absent;nothing-installed",
                "hygiene-launcher",
            );
            evidence(
                "pip-only-binary-cannot-be-undone-by-variable-or-file",
                "not-built:image-pip-conf-asks-no-binary;backend-marker-absent",
                "hygiene-launcher",
            );
        });

        // 9. The image's `pip.conf` names the ungranted index, which is
        // granted here: were it read, pip would install from it.
        n += 1;
        groups.run("pip-image-configuration-not-read", || {
            let served = lab.ungranted.requests().len();
            let mut a = lab.peer(n, &[format!("network.https:{UNGRANTED}:{UNGRANTED_PORT}")]);
            let target = format!("{TARGETS}/image-conf");
            let ran = lab.pip(&mut a, &["install", "--target", &target, &base]);
            assert!(ran.failed(), "{}", lab.why("image pip.conf", Some(&ran)));
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, &target), 0);
            assert_eq!(
                lab.ungranted.requests().len(),
                served,
                "the image's pip.conf was read"
            );
            // pip went to its own default index, which no grant names, so the
            // proxy refused it: pip ran, and without the image's file.
            let refused = lab.release(&mut a, &ran.environment);
            assert!(
                refused >= 1,
                "{}",
                lab.why("pip asked no index", Some(&ran))
            );
            evidence(
                "pip-image-configuration-not-read",
                "not-read:ungranted-index-untouched;nothing-installed",
                "hygiene-launcher",
            );
        });

        // 10. An issuer pip must not trust: the rogue authority's. (11, the
        // one only the image's system store holds, is measured last.)
        n += 1;
        groups.run("pip-untrusted-issuer-refused", || {
            lab.untrusted_issuer(
                n,
                "pip-untrusted-issuer-refused",
                "rogue",
                ROGUE_PORT,
                &base,
            );
        });

        // 13-15 and D4. Refused before an intent, each by the authority.
        n += 1;
        groups.run(
            "pip-undoing-arguments-refused and the other refusals",
            || {
                let mut a = lab.peer(n, &[]);
                let mut undoing = 0;
                for undo in [
                    &["--no-binary", ":all:"][..],
                    &["--only-binary=:none:"],
                    &["-e", "."],
                    &["--editable=."],
                    &["--config-settings", "a=b"],
                    &["--global-option=x"],
                    &["--build-option=x"],
                    &["--no-build-isolation"],
                    &["--use-pep517"],
                    &["--no-use-pep517"],
                    &["--isolated"],
                    &["--proxy", "http://p"],
                    &["--trusted-host", GRANTED],
                    &["--cert", "/workspace/ca.pem"],
                    &["--client-cert", "/workspace/c.pem"],
                    &["-r", "req.txt"],
                    &["-c", "c.txt"],
                    &["-f", "/workspace/wheels"],
                    &["--user"],
                    &["--root", "/x"],
                    &["--prefix=/x"],
                    &["--src", "/x"],
                ] {
                    let mut args = vec!["install"];
                    args.extend_from_slice(undo);
                    args.push(&base);
                    let (reason, rule) = denied(&a.exec(&lab.pins.pip, &args));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{undo:?}");
                    assert_eq!(rule, RULE);
                    undoing += 1;
                }
                evidence(
                    "pip-undoing-arguments-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{undoing}-arguments;no-intent"),
                    "authority-obligation",
                );
                let mut subcommands = 0;
                for sub in ["download", "wheel", "uninstall", "config", "cache", "debug"] {
                    let (reason, _) = denied(&a.exec(&lab.pins.pip, &[sub, &base]));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{sub}");
                    subcommands += 1;
                }
                evidence(
                    "pip-other-subcommands-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{subcommands}-subcommands"),
                    "authority-obligation",
                );
                let mut specs = 0;
                for spec in [
                    ".",
                    "./x",
                    "/abs/x",
                    "x.whl",
                    "x.tar.gz",
                    "https://h/x.whl",
                    "git+https://h/x.git",
                    "x @ https://h/x.whl",
                ] {
                    let (reason, _) = denied(&a.exec(&lab.pins.pip, &["install", spec]));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{spec}");
                    specs += 1;
                }
                evidence(
                    "pip-non-name-specs-refused",
                    &format!("refused:OBLIGATION_UNENFORCEABLE;{specs}-specs"),
                    "authority-obligation",
                );
                for args in [
                    &["-I", "-m", "pip", "install", "x"][..],
                    &["-Im", "pip", "install", "x"],
                    &["-m", "ensurepip"],
                ] {
                    let (reason, _) = denied(&a.exec(&lab.pins.python, args));
                    assert_eq!(reason, "OBLIGATION_UNENFORCEABLE", "{args:?}");
                }
                evidence(
                    "pip-interpreter-module-refused",
                    "refused:OBLIGATION_UNENFORCEABLE;python-m-pip-and-ensurepip",
                    "authority-obligation",
                );
                assert_eq!(
                    lab.rows("SELECT count(*) FROM environment WHERE run_id = ?1", &a.run),
                    0,
                    "a refusal prepared an environment"
                );
                a.release();
            },
        );

        // 16. No cache: a second install of the same wheel fetches it again.
        n += 1;
        groups.run("pip-no-cache-reused", || {
            let fetched = lab.granted.to(&format!("/files/{base_file}")).len();
            let mut a = lab.peer(n, &[]);
            for target in ["cache-1", "cache-2"] {
                let target = format!("{TARGETS}/{target}");
                let ran = lab.pip(
                    &mut a,
                    &[
                        "install",
                        "--index-url",
                        &granted,
                        "--target",
                        &target,
                        &base,
                    ],
                );
                assert_eq!(ran.exit, Some(0), "{}", lab.why("no cache", Some(&ran)));
            }
            let environment = {
                let container = lab.container(&a.run);
                let _ = container;
                raw(&lab.dir.state())
                .query_row(
                    "SELECT environment_id FROM environment WHERE run_id = ?1 AND state = 'READY'",
                    [a.run.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
            };
            let refetched = lab.granted.to(&format!("/files/{base_file}")).len() - fetched;
            assert_eq!(refetched, 2, "the second install reused a cached wheel");
            lab.release(&mut a, &environment);
            evidence(
                "pip-no-cache-reused",
                &format!("refetched:{refetched}-fetches-of-one-wheel"),
                "hygiene-launcher",
            );
        });

        // 18. A wheel's `.pth`, installed and not run by the install.
        n += 1;
        groups.run("pip-installed-pth-not-executed-by-install", || {
            let (pth, _, _) = lab.project("pth");
            let mut a = lab.peer(n, &[]);
            let target = format!("{TARGETS}/pth");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &granted,
                    "--target",
                    &target,
                    &pth,
                ],
            );
            assert_eq!(ran.exit, Some(0), "{}", lab.why("pth", Some(&ran)));
            lab.container(&a.run);
            let files = lab.installed(&mut a, "pth", &["pth"]);
            assert!(
                !lab.marker(n, "pip-pth").exists(),
                "the install ran the .pth"
            );
            lab.release(&mut a, &ran.environment);
            evidence(
                "pip-installed-pth-not-executed-by-install",
                &format!("not-run:pth-marker-absent;{files}-files-as-the-fixture"),
                "workload-effects-measured",
            );
        });

        // Last, the cases measured rather than assumed, so that a first
        // run's surprise in one hides no other case.
        // 17. What the first install changed in its container's own
        // filesystem: nothing outside the mounts.
        groups.run("pip-writes-only-workspace-and-tmp", || {
            let changed = changed.expect("the first case never measured pip's container");
            assert!(
                changed.is_empty(),
                "the container's own files changed: {changed:?}"
            );
            evidence(
                "pip-writes-only-workspace-and-tmp",
                "contained:no-change-outside-workspace-and-tmp",
                "read-only-root",
            );
        });
        // 11. The granted name under an authority only the image's system
        // store holds (ADR-0055 §5, revised for F-PIP-TRUST: with the
        // prefix's `--use-deprecated=legacy-certs`, pip makes no `truststore`
        // context, so the pinned `--cert` is its whole trust -- measured, not
        // assumed; the hosted mutant that drops the value must fail here).
        n += 1;
        groups.run("pip-os-trust-store-not-used", || {
            lab.untrusted_issuer(
                n,
                "pip-os-trust-store-not-used",
                "system",
                SYSTEM_PORT,
                &base,
            );
        });
        groups.run("the census", || {
            lab.census();
        });
        groups.end();
    }

    // ---- without a trust file, both fail closed -----------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-hygiene-evidence on a disposable GitHub-hosted runner"]
    fn without_a_trust_file_both_fail_closed() {
        let lab = Lab::new(
            "m5e5t",
            Setup {
                trusted: false,
                ..AS_PROPOSED
            },
        );
        let (plain, _) = lab.npm_package("plain");
        let (base, _, _) = lab.project("base");
        let mut groups = Groups::default();

        // The image, measured from inside: no file at either trust path. The
        // workload is the interpreter, which no trust file concerns, so the
        // environment and the launcher work, and what follows is the trust
        // file's absence alone.
        groups.run("the image without trust files", || {
            let mut a = lab.peer(1, &[]);
            let ran = lab.python(&mut a, &["-I", INSPECT, "tree", "/etc/direwolf"]);
            assert_eq!(ran.exit, Some(0), "{}", lab.why("trust paths", Some(&ran)));
            let measured = object(&ran.stdout);
            assert!(
                matches!(measured.get("files"), Some(Value::Object(files)) if files.is_empty()),
                "the image without trust files carries one: {measured:?}"
            );
            lab.container(&a.run);
            lab.release(&mut a, &ran.environment);
        });

        // npm ignores a `cafile` it cannot find and would trust Node.js's
        // bundled roots instead, so the launcher refuses the launch: npm
        // never starts, nothing is tunnelled, and the authority, which
        // cannot believe the launcher's status as npm's, ends the run's
        // environment (ADR-0052 §5).
        groups.run("npm-missing-trust-file-fails-closed", || {
            let served = lab.granted.requests().len();
            let mut a = lab.peer(2, &[]);
            let body = a.exec(
                &lab.pins.npm,
                &[
                    "install",
                    "--registry",
                    &registry(GRANTED, GRANTED_PORT),
                    &plain,
                ],
            );
            let DwkpBody::ToolFailedV5(failure) = &body else {
                panic!(
                    "npm without its trust file was not refused at launch: {body:?}\n{}",
                    lab.why("npm without its trust file", None)
                )
            };
            assert_eq!(failure.reason.as_str(), "OUTCOME_UNKNOWN", "{failure:?}");
            assert_eq!(failure.environment_destroyed, Some(true), "{failure:?}");
            let environment = failure
                .environment_id
                .as_ref()
                .expect("the failure names its environment")
                .as_str()
                .to_owned();
            a.release();
            let dispositions = lab.destroyed(&environment);
            assert_eq!(
                tunnels(&dispositions),
                0,
                "npm reached a tunnel without its trust file: {dispositions:?}"
            );
            assert_eq!(
                beyond_the_probe(&dispositions, lab.probe_questions(&environment)),
                0
            );
            assert_eq!(
                lab.granted.requests().len(),
                served,
                "the registry was asked"
            );
            assert!(!lab.workspace(2).join("node_modules").exists());
            evidence(
                "npm-missing-trust-file-fails-closed",
                "refused:nothing-installed;no-tunnel;launcher-refused;OUTCOME_UNKNOWN",
                "hygiene-launcher",
            );
        });

        // pip refuses a `--cert` it cannot find itself, before it connects.
        groups.run("pip-missing-trust-file-fails-closed", || {
            let mut a = lab.peer(3, &[]);
            let target = format!("{TARGETS}/no-trust");
            let ran = lab.pip(
                &mut a,
                &[
                    "install",
                    "--index-url",
                    &index(GRANTED, GRANTED_PORT),
                    "--target",
                    &target,
                    &base,
                ],
            );
            assert!(
                ran.failed(),
                "{}",
                lab.why("pip without its trust file", Some(&ran))
            );
            assert!(
                ran.said("Could not find a suitable TLS CA certificate bundle"),
                "{}",
                lab.why("pip did not refuse its missing trust file", Some(&ran))
            );
            lab.container(&a.run);
            assert_eq!(lab.files(&mut a, &target), 0);
            a.release();
            let dispositions = lab.destroyed(&ran.environment);
            assert_eq!(
                tunnels(&dispositions),
                0,
                "pip reached a tunnel without its trust file: {dispositions:?}"
            );
            evidence(
                "pip-missing-trust-file-fails-closed",
                "refused:nothing-installed;no-tunnel;cert-bundle-missing",
                "workload-tls-verification",
            );
        });
        groups.run("the census", || {
            lab.census();
        });
        groups.end();
    }

    // ---- without the option, nothing changes --------------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-hygiene-evidence on a disposable GitHub-hosted runner"]
    fn without_the_option_nothing_changes() {
        let lab = Lab::new(
            "m5e5o",
            Setup {
                profiles: false,
                ..AS_PROPOSED
            },
        );
        let (base, _, _) = lab.project("base");
        lab.npm_project(1);
        let mut a = lab.peer(1, &[]);
        let (reason, rule) = denied(&a.exec(
            &lab.pins.npm,
            &["ci", "--registry", &registry(GRANTED, GRANTED_PORT)],
        ));
        assert_eq!(
            (reason.as_str(), rule.as_str()),
            ("OBLIGATION_UNENFORCEABLE", RULE)
        );
        assert_eq!(
            lab.rows("SELECT count(*) FROM environment WHERE run_id = ?1", &a.run),
            0
        );
        a.release();
        evidence(
            "npm-refused-without-the-evidence-option",
            "refused:OBLIGATION_UNENFORCEABLE;option-absent;no-environment",
            "authority-obligation",
        );

        // pip, as it is today: kept with nothing pip-specific -- the
        // residual ADR-0055 exists to close, stated as such.
        let mut a = lab.peer(2, &[]);
        let target = format!("{TARGETS}/today");
        let _ = a.exec(
            &lab.pins.pip,
            &[
                "install",
                "--index-url",
                &index(GRANTED, GRANTED_PORT),
                "--target",
                &target,
                &base,
            ],
        );
        let (launch, prefix, _) = lab.recorded_plan(&a.run, &lab.pins.pip);
        assert_eq!(launch, "HYGIENE", "pip's launch changed without the option");
        assert!(
            prefix.is_empty(),
            "pip got a prefix without the option: {prefix:?}"
        );
        let environment: Option<String> = raw(&lab.dir.state())
            .query_row(
                "SELECT environment_id FROM environment WHERE run_id = ?1",
                [a.run.as_str()],
                |row| row.get(0),
            )
            .ok();
        if let Some(environment) = environment {
            lab.container(&a.run);
            lab.release(&mut a, &environment);
        } else {
            a.release();
        }
        evidence(
            "pip-refused-without-the-evidence-option",
            "today:launch-HYGIENE;no-pip-prefix;option-absent",
            "authority-obligation",
        );
        lab.census();
    }

    // ---- what the shipped packs decide --------------------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-hygiene-evidence on a disposable GitHub-hosted runner"]
    fn the_shipped_packs_decide() {
        let mut npm_decided = Vec::new();
        let mut pip_decided = Vec::new();
        let mut groups = Groups::default();
        for pack in ["balanced", "power"] {
            groups.run(pack, || {
                let lab = Lab::new(
                    &format!("m5e5s{pack}"),
                    Setup {
                        policy: Policy::Shipped(pack),
                        ..AS_PROPOSED
                    },
                );
                let (base, _, _) = lab.project("base");
                lab.npm_project(1);
                let mut a = lab.peer(1, &[]);
                // The run's live environment, if an earlier workload made one.
                let environment_of = |run: &RunId| -> Option<String> {
                    raw(&lab.dir.state())
                        .query_row(
                            "SELECT environment_id FROM environment WHERE run_id = ?1 \
                         AND state = 'READY'",
                            [run.as_str()],
                            |row| row.get(0),
                        )
                        .ok()
                };
                let made = "SELECT count(*) FROM environment WHERE run_id = ?1";
                // A denial may name the run's live environment, never another
                // (`denied_in`).
                let decision = |body: &DwkpBody, environment: Option<&str>| -> String {
                    match body {
                        DwkpBody::ToolDeniedV5(_) => {
                            let (reason, rule) = denied_in(body, environment);
                            format!("denied-{reason}-by-{rule}")
                        }
                        DwkpBody::ToolResultV5(_) => "permitted".to_owned(),
                        other => format!("other-{other:?}").chars().take(60).collect(),
                    }
                };
                let npm = a.exec(
                    &lab.pins.npm,
                    &["ci", "--registry", &registry(GRANTED, GRANTED_PORT)],
                );
                let npm_decision = decision(&npm, None);
                let before = environment_of(&a.run);
                let environments = lab.rows(made, &a.run);
                let pip = a.exec(
                    &lab.pins.pip,
                    &[
                        "install",
                        "--index-url",
                        &index(GRANTED, GRANTED_PORT),
                        &base,
                    ],
                );
                let pip_decision = decision(&pip, before.as_deref());
                assert!(
                    pip_decision.starts_with("denied-"),
                    "{pack} did not deny pip install (R3): {pip_decision}"
                );
                assert_eq!(
                    lab.rows(made, &a.run),
                    environments,
                    "{pack}: the denial prepared an environment"
                );
                if let Some(environment) = environment_of(&a.run) {
                    lab.container(&a.run);
                    lab.release(&mut a, &environment);
                } else {
                    a.release();
                }
                lab.census();
                npm_decided.push(format!("{pack}:{npm_decision}"));
                pip_decided.push(format!("{pack}:{pip_decision}"));
            });
        }
        groups.end();
        evidence(
            "npm-shipped-packs-behaviour",
            &format!("decided:{}", npm_decided.join(";")),
            "authority-policy",
        );
        evidence(
            "pip-shipped-packs-behaviour",
            &format!("denied:{}", pip_decided.join(";")),
            "authority-policy",
        );
    }
}
