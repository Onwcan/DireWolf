//! M5e.4's registry evidence (`docs/M5E_ASSURANCE_PLAN.md` §§6, 8; the
//! handoff, `docs/M5E4_IMPLEMENTATION_HANDOFF.md`): **pip as it is today** --
//! under its profile since ADR-0055's acceptance (2026-11-11) -- against
//! M5e.3's fixture registries, and **npm refused** before anything is prepared
//! when an argument its profile refuses is given (ADR-0054 §3) -- run the way
//! a runtime runs a workload: a real DWKP client on
//! the **released** `dwkd-authority serve --sandbox-config`, the **released**
//! `dwkd-broker`, the runner's Docker Engine, and a fresh measured `PROXY_ONLY`
//! environment for every pip case.
//!
//! What is a fixture here, and what is not:
//!
//! * The **registries** are fixtures: M5e.3's PEP 503 index and npm registry
//!   (`tests/sandbox/registry_fixtures.py`), generated from one seed with the
//!   origins' fixed unprivileged ports in every URL, served by M5e.3's two
//!   registry origins (`tests/net_http/origin.py --routes`) on this runner's
//!   loopback under a PKI made for this run, and named through the broker's
//!   evidence-only resolver file. No public network is touched.
//! * The **tools** are not: the registry tools image's pinned CPython, pip,
//!   Node.js and npm, each archive checked against its recorded SHA-256 before
//!   the image was built (`make sandbox-registry-evidence`, on the runner).
//! * **pip's trust** is its profile's (ADR-0055 §5): the task's run anchor in
//!   the image at `/etc/direwolf/pip-ca.pem`, the image built by the hygiene
//!   evidence's own builder, and pip started by its launcher, which pins it.
//!   Until the profile's acceptance (run 42908907916 caught it) this suite ran
//!   `python -m pip` with the anchor as `--cert`, both of which the profile now
//!   refuses. The direct-route cases still run pip inside the interpreter's own
//!   program, with the anchor in the workspace.
//! * The **boundary** is not a fixture: the authority's gates, obligation and
//!   ledger, the operator's file, the environment's measurement, the namespace,
//!   the relay, the CONNECT proxy's grant, the release's teardown.
//!
//! Every line is attributed to what enforced or observed it: the proxy's
//! grant, by what the origins never saw and the dispositions the authority
//! counted at the environment's destruction; the namespace's topology, by the
//! errno pip's own connection got; pip's **own** TLS verification, which is the
//! workload's and not DireWolf's; the authority's obligation, by the decision
//! it sent; and what pip did and did not do, measured in the workspace. Where
//! pip still runs code -- a `.pth` file at a later interpreter's start -- the
//! line says so: a residual the environment contains, never one neutralised. A
//! source distribution's build backend, which pip ran before its profile, it
//! never runs now (`registry-pip-sdist-never-built`).
//!
//! **The proxy's count includes the boundary measuring itself.** Every
//! measurement of a `PROXY_ONLY` environment asks its proxy for a name no
//! grant can hold (`CONTAINER_PROXY_REACHABLE`), and the proxy refuses and
//! counts that `TARGET_NOT_GRANTED` like any other. So a case reads the
//! refusals its workloads caused as the destruction's count less the probe's
//! questions (`beyond_the_probe`), never the raw count: hosted run
//! 42296614431 failed a granted install on the probe's one refusal, and a
//! refused case's `>= 1` would have passed on it alone.
//!
//! Every evidence test is `#[ignore]`d and runs only on a disposable
//! GitHub-hosted runner (`DW_REGISTRY_EVIDENCE=1`): anywhere else it panics NOT
//! EXERCISED. The one test of that accounting runs everywhere, and needs
//! nothing.

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
    use dwkd_authority::state::{
        DEFAULT_LEASE_TTL_MS, ManualClock, Mode, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };

    use super::broker_support::Broker;
    use super::net_support::Origin;
    use super::state_support::{
        START_MS, TempDir, acquire_msg, admit_msg, audit_records, ceiling, decode, id,
        install_fixtures, policy, profile, raw, release_run_msg, session,
    };
    use super::transport_support::{Client, PROMPT, Server, handshake, own_uid};

    const SUITE: &str = "sandbox-registry";
    /// Every line: a real DWKP client on the released `serve`, the released
    /// broker, a real runtime.
    const LEVEL: &str = "dwkp-end-to-end";
    /// The fixtures' names (RFC 6761's `.test`) and the origins' fixed
    /// unprivileged loopback ports, which every fixture URL names: the
    /// granted registry, the ungranted one, and the granted name under an
    /// issuer pip must not trust.
    const GRANTED: &str = "granted-registry.test";
    const UNGRANTED: &str = "ungranted-registry.test";
    /// F-17's standing control (ADR-0061, Proposed): a registry a run may be
    /// granted that no rule of the policy allows -- and a name the resolver
    /// does not hold, so had the proxy asked, it would have failed.
    const REFUSED: &str = "refused-registry.test";
    const GRANTED_PORT: u16 = 18443;
    const UNGRANTED_PORT: u16 = 18444;
    const ROGUE_PORT: u16 = 18445;
    const SEED: &str = "m5e4-registry";
    /// Where the workspace holds the run's trust anchor and the inspection
    /// script, inside the environment, and where each case's target is.
    const ANCHOR: &str = "/workspace/tools/ca.pem";
    const INSPECT: &str = "/workspace/tools/registry_inspect.py";
    const TARGETS: &str = "/workspace/t";
    /// An address no environment has a route to (RFC 5737's TEST-NET-1).
    const UNROUTED: &str = "192.0.2.1";
    /// The operator's rule for the registry tools.
    const RULE: &str = "registry-tools-in-a-sandbox";
    /// The invariant whose measurement asks the proxy its unanswerable
    /// question (`beyond_the_probe`).
    const PROBE_INVARIANT: &str = "CONTAINER_PROXY_REACHABLE";
    /// The wall clock every workload asks for, and the operator's budgets.
    const WALL: u32 = 120;
    const MAX_TUNNELS: usize = 8;
    const MAX_UPLOAD: usize = 256 * 1024;
    const MAX_DOWNLOAD: usize = 4 * 1024 * 1024;
    /// pip with its proxy variables removed by the workload itself: a
    /// direct route, which only the environment's topology refuses.
    const DIRECT: &str = "import os, runpy; [os.environ.pop(k) for k in list(os.environ) \
                          if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')]; \
                          runpy.run_module('pip', run_name='__main__', alter_sys=True)";

    /// One line of evidence: the case, how it ended and what enforced or
    /// observed it, at this suite's one level (M5e.1, OD-E1) -- canonical
    /// JSON, so no outcome can break the line.
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

    /// The task's refusal, again, before anything starts: a disposable
    /// GitHub-hosted runner, and the hosted job's own flag.
    fn hosted() {
        let said = |name: &str| std::env::var(name).unwrap_or_default();
        assert!(
            said("DW_REGISTRY_EVIDENCE") == "1"
                && said("GITHUB_ACTIONS") == "true"
                && said("RUNNER_ENVIRONMENT") == "github-hosted",
            "NOT EXERCISED: the registry evidence runs only on a disposable GitHub-hosted \
             runner (DW_REGISTRY_EVIDENCE=1, the hosted `sandbox-registry` job)"
        );
    }

    fn var(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "NOT EXERCISED: {name} is not set; run `make sandbox-registry-evidence`, which \
                 builds the registry tools image and pins its digests"
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

    /// The repository's root.
    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    // ---- JSON ---------------------------------------------------------------

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

    /// How many of `disposition` an environment's destruction counted.
    fn counted(dispositions: &[String], disposition: &str) -> u64 {
        dispositions
            .iter()
            .find_map(|d| d.strip_prefix(&format!("{disposition}=")))
            .map_or(0, |n| n.parse::<u64>().unwrap())
    }

    /// The `TARGET_NOT_GRANTED` refusals an environment's workloads caused:
    /// its destruction's count less the questions its own probe asked.
    ///
    /// Each measurement of a `PROXY_ONLY` environment sends the proxy one
    /// `CONNECT` for a name no grant can hold (`CONTAINER_PROXY_REACHABLE`;
    /// `dwk-sandbox-probe`'s `network.rs`, `PROXY_PROBE_HOST`) and passes only
    /// on the proxy's refusal, which the proxy counts like any other. That is
    /// the boundary measuring itself, not a workload reaching for a host. A
    /// count below the questions is a measurement the proxy never refused --
    /// an error, never zero.
    fn beyond_the_probe(dispositions: &[String], probe_questions: u64) -> Result<u64, String> {
        let refused = counted(dispositions, "TARGET_NOT_GRANTED");
        refused.checked_sub(probe_questions).ok_or_else(|| {
            format!(
                "{refused} TARGET_NOT_GRANTED counted, fewer than the {probe_questions} \
                 question(s) the environment's own probe asked: {dispositions:?}"
            )
        })
    }

    /// The tunnels an environment's workloads had refused by policy (F-17,
    /// ADR-0061, Proposed). Never the probe's: its one question names a host
    /// no grant can hold, which the ceiling refuses before any policy is
    /// consulted (`TARGET_NOT_GRANTED`), so no probe question is taken away.
    fn policy_refusals(dispositions: &[String]) -> u64 {
        dispositions
            .iter()
            .find_map(|d| d.strip_prefix("POLICY_DENIED="))
            .map_or(0, |n| n.parse::<u64>().unwrap())
    }

    /// The accounting every registry case relies on, needing no runtime: the
    /// hosted failure's own numbers, and the controls either side of them.
    #[test]
    fn a_probes_own_question_is_never_counted_as_a_workloads_refusal() {
        let d = |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
        // Run 42296614431: a granted install's environment, measured once,
        // destroyed with the probe's one refusal. The workload caused none.
        assert_eq!(
            beyond_the_probe(&d(&["CLOSED=2", "TARGET_NOT_GRANTED=1"]), 1),
            Ok(0)
        );
        // The probe's refusal alone is no refusal of the workload's: a
        // refused case can no longer pass on the measurement's question...
        assert_eq!(beyond_the_probe(&d(&["TARGET_NOT_GRANTED=1"]), 1), Ok(0));
        // ...and one tunnel refused beside it is exactly one.
        assert_eq!(beyond_the_probe(&d(&["TARGET_NOT_GRANTED=2"]), 1), Ok(1));
        // A later measurement asks again.
        assert_eq!(beyond_the_probe(&d(&["TARGET_NOT_GRANTED=3"]), 2), Ok(1));
        // A question the proxy never refused is an error, never zero.
        assert!(beyond_the_probe(&d(&["CLOSED=1"]), 1).is_err());
        assert!(beyond_the_probe(&d(&[]), 1).is_err());
        assert!(beyond_the_probe(&d(&["TARGET_NOT_GRANTED=1"]), 2).is_err());
    }

    /// At most this much of a workload's output goes into a failure's report.
    const TAIL: usize = 4096;

    /// `text` for a failure's report: key or certificate material and
    /// credential headers withheld, then its last [`TAIL`] bytes.
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
        if from == 0 {
            kept
        } else {
            format!("[{from} earlier bytes omitted]\n{}", &kept[from..])
        }
    }

    #[test]
    fn a_failures_report_is_bounded_and_withholds_key_material() {
        let pem = "a\n-----BEGIN PRIVATE KEY-----\nMIIsecret\n-----END PRIVATE KEY-----\nb\n";
        let shown = bounded(pem);
        assert!(!shown.contains("MIIsecret"), "{shown}");
        assert!(shown.contains("withheld") && shown.contains("a\n") && shown.contains("b\n"));
        assert!(!bounded("Proxy-Authorization: Basic c2VjcmV0\n").contains("c2VjcmV0"));
        let long = "é".repeat(5 * TAIL);
        let shown = bounded(&long);
        assert!(
            shown.starts_with('[') && shown.len() < TAIL + 64,
            "{}",
            shown.len()
        );
        assert_eq!(bounded("short\n"), "short\n");
    }

    /// The path a logged origin request asked for.
    fn target_of(line: &str) -> Option<&str> {
        let (_, rest) = line.split_once("\"target\": \"")?;
        rest.split('"').next()
    }

    /// A host-side helper of the evidence's (`tests/sandbox/*.py`, standard
    /// library only, isolated mode): its one JSON line.
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

    /// The image and the digests `make sandbox-registry-evidence` pinned.
    struct Pins {
        runtime: String,
        socket: String,
        image: String,
        probe: String,
        relay: String,
        python: String,
        python_sha: String,
        python_version: String,
        pip_version: String,
        npm: String,
        npm_sha: String,
        pip: String,
        pip_sha: String,
        pki: PathBuf,
    }

    impl Pins {
        fn load() -> Self {
            Self {
                runtime: var("DW_SANDBOX_RUNTIME"),
                socket: var("DW_SANDBOX_SOCKET"),
                image: var("DW_REGISTRY_IMAGE"),
                probe: var("DW_SANDBOX_PROBE_SHA256"),
                relay: var("DW_EGRESS_RELAY_SHA256"),
                python: var("DW_REGISTRY_PYTHON"),
                python_sha: var("DW_REGISTRY_PYTHON_SHA256"),
                python_version: var("DW_REGISTRY_PYTHON_VERSION"),
                pip_version: var("DW_REGISTRY_PIP_VERSION"),
                npm: var("DW_REGISTRY_NPM"),
                npm_sha: var("DW_REGISTRY_NPM_SHA256"),
                pip: var("DW_REGISTRY_PIP"),
                pip_sha: var("DW_REGISTRY_PIP_SHA256"),
                pki: PathBuf::from(var("DW_REGISTRY_PKI")),
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

        /// Every container the runtime holds, or those `filters` select.
        fn containers(&self, filters: &[String]) -> BTreeSet<String> {
            let mut args = vec!["container", "ls", "--all", "--no-trunc", "--quiet"];
            for filter in filters {
                args.push("--filter");
                args.push(filter);
            }
            self.ok(&args).lines().map(str::to_owned).collect()
        }

        /// The containers of `environment` with the role `role`.
        fn role(&self, environment: &str, role: &str) -> BTreeSet<String> {
            self.containers(&[
                format!("label=io.direwolf.environment={environment}"),
                format!("label=io.direwolf.role={role}"),
            ])
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
            assert!(!store.is_empty(), "{container} carries no store label");
            self.stores.lock().unwrap().insert(store);
        }

        fn stores(&self) -> BTreeSet<String> {
            self.stores.lock().unwrap().clone()
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

    /// A `Heartbeat` for `session` at `epoch`, with an id of its own.
    fn heartbeat(session: &SessionId, epoch: Epoch) -> DwkpMessage {
        decode(&format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-11-05T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
            id = id("msg", 960_000 + next()),
            session = session.as_str(),
            epoch = epoch.get(),
        ))
    }

    /// A runtime: one DWKP connection, its session's lease, and one run --
    /// the agent evidence's discipline: it renews its lease by `Heartbeat`
    /// before every epoch-carrying request, sends nothing while a request is
    /// outstanding, and requires every answer to name the request it answers.
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
            assert!(
                self.outstanding.is_none(),
                "a request is already outstanding: {:?}",
                self.outstanding
            );
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
                    "the lease was not renewed after {unrenewed:?} unrenewed (the server's TTL \
                     is {:?}): {other:?}",
                    Duration::from_millis(DEFAULT_LEASE_TTL_MS)
                ),
            }
        }

        /// End the run (`ReleaseRun`): `Ack`, its environment destroyed.
        fn release(&mut self) {
            self.renew();
            let message = release_run_msg(&self.session, &self.run, self.epoch);
            self.send(&message);
            let released = self.answer(PROMPT);
            assert!(matches!(released, DwkpBody::Ack(_)), "{released:?}");
        }

        fn exec(&mut self, executable: &str, args: &[&str]) -> DwkpBody {
            self.renew();
            let key = format!("x-{}", next());
            let message = decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-11-05T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"process_exec":{call}}}}}"#,
                id = id("msg", 970_000 + next()),
                session = self.session.as_str(),
                run = self.run.as_str(),
                epoch = self.epoch.get(),
                call = call(executable, args),
            ));
            self.send(&message);
            self.answer(Duration::from_secs(u64::from(WALL) + 240))
        }
    }

    fn call(executable: &str, args: &[&str]) -> String {
        let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
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

    /// What one workload did, as the authority answered it.
    #[derive(Debug)]
    struct Ran {
        environment: String,
        image: String,
        sha256: String,
        exit: Option<u8>,
        stdout: String,
        stderr: String,
        /// The workload's arguments, as the request named them.
        invocation: String,
    }

    impl Ran {
        fn of(body: &DwkpBody) -> Self {
            let out = sandboxed(body);
            assert_eq!(out.assurance, ExecutionAssurance::ContainerIsolation);
            assert_eq!(out.residue, ResidueVerdict::Pass, "{out:?}");
            assert!(!out.environment_destroyed, "{out:?}");
            assert!(
                !out.stdout.truncated && !out.stderr.truncated,
                "the evidence reads all of pip's output: {out:?}"
            );
            assert!(
                matches!(out.ending, SandboxEnding::Exited),
                "an ending other than an exit: {out:?}"
            );
            Self {
                environment: out.environment_id.as_str().to_owned(),
                image: out.executable.image.as_str().to_owned(),
                sha256: out.executable.sha256.as_str().to_owned(),
                exit: out.exit_code.map(|c| c.get()),
                stdout: String::from_utf8_lossy(&out.stdout.content.to_bytes()).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr.content.to_bytes()).into_owned(),
                invocation: String::new(),
            }
        }

        fn said(&self, needle: &str) -> bool {
            self.stdout.contains(needle) || self.stderr.contains(needle)
        }

        fn failed(&self) -> bool {
            !matches!(self.exit, Some(0))
        }
    }

    // ---- the lab ------------------------------------------------------------

    /// A pip project of the fixtures: its name, version and file.
    struct Project {
        name: String,
        version: String,
        file: String,
    }

    /// The released daemons, the registry origins, the operator's files, a
    /// workspace with the run's anchor and the inspection script, and the
    /// store, set up as an operator would before the server starts.
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
        broker: Option<Broker>,
        server: Option<Server>,
        socket: PathBuf,
        workspace: PathBuf,
        /// Every container the runtime held before the lab made any.
        before: BTreeSet<String>,
    }

    /// The operator's policy -- the evidence's, never shipped: the image's
    /// Python and npm, by path and digest, in a sandbox, under the shipped
    /// packs' own obligation (`allow-known-tools`) but without their
    /// `argv_safe`, which keeps `pip install` out of the shipped packs' reach
    /// (`docs/M5E_ASSURANCE_PLAN.md` §3, R14). Reads in the workspace; HTTPS
    /// from a sandbox to exactly the two evidence registries (F-17, ADR-0061,
    /// Proposed: every tunnel is decided by policy), so each case is still
    /// refused by the mechanism it always was; nothing on the host;
    /// everything else denied -- the standing control among it.
    fn policy_text(pins: &Pins) -> String {
        format!(
            r#"schema_version = 1

[meta]
name = "m5e4"

[[rule]]
id = "{RULE}"
effect = "ALLOW"
when.verb = "process.exec"
when.environment = "sandbox"
when.executable_in = ["{python}@{python_sha}", "{npm}@{npm_sha}", "{pip}@{pip_sha}"]
obligations = ["workspace_exec_hygiene", "max_output_bytes=262144"]

[[rule]]
id = "read-the-workspace"
effect = "ALLOW"
when.verb = "fs.read"
when.path_under = "${{WORKSPACE}}"
when.max_bytes = 65536

[[rule]]
id = "https-to-the-evidence-registries"
effect = "ALLOW"
when.verb = "network.https"
when.environment = "sandbox"
when.host_matches = ["{GRANTED}", "{UNGRANTED}"]

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
            pip = pins.pip,
            pip_sha = pins.pip_sha,
        )
    }

    impl Lab {
        fn new(tag: &str) -> Self {
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
            // The task's PKI: its anchor is the image's pip trust file.
            let pki = pins.pki.clone();

            // The fixtures, generated for this run's fixed ports; their
            // markers name the environment's workspace.
            let fixtures = dir.path().join("fixtures");
            let granted_port = GRANTED_PORT.to_string();
            let ungranted_port = UNGRANTED_PORT.to_string();
            host_json(
                "tests/sandbox/registry_fixtures.py",
                &[
                    SEED,
                    fixtures.to_str().unwrap(),
                    "--granted-port",
                    &granted_port,
                    "--ungranted-port",
                    &ungranted_port,
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

            // The broker's evidence-only names: both registries on loopback,
            // which the address guard otherwise refuses.
            let egress = dir.path().join("egress.fixture");
            std::fs::write(
                &egress,
                format!(
                    "# The M5e.4 registry evidence's names.\n\
                     resolve {GRANTED} 127.0.0.1\n\
                     resolve {UNGRANTED} 127.0.0.1\n\
                     allow 127.0.0.1\n"
                ),
            )
            .unwrap();
            mode(&egress, 0o644);

            // The workspace: the run's anchor, the inspection script, and the
            // fixtures' npm project.
            let workspace = dir.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();
            mode(&workspace, 0o777);
            let tools = workspace.join("tools");
            std::fs::create_dir(&tools).unwrap();
            mode(&tools, 0o755);
            for (name, source) in [
                ("ca.pem", pki.join("ca.pem")),
                (
                    "registry_inspect.py",
                    repo().join("tests/sandbox/registry_inspect.py"),
                ),
            ] {
                std::fs::copy(source, tools.join(name)).unwrap();
                mode(&tools.join(name), 0o644);
            }
            let npm = workspace.join("npm");
            std::fs::create_dir(&npm).unwrap();
            mode(&npm, 0o755);
            for name in ["package.json", "package-lock.json"] {
                std::fs::copy(fixtures.join("workspace/npm").join(name), npm.join(name)).unwrap();
                mode(&npm.join(name), 0o644);
            }

            // The store, as the operator's own tooling prepares it.
            let state = dir.state();
            let text = policy_text(&pins);
            {
                let config = StartupConfig::new(policy("m5e4", &text), Mode::Balanced, {
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
                    .install_workspace_root(&ws, workspace.to_str().unwrap())
                    .unwrap();
                // F-18: the runtime -- this process's uid, the one `serve`
                // allows -- is the lab's principal and owns its sessions.
                crate::state_support::grant_lab(
                    &mut authority,
                    &ws,
                    &["researcher", "coder", "agent"],
                    &[own_uid()],
                );
                for n in 1..=32 {
                    crate::state_support::bind_owned(&mut authority, own_uid(), &session(n), &ws);
                }
            }
            let policy_file = dir.path().join("m5e4.toml");
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
                     [budget]\nworkloads = 60\nseconds = 7200\n\
                     [executables]\n\"{python}\" = \"{python_sha}\"\n\"{npm}\" = \"{npm_sha}\"\n\
                     \"{pip}\" = \"{pip_sha}\"\n\
                     [workspace]\nunverified_evidence = true\n",
                    runtime = pins.runtime,
                    socket = pins.socket,
                    image = pins.image,
                    probe = pins.probe,
                    relay = pins.relay,
                    python = pins.python,
                    python_sha = pins.python_sha,
                    npm = pins.npm,
                    npm_sha = pins.npm_sha,
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
            let mut args: Vec<String> = [
                "serve",
                "--state-dir",
                state.to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--policy-file",
                policy_file.to_str().unwrap(),
                "--policy-profile",
                "m5e4",
                "--mode",
                "balanced",
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
            let mut ceiling = ceiling();
            ceiling.push("process.exec:*".to_owned());
            for capability in ceiling {
                args.push("--ceiling".to_owned());
                args.push(capability);
            }
            let server = Server::start(&args);
            assert!(
                server
                    .stderr()
                    .contains("execution environment attached from"),
                "{}",
                server.stderr()
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
                broker: Some(broker),
                server: Some(server),
                socket,
                workspace,
                before,
            }
        }

        fn project(&self, role: &str) -> Project {
            let project = member(member(&self.plan, "projects"), role);
            Project {
                name: text(project, "name"),
                version: text(project, "version"),
                file: text(project, "file"),
            }
        }

        /// A marker's path on the host: the environment's `/workspace/<name>`.
        fn marker(&self, what: &str) -> PathBuf {
            let name = text(member(&self.plan, "markers"), what);
            assert!(!name.is_empty(), "no marker {what}");
            self.workspace.join(name)
        }

        fn index(host: &str, port: u16) -> String {
            format!("https://{host}:{port}/simple/")
        }

        /// A run granted the granted registry, and `extra`.
        fn peer(&self, n: u64, extra: &[String]) -> Peer {
            let mut grants = vec![
                "process.exec:*".to_owned(),
                "fs.read:/workspace".to_owned(),
                format!("network.https:{GRANTED}:{GRANTED_PORT}"),
            ];
            grants.extend_from_slice(extra);
            let refs: Vec<&str> = grants.iter().map(String::as_str).collect();
            Peer::admit(Client::connect(&self.socket), n, &refs)
        }

        /// The run's live environment's container, once a launch prepared it.
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

        /// The broker's last events, for a failure's report: the hosted run
        /// is the only place this suite runs, and the wire's one refusal
        /// reason does not say which of its causes it was.
        fn last_events(&self) -> String {
            let events = self.broker.as_ref().map_or_else(Vec::new, Broker::events);
            let from = events.len().saturating_sub(24);
            events[from..].join("\n")
        }

        /// A workload of the image's Python.
        fn python(&self, peer: &mut Peer, args: &[&str]) -> Ran {
            let body = peer.exec(&self.pins.python, args);
            assert!(
                matches!(body, DwkpBody::ToolResultV5(_)),
                "the workload did not run: {body:?}\nthe broker's last events:\n{}",
                self.last_events()
            );
            let mut ran = Ran::of(&body);
            assert_eq!(ran.image, self.pins.image);
            assert_eq!(ran.sha256, self.pins.python_sha);
            ran.invocation = args.join(" ");
            ran
        }

        /// How many questions `environment`'s own probe asked its proxy: one
        /// at its preparation -- which it passed, or it would never have
        /// been ready -- and one at every later measurement the authority
        /// recorded. A workload's launch is judged from the host and asks
        /// nothing (`judged_for_work`).
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
            assert_eq!(
                ready.len(),
                1,
                "{environment} was not made ready once: {ready:?}"
            );
            for list in ["failed", "unobservable"] {
                assert!(
                    !texts(&ready[0], list).iter().any(|i| i == PROBE_INVARIANT),
                    "{environment} was ready with {PROBE_INVARIANT} {list}: {ready:?}"
                );
            }
            1 + u64::try_from(of("environment.measured").len()).unwrap()
        }

        /// The `TARGET_NOT_GRANTED` refusals `environment`'s workloads caused,
        /// from its destruction's record (`beyond_the_probe`).
        fn refused_by_proxy(&self, destroyed: &json::Object, environment: &str) -> u64 {
            let dispositions = texts(destroyed, "egress_dispositions");
            beyond_the_probe(&dispositions, self.probe_questions(environment)).unwrap_or_else(
                |why| {
                    panic!(
                        "{why}\n{}",
                        self.why("the proxy's count", None, Some(destroyed))
                    )
                },
            )
        }

        /// A failure's report, bounded: what ran and how it ended, what the
        /// proxy counted at the destruction, what each origin was asked, and
        /// the broker's last events. Output only as its withheld, bounded
        /// tail (`bounded`); the suite holds no credential, and the run's
        /// anchor is only ever named by its path.
        fn why(&self, what: &str, ran: Option<&Ran>, destroyed: Option<&json::Object>) -> String {
            let mut report = format!("{what}\n");
            if let Some(ran) = ran {
                report.push_str(&format!(
                    "workload: {} {}\nexit: {:?}; environment {}\n\
                     stdout, last {TAIL} bytes:\n{}stderr, last {TAIL} bytes:\n{}",
                    self.pins.python,
                    ran.invocation,
                    ran.exit,
                    ran.environment,
                    bounded(&ran.stdout),
                    bounded(&ran.stderr),
                ));
            }
            if let Some(destroyed) = destroyed {
                report.push_str(&format!(
                    "counted at the destruction: {:?}\n",
                    texts(destroyed, "egress_dispositions")
                ));
            }
            for (name, origin) in [
                ("granted", &self.granted),
                ("ungranted", &self.ungranted),
                ("rogue", &self.rogue),
            ] {
                let requests = origin.requests();
                let last: Vec<&str> = requests
                    .iter()
                    .rev()
                    .take(6)
                    .filter_map(|r| target_of(r))
                    .collect();
                report.push_str(&format!(
                    "the {name} origin: {} request(s), the last {last:?}\n",
                    requests.len()
                ));
            }
            report.push_str(&format!(
                "the broker's last events:\n{}\n",
                self.last_events()
            ));
            report
        }

        /// pip, as it is today -- started by its launcher under its profile
        /// (ADR-0055), which adds its prefix and pins its trust -- installing
        /// `args` into a target of its own: no cache, no compiled files, no
        /// retry, every connection attempt in its output. `direct` instead
        /// runs pip inside the interpreter's own program, which removes its
        /// proxy variables first and is given the run's anchor itself.
        fn pip(&self, peer: &mut Peer, target: &str, direct: bool, args: &[&str]) -> Ran {
            let target = format!("{TARGETS}/{target}");
            let mut words: Vec<&str> = if direct {
                vec!["-I", "-c", DIRECT]
            } else {
                Vec::new()
            };
            words.extend_from_slice(&[
                "install",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "--no-input",
                "--no-compile",
                "--retries",
                "0",
                "--timeout",
                "30",
                "-vv",
            ]);
            if direct {
                words.extend_from_slice(&["--cert", ANCHOR]);
            }
            words.extend_from_slice(&["--target", &target]);
            words.extend_from_slice(args);
            if direct {
                self.python(peer, &words)
            } else {
                self.profiled_pip(peer, &words)
            }
        }

        /// pip by its own identity, under its profile: the launcher's pip,
        /// pinned by digest in the manifest and the policy.
        fn profiled_pip(&self, peer: &mut Peer, args: &[&str]) -> Ran {
            let body = peer.exec(&self.pins.pip, args);
            assert!(
                matches!(body, DwkpBody::ToolResultV5(_)),
                "pip did not run: {body:?}\nthe broker's last events:\n{}",
                self.last_events()
            );
            let mut ran = Ran::of(&body);
            assert_eq!(ran.image, self.pins.image);
            assert_eq!(ran.sha256, self.pins.pip_sha);
            ran.invocation = args.join(" ");
            ran
        }

        /// What a target holds, read inside the environment (pip's files are
        /// uid 10001's): the inspection's line, as text.
        fn tree(&self, peer: &mut Peer, target: &str) -> String {
            let ran = self.python(
                peer,
                &["-I", INSPECT, "tree", &format!("{TARGETS}/{target}")],
            );
            assert_eq!(ran.exit, Some(0), "{ran:?}");
            ran.stdout
        }

        /// The target holds exactly `roles`' wheels as pip installs them,
        /// byte for byte (`registry_inspect.py check`): how many files.
        fn installed(&self, peer: &mut Peer, target: &str, roles: &[&str]) -> usize {
            let measured = self.tree(peer, target);
            let file = self.dir.path().join(format!("tree-{target}.json"));
            std::fs::write(&file, &measured).unwrap();
            let verdict = host_json(
                "tests/sandbox/registry_inspect.py",
                &[
                    "check",
                    self.fixtures.to_str().unwrap(),
                    &roles.join(","),
                    file.to_str().unwrap(),
                ],
            );
            assert!(flag(&verdict, "ok"), "{target}: {verdict:?}");
            match verdict.get("files") {
                Some(Value::Number(json::Number::Int(n))) => usize::try_from(*n).unwrap(),
                other => panic!("no count: {other:?}"),
            }
        }

        /// The target holds nothing: pip installed nothing at all.
        fn nothing(&self, peer: &mut Peer, target: &str) {
            let measured = object(&self.tree(peer, target));
            assert!(
                matches!(measured.get("files"), Some(Value::Object(files)) if files.is_empty()),
                "{target}: something was installed: {measured:?}"
            );
        }

        /// End the run; its environment and its relay are gone when the
        /// release is answered (M5d.6); the destruction's audit record.
        fn release(&self, peer: &mut Peer, environment: &str) -> json::Object {
            peer.release();
            for role in ["environment", "relay", "setup"] {
                assert!(
                    self.runtime.role(environment, role).is_empty(),
                    "a {role} container of the released environment remains"
                );
            }
            audit_records(&self.dir.state(), "environment.destroyed")
                .into_iter()
                .find(|r| super::state_support::text(r, "environment_id") == Some(environment))
                .expect("the destruction was audited")
        }

        /// The grants the authority recorded for `environment` at its intent.
        fn intent_targets(&self, environment: &str) -> Vec<String> {
            let intent = audit_records(&self.dir.state(), "environment.intent_recorded")
                .into_iter()
                .find(|r| super::state_support::text(r, "environment_id") == Some(environment))
                .expect("the intent was audited");
            texts(&intent, "egress_targets")
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

    // ---- pip, as it is today ------------------------------------------------

    #[test]
    #[ignore = "hosted only: make sandbox-registry-evidence on a disposable GitHub-hosted runner"]
    fn pip_as_it_is_today_reaches_only_the_granted_fixture_registry() {
        let lab = Lab::new("m5e4p");
        let granted_index = Lab::index(GRANTED, GRANTED_PORT);
        let ungranted_index = Lab::index(UNGRANTED, UNGRANTED_PORT);
        let base = lab.project("base");
        let mut n = 0;
        let mut refused: Vec<String> = Vec::new();

        // The tools are the pinned ones, in the environment.
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.python(&mut a, &["-I", INSPECT, "versions"]);
        assert_eq!(
            ran.exit,
            Some(0),
            "{}",
            lab.why("the workload did not succeed", Some(&ran), None)
        );
        let found = object(&ran.stdout);
        assert_eq!(text(&found, "python"), lab.pins.python_version);
        assert_eq!(text(&found, "pip"), lab.pins.pip_version);
        assert_eq!(text(&found, "executable"), lab.pins.python);
        let container = lab.container(&a.run);
        assert!(lab.runtime.exists(&container));
        lab.release(&mut a, &ran.environment);
        evidence(
            "registry-tools-pinned-in-the-environment",
            &format!(
                "pinned:python-{}+pip-{};sha256-{}",
                lab.pins.python_version, lab.pins.pip_version, lab.pins.python_sha
            ),
            "executable-digest-pin",
        );

        // The granted index: the base wheel, byte for byte.
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "granted",
            false,
            &["--index-url", &granted_index, &base.name],
        );
        assert_eq!(
            ran.exit,
            Some(0),
            "{}",
            lab.why("the workload did not succeed", Some(&ran), None)
        );
        lab.container(&a.run);
        let files = lab.installed(&mut a, "granted", &["base"]);
        assert_eq!(lab.granted.to(&format!("/files/{}", base.file)).len(), 1);
        assert!(
            lab.ungranted.requests().is_empty(),
            "the ungranted origin was reached"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a tunnel of a granted install",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-granted-index-installs",
            &format!(
                "installed:{files}-files-as-the-fixture;{}=={}",
                base.name, base.version
            ),
            "relay-and-connect-proxy-grant",
        );

        // A dependency, resolved and fetched from the same granted index.
        let dependent = lab.project("dependent");
        let base_fetched = lab.granted.to(&format!("/files/{}", base.file)).len();
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "dependency",
            false,
            &["--index-url", &granted_index, &dependent.name],
        );
        assert_eq!(
            ran.exit,
            Some(0),
            "{}",
            lab.why("the workload did not succeed", Some(&ran), None)
        );
        lab.container(&a.run);
        let files = lab.installed(&mut a, "dependency", &["dependent", "base"]);
        assert_eq!(
            lab.granted.to(&format!("/files/{}", base.file)).len(),
            base_fetched + 1,
            "the dependency was not fetched from the granted index"
        );
        assert_eq!(
            lab.granted.to(&format!("/files/{}", dependent.file)).len(),
            1
        );
        assert!(
            lab.ungranted.requests().is_empty(),
            "the ungranted origin was reached"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a tunnel of a granted dependency install",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-dependency-from-granted-index",
            &format!(
                "installed:{files}-files-as-the-fixture;{}=={}+{}=={}",
                dependent.name, dependent.version, base.name, base.version
            ),
            "relay-and-connect-proxy-grant",
        );

        // The ungranted index: the proxy refuses the tunnel, nothing is dialled.
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "ungranted",
            false,
            &["--index-url", &ungranted_index, &base.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("403"),
            "{}",
            lab.why("pip never saw the proxy refusal", Some(&ran), None)
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "ungranted");
        assert!(
            lab.ungranted.requests().is_empty(),
            "the ungranted origin was reached"
        );
        let targets = lab.intent_targets(&ran.environment);
        let destroyed = lab.release(&mut a, &ran.environment);
        let refusals = lab.refused_by_proxy(&destroyed, &ran.environment);
        assert!(
            refusals >= 1,
            "{}",
            lab.why(
                "the proxy refused nothing of the workload",
                Some(&ran),
                Some(&destroyed)
            )
        );
        refused.push(format!("ungranted-index:TARGET_NOT_GRANTED={refusals}"));
        evidence(
            "registry-pip-ungranted-index-refused",
            &format!("refused:nothing-installed;connect-403;exit-{:?}", ran.exit),
            "connect-proxy:grant",
        );
        assert_eq!(
            targets,
            [format!("{GRANTED}:{GRANTED_PORT}")],
            "{targets:?}"
        );
        evidence(
            "registry-intent-names-only-the-granted-registry",
            &format!("granted:{}", targets.join(",")),
            "authority-audit",
        );

        // The control: granted, the same index serves the same wheel -- so
        // the refusal above is the grant's, not the index's.
        n += 1;
        let mut a = lab.peer(n, &[format!("network.https:{UNGRANTED}:{UNGRANTED_PORT}")]);
        let ran = lab.pip(
            &mut a,
            "control",
            false,
            &["--index-url", &ungranted_index, &base.name],
        );
        assert_eq!(
            ran.exit,
            Some(0),
            "{}",
            lab.why("the workload did not succeed", Some(&ran), None)
        );
        lab.container(&a.run);
        let files = lab.installed(&mut a, "control", &["base"]);
        assert_eq!(lab.ungranted.to(&format!("/files/{}", base.file)).len(), 1);
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a tunnel of the granted control",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-ungranted-index-installs-when-granted",
            &format!("installed:{files}-files-as-the-fixture;from-{UNGRANTED}"),
            "relay-and-connect-proxy-grant",
        );
        let ungranted_served = lab.ungranted.requests().len();

        // F-17's standing control (ADR-0061, Proposed): a registry granted to
        // the run that no rule of the policy allows. The proxy refuses it on
        // the workload's authorisation, before resolving its name, and
        // nothing is dialled.
        n += 1;
        let granted_served = lab.granted.requests().len();
        let mut a = lab.peer(n, &[format!("network.https:{REFUSED}:{GRANTED_PORT}")]);
        let ran = lab.pip(
            &mut a,
            "policy-denied",
            false,
            &[
                "--index-url",
                &Lab::index(REFUSED, GRANTED_PORT),
                &base.name,
            ],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("403"),
            "{}",
            lab.why("pip never saw the proxy refusal", Some(&ran), None)
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "policy-denied");
        assert_eq!(lab.granted.requests().len(), granted_served);
        let destroyed = lab.release(&mut a, &ran.environment);
        let denied = policy_refusals(&texts(&destroyed, "egress_dispositions"));
        assert!(
            denied >= 1,
            "{}",
            lab.why(
                "the proxy did not refuse the registry on policy",
                Some(&ran),
                Some(&destroyed)
            )
        );
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the ceiling refused a registry the run was granted",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-granted-index-denied-by-policy",
            &format!("refused:nothing-installed;connect-403;POLICY_DENIED={denied}"),
            "connect-proxy:workload-authorisation",
        );

        // A granted page whose one file is on the ungranted host.
        let offsite = lab.project("offsite");
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "offsite",
            false,
            &["--index-url", &granted_index, &offsite.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("403"),
            "{}",
            lab.why("pip never saw the proxy refusal", Some(&ran), None)
        );
        assert_eq!(
            lab.granted.to(&format!("/simple/{}/", offsite.name)).len(),
            1
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "offsite");
        assert_eq!(
            lab.ungranted.requests().len(),
            ungranted_served,
            "the file's host was reached"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        let refusals = lab.refused_by_proxy(&destroyed, &ran.environment);
        assert!(
            refusals >= 1,
            "{}",
            lab.why(
                "the proxy refused nothing of the workload",
                Some(&ran),
                Some(&destroyed)
            )
        );
        refused.push(format!(
            "file-on-ungranted-host:TARGET_NOT_GRANTED={refusals}"
        ));
        evidence(
            "registry-pip-file-on-ungranted-host-refused",
            &format!(
                "refused:nothing-installed;page-from-granted;file-connect-403;exit-{:?}",
                ran.exit
            ),
            "connect-proxy:grant",
        );

        // A granted page redirected to the ungranted host, which serves it.
        let redirected = lab.project("redirected");
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "redirected",
            false,
            &["--index-url", &granted_index, &redirected.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("403"),
            "{}",
            lab.why("pip never saw the proxy refusal", Some(&ran), None)
        );
        assert_eq!(
            lab.granted
                .to(&format!("/simple/{}/", redirected.name))
                .len(),
            1
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "redirected");
        assert_eq!(
            lab.ungranted.requests().len(),
            ungranted_served,
            "the redirect was followed"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        let refusals = lab.refused_by_proxy(&destroyed, &ran.environment);
        assert!(
            refusals >= 1,
            "{}",
            lab.why(
                "the proxy refused nothing of the workload",
                Some(&ran),
                Some(&destroyed)
            )
        );
        refused.push(format!("redirect:TARGET_NOT_GRANTED={refusals}"));
        evidence(
            "registry-pip-redirect-to-ungranted-host-refused",
            &format!(
                "refused:nothing-installed;302-from-granted;connect-403;exit-{:?}",
                ran.exit
            ),
            "connect-proxy:grant",
        );

        // A direct route: pip without its proxy variables, to an address --
        // the environment has no route but the relay's.
        let served = lab.granted.requests().len();
        n += 1;
        let mut a = lab.peer(n, &[]);
        let unrouted = format!("https://{UNROUTED}:{GRANTED_PORT}/simple/");
        let ran = lab.pip(
            &mut a,
            "direct",
            true,
            &["--index-url", &unrouted, &base.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("Errno 101"),
            "{}",
            lab.why("not ENETUNREACH", Some(&ran), None)
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "direct");
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a tunnel of pip without its proxy",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-direct-route-refused",
            "refused:nothing-installed;ENETUNREACH",
            "topology-no-route",
        );

        // And by name: nothing in the environment resolves one.
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "direct-name",
            true,
            &["--index-url", &granted_index, &base.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        // getaddrinfo's own failure, a negative `EAI_*` code -- which one
        // depends on what the environment's resolver configuration names;
        // none of them is an answer.
        let unresolved = [ran.stdout.as_str(), ran.stderr.as_str()]
            .into_iter()
            .find_map(|out| out.split("[Errno -").nth(1))
            .and_then(|rest| rest.split(']').next())
            .filter(|code| !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()))
            .map(|code| format!("[Errno -{code}]"))
            .unwrap_or_else(|| {
                panic!(
                    "{}",
                    lab.why("the name was not left unresolved", Some(&ran), None)
                )
            });
        lab.container(&a.run);
        lab.nothing(&mut a, "direct-name");
        assert_eq!(
            lab.granted.requests().len(),
            served,
            "a direct attempt reached the origin"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a tunnel of pip without its proxy",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-direct-by-name-unresolved",
            &format!("refused:nothing-installed;getaddrinfo-{unresolved}"),
            "topology-no-resolver",
        );

        // The granted name under an issuer pip must not trust: the proxy
        // carries the granted tunnel; pip's own verification ends it.
        n += 1;
        let mut a = lab.peer(n, &[format!("network.https:{GRANTED}:{ROGUE_PORT}")]);
        let rogue_index = Lab::index(GRANTED, ROGUE_PORT);
        let ran = lab.pip(
            &mut a,
            "rogue",
            false,
            &["--index-url", &rogue_index, &base.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("CERTIFICATE_VERIFY_FAILED") || ran.said("certificate verify failed"),
            "{}",
            lab.why("pip did not refuse the issuer", Some(&ran), None)
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "rogue");
        assert!(
            lab.rogue.requests().is_empty(),
            "a request reached the rogue origin"
        );
        let destroyed = lab.release(&mut a, &ran.environment);
        assert_eq!(
            lab.refused_by_proxy(&destroyed, &ran.environment),
            0,
            "{}",
            lab.why(
                "the proxy refused a granted tunnel",
                Some(&ran),
                Some(&destroyed)
            )
        );
        evidence(
            "registry-pip-untrusted-issuer-refused",
            "refused:nothing-installed;certificate-verify-failed;tunnel-granted",
            "workload-tls-verification",
        );

        // A source distribution: under its profile pip installs wheels only
        // (ADR-0055 §2), so it finds nothing it may install and never runs
        // the build backend. Before the profile it did (this case was
        // `registry-pip-sdist-built-today`, a gap stated, not hidden).
        let sdist = lab.project("sdist");
        let backend = lab.marker("pip-build-backend");
        assert!(!backend.exists(), "the backend's marker predates the case");
        n += 1;
        let mut a = lab.peer(n, &[]);
        let ran = lab.pip(
            &mut a,
            "sdist",
            false,
            &["--index-url", &granted_index, &sdist.name],
        );
        assert!(
            ran.failed(),
            "{}",
            lab.why("pip succeeded where it must fail", Some(&ran), None)
        );
        assert!(
            ran.said("No matching distribution found"),
            "{}",
            lab.why("not pip's binary-only refusal", Some(&ran), None)
        );
        assert!(
            !backend.exists(),
            "{}",
            lab.why("the build backend ran", Some(&ran), None)
        );
        lab.container(&a.run);
        lab.nothing(&mut a, "sdist");
        lab.release(&mut a, &ran.environment);
        evidence(
            "registry-pip-sdist-never-built",
            &format!(
                "not-built:backend-marker-absent;nothing-installed;exit-{:?}",
                ran.exit
            ),
            "hygiene-launcher",
        );

        // A wheel carrying a `.pth`: installed, not run by the install -- and
        // run by a later interpreter start whose site path holds it.
        let pth = lab.marker("pip-pth");
        assert!(!pth.exists(), "the .pth marker predates the case");
        n += 1;
        let mut a = lab.peer(n, &[]);
        let project = lab.project("pth");
        let ran = lab.pip(
            &mut a,
            "pth",
            false,
            &["--index-url", &granted_index, &project.name],
        );
        assert_eq!(
            ran.exit,
            Some(0),
            "{}",
            lab.why("the workload did not succeed", Some(&ran), None)
        );
        lab.container(&a.run);
        let files = lab.installed(&mut a, "pth", &["pth"]);
        assert!(!pth.exists(), "the install ran the .pth");
        evidence(
            "registry-pip-pth-not-run-by-install",
            &format!("not-run:pth-marker-absent;{files}-files-as-the-fixture"),
            "workload-effects-measured",
        );
        let later = lab.python(&mut a, &["-I", INSPECT, "site", &format!("{TARGETS}/pth")]);
        assert_eq!(later.exit, Some(0), "{later:?}");
        assert!(pth.exists(), "a later start did not run the .pth");
        lab.release(&mut a, &later.environment);
        evidence(
            "registry-pip-pth-runs-at-a-later-start",
            "runs-later:pth-marker-present;site-addsitedir",
            "residual-contained-by-the-environment",
        );

        // The egress the proxy refused, counted by disposition when each
        // environment was destroyed -- never one event per attempt.
        assert_eq!(refused.len(), 3, "{refused:?}");
        evidence(
            "registry-egress-counted-at-destruction",
            &format!("counted:{};probe-questions-excluded", refused.join(";")),
            "authority-audit-at-destruction",
        );

        // Every environment the run's store made is gone by its labels, and
        // every container that predates the lab is still there.
        let stores = lab.reaper.stores();
        assert_eq!(stores.len(), 1, "{stores:?}");
        for store in &stores {
            let left = lab
                .runtime
                .containers(&[format!("label=io.direwolf.store={store}")]);
            assert!(left.is_empty(), "the store's containers remain: {left:?}");
        }
        let now = lab.runtime.containers(&[]);
        assert!(
            lab.before.is_subset(&now),
            "a container that predates the lab is gone"
        );
        let destroyed = audit_records(&lab.dir.state(), "environment.destroyed").len();
        assert_eq!(
            u64::try_from(destroyed).unwrap(),
            n,
            "one destruction per run"
        );
        evidence(
            "registry-census-clean",
            &format!(
                "clean:{n}-environments-destroyed-by-label;{}-pre-existing-kept",
                lab.before.len()
            ),
            "exact-label-cleanup",
        );
    }

    // ---- npm, refused when its profile refuses an argument ---------------------
    //
    // Before ADR-0054's acceptance npm was refused outright; since, it is kept
    // under its profile (M5e.5's suite), and these invocations are refused
    // because they name `--prefix`, which the profile refuses (§3): still
    // before any environment, workload, container or request.

    #[test]
    #[ignore = "hosted only: make sandbox-registry-evidence on a disposable GitHub-hosted runner"]
    fn npm_is_refused_before_anything_is_prepared() {
        let lab = Lab::new("m5e4n");
        let registry = format!("https://{GRANTED}:{GRANTED_PORT}/");
        let containers = lab.runtime.containers(&[]);
        let mut a = lab.peer(1, &[]);

        let denied = |body: &DwkpBody| {
            let DwkpBody::ToolDeniedV5(denied) = body else {
                panic!("npm was not denied: {body:?}")
            };
            let action = denied.plan.actions.as_slice()[0].workload.as_ref().unwrap();
            assert_eq!(action.decision.reason.as_str(), "OBLIGATION_UNENFORCEABLE");
            assert_eq!(action.decision.rule_id.as_str(), RULE);
            assert_eq!(action.executable.sha256.as_str(), lab.pins.npm_sha);
            assert!(action.environment_id.is_none(), "{action:?}");
        };
        let body = a.exec(
            &lab.pins.npm,
            &[
                "install",
                "--registry",
                &registry,
                "--prefix",
                "/workspace/npm",
            ],
        );
        denied(&body);
        evidence(
            "registry-npm-install-refused-before-preparation",
            "refused:OBLIGATION_UNENFORCEABLE;no-environment",
            "authority-obligation",
        );
        let body = a.exec(
            &lab.pins.npm,
            &["ci", "--registry", &registry, "--prefix", "/workspace/npm"],
        );
        denied(&body);
        evidence(
            "registry-npm-ci-refused-before-preparation",
            "refused:OBLIGATION_UNENFORCEABLE;no-environment",
            "authority-obligation",
        );

        // Nothing was prepared, run or reached.
        assert_eq!(
            lab.rows("SELECT count(*) FROM environment WHERE run_id = ?1", &a.run),
            0,
            "an environment was recorded"
        );
        assert_eq!(
            lab.rows("SELECT count(*) FROM workload WHERE run_id = ?1", &a.run),
            0,
            "a workload was recorded"
        );
        assert!(audit_records(&lab.dir.state(), "environment.intent_recorded").is_empty());
        assert_eq!(
            lab.runtime.containers(&[]),
            containers,
            "a container was made"
        );
        for origin in [&lab.granted, &lab.ungranted, &lab.rogue] {
            assert!(
                origin.requests().is_empty(),
                "a registry origin was reached"
            );
        }
        let markers: Vec<PathBuf> = member(&lab.plan, "markers")
            .iter()
            .filter(|(what, _)| what.starts_with("npm-"))
            .map(|(what, _)| lab.marker(what))
            .collect();
        assert!(markers.len() >= 4, "{markers:?}");
        for marker in &markers {
            assert!(!marker.exists(), "{} was written", marker.display());
        }
        assert!(!lab.workspace.join("npm/node_modules").exists());
        a.release();
        evidence(
            "registry-npm-nothing-prepared-or-reached",
            &format!(
                "nothing:no-environment;no-workload;no-container;no-request;{}-markers-absent",
                markers.len()
            ),
            "authority-environment-decision",
        );
    }
}
