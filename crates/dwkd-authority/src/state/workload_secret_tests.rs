//! A sandboxed `process.exec`'s credential (M5d.3, ADR-0052 §7; ADR-0046
//! §§15–20) in this crate's unit tests: the real authority, real values in
//! the **kernel keyring** read by the real backend, and the route tests'
//! **fake broker**, which reads the one-shot pipe each secret-bearing start
//! hands it and records what was durable when it arrived. A fake runs and
//! contains nothing: these tests prove what the authority decides, records,
//! reads, hands over, refuses and never repeats. Delivery inside a real
//! environment is `make sandbox-secret-evidence`'s.
//!
//! Every value is generated at run time; assertions compare digests,
//! lengths and booleans, never values.

use std::sync::atomic::Ordering;

use dwk_proto::brokerp::SecretDelivery;
use dwk_proto::dwkp::secretops::{PlannedSpawnInjectionAction, SpawnInjection, ToolPlanV6};

use super::*;
use crate::secret::backend::{keychain_test_support, reads_on_this_thread};
use crate::secret::metadata;

const DEPLOY: &str = "deploy-key";
const ENV_TOKEN: &str = "env-token";
const BOTH: &str = "both-key";
const API: &str = "api-token";
const ELSEWHERE: &str = "true-token";
const SPARE: &str = "spare-key";
const PROXY: &str = "proxy-token";
const NUL: &str = "nul-token";
const GONE: &str = "gone-key";
const VARIABLE: &str = "GH_TOKEN";

/// `secret.use` in a sandbox, keeping only `audit_level`: a dedicated
/// operator test policy, **not** a shipped pack.
const ALLOW: &str = "[[rule]]\nid = \"secret-use-in-a-sandbox\"\neffect = \"ALLOW\"\n\
                     when.verb = \"secret.use\"\nwhen.environment = \"sandbox\"\n\
                     obligations = [\"audit_level=full\"]\n\n";
/// Approvals arrive at M6: until then a rule that asks for one denies.
const APPROVAL: &str = "[[rule]]\nid = \"secret-use-needs-approval\"\n\
                        effect = \"REQUIRE_APPROVAL\"\nreason = \"NO_HUMAN_AVAILABLE\"\n\
                        when.verb = \"secret.use\"\nwhen.environment = \"sandbox\"\n\
                        approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\n\
                        approval.max_uses = 1\n\n";
/// An obligation a secret use cannot keep.
const UNKEEPABLE: &str = "[[rule]]\nid = \"secret-use-no-network\"\neffect = \"ALLOW\"\n\
                          when.verb = \"secret.use\"\nwhen.environment = \"sandbox\"\n\
                          obligations = [\"network_deny\"]\n\n";
/// Allowed on the host only: never a sandbox's.
const HOST_ONLY: &str = "[[rule]]\nid = \"secret-use-on-the-host\"\neffect = \"ALLOW\"\n\
                         when.verb = \"secret.use\"\nwhen.environment = \"host\"\n\n";

/// The route tests' policy with `rule` before its default.
fn secret_policy(rule: &str) -> PolicySet {
    let marker = "[[rule]]\nid = \"default\"";
    assert!(POLICY.contains(marker));
    PolicySet {
        profile: "m5d3".to_owned(),
        sources: vec![PolicySource {
            name: "m5d3.toml".to_owned(),
            text: POLICY
                .replacen("name = \"m5d2\"", "name = \"m5d3\"", 1)
                .replacen(marker, &format!("{rule}{marker}"), 1),
        }],
    }
}

fn salt() -> u32 {
    static SALT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        nanos ^ 0x5d3c_0de5
    })
}

/// A synthetic value: `len` printable bytes, distinct per `seed` and run.
fn value(seed: u8, len: usize) -> Vec<u8> {
    let salt = salt();
    (0..len)
        .map(|i| {
            let x = u32::try_from(i).unwrap().wrapping_mul(2_654_435_761) ^ salt ^ u32::from(seed);
            b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
                [usize::try_from(x % 57).unwrap()]
        })
        .collect()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// Keychain entries a fixture seeded, removed when it drops.
struct Seeded(Vec<String>);

impl Drop for Seeded {
    fn drop(&mut self) {
        for entry in &self.0 {
            keychain_test_support::remove(entry);
        }
    }
}

/// The values a fixture's handles hold.
struct Values {
    deploy: Vec<u8>,
    env: Vec<u8>,
    both: Vec<u8>,
}

/// Every handle a fixture configures:
///
/// | handle | modes | consumers | |
/// |---|---|---|---|
/// | `deploy-key` | C | the fixture | |
/// | `env-token` | B, `GH_TOKEN` | the fixture | |
/// | `both-key` | B and C | the fixture | C is chosen |
/// | `api-token` | A | -- | never a spawn's |
/// | `true-token` | C | `/usr/bin/true` | the image's, by its own digest |
/// | `spare-key` | C | the fixture | never granted |
/// | `proxy-token` | B, `HTTPS_PROXY` | the fixture | a variable the environment sets |
/// | `nul-token` | B, `NUL_TOKEN` | the fixture | its value holds a NUL |
/// | `gone-key` | C | the fixture | its entry was never seeded |
fn secrets_toml(prefix: &str) -> String {
    format!(
        r#"schema_version = 1

[secrets.deploy-key]
type = "generic"
storage = "keychain"
keychain = "{prefix}-deploy"
injection = ["fd_at_spawn"]
consumers = ["{FIXTURE}"]

[secrets.env-token]
type = "generic"
storage = "keychain"
keychain = "{prefix}-env"
injection = ["env_at_spawn"]
consumers = ["{FIXTURE}"]
env = "{VARIABLE}"

[secrets.both-key]
type = "generic"
storage = "keychain"
keychain = "{prefix}-both"
injection = ["env_at_spawn", "fd_at_spawn"]
consumers = ["{FIXTURE}"]
env = "BOTH_TOKEN"

[secrets.api-token]
type = "bearer"
storage = "keychain"
keychain = "{prefix}-api"
origins = ["api.example.com:443"]
header = "Authorization"
prefix = "Bearer "
injection = ["egress"]

[secrets.true-token]
type = "generic"
storage = "keychain"
keychain = "{prefix}-deploy"
injection = ["fd_at_spawn"]
consumers = ["{TRUE}"]

[secrets.spare-key]
type = "generic"
storage = "keychain"
keychain = "{prefix}-deploy"
injection = ["fd_at_spawn"]
consumers = ["{FIXTURE}"]

[secrets.proxy-token]
type = "generic"
storage = "keychain"
keychain = "{prefix}-env"
injection = ["env_at_spawn"]
consumers = ["{FIXTURE}"]
env = "HTTPS_PROXY"

[secrets.nul-token]
type = "generic"
storage = "keychain"
keychain = "{prefix}-nul"
injection = ["env_at_spawn"]
consumers = ["{FIXTURE}"]
env = "NUL_TOKEN"

[secrets.gone-key]
type = "generic"
storage = "keychain"
keychain = "{prefix}-gone"
injection = ["fd_at_spawn"]
consumers = ["{FIXTURE}"]
"#
    )
}

/// What every secret test's run is granted: each handle but `spare-key`.
const GRANTS: &[&str] = &[
    "process.exec:*",
    "fs.stat:*",
    "secret.use:deploy-key",
    "secret.use:env-token",
    "secret.use:both-key",
    "secret.use:api-token",
    "secret.use:true-token",
    "secret.use:proxy-token",
    "secret.use:nul-token",
    "secret.use:gone-key",
];

/// A real authority with the sandbox attached and values in the kernel
/// keyring, or `None` when this host has none (NOT EXERCISED, said so; the
/// evidence task requires every case's line, so it fails there).
fn secret_fixture(
    tag: &str,
    rule: &str,
    hook: Option<CrashHook>,
) -> Option<(Fixture, Seeded, Values)> {
    let prefix = format!("direwolf-test/m5d3-{tag}-{}", salt());
    let values = Values {
        deploy: value(1, 40),
        env: value(2, 36),
        both: value(3, 32),
    };
    let mut nul = value(4, 24);
    nul[7] = 0;
    let mut seeded = Seeded(Vec::new());
    for (suffix, bytes) in [
        ("deploy", values.deploy.clone()),
        ("env", values.env.clone()),
        ("both", values.both.clone()),
        ("api", value(5, 40)),
        ("nul", nul),
    ] {
        let entry = format!("{prefix}-{suffix}");
        if keychain_test_support::seed(&entry, &bytes).is_none() {
            println!("NOT EXERCISED: no usable kernel keyring on this host");
            return None;
        }
        seeded.0.push(entry);
    }
    let scratch = Scratch::new("workload-secret");
    let root = scratch.path().join("ws");
    std::fs::create_dir_all(&root).unwrap();
    let mut config = StartupConfig::new(
        secret_policy(rule),
        Mode::Balanced,
        vec![
            "process.exec:*".to_owned(),
            "fs.read:*".to_owned(),
            "fs.stat:*".to_owned(),
            "secret.use:*".to_owned(),
        ],
    );
    config.secrets = metadata::parse(&secrets_toml(&prefix)).unwrap();
    let mut fx = Fixture {
        scratch,
        authority: None,
        fake: Arc::new(Fake::default()),
        clock: Arc::new(ManualClock::new(START_MS)),
        caller: None,
        session: SessionId::from_uuid(uuid(1)).unwrap(),
        epoch: Epoch::new(1).unwrap(),
        config,
    };
    fx.start(hook);
    *fx.fake.store.lock().unwrap() = Some(fx.state().join("kernel.db"));
    let workspace = WorkspaceId::new("ws").unwrap();
    let session = fx.session.clone();
    {
        let mut operator = fx.authority().operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: vec![
                    "process.exec:*".to_owned(),
                    "fs.read:*".to_owned(),
                    "fs.stat:*".to_owned(),
                    "secret.use:*".to_owned(),
                ],
                baseline_skills: Vec::new(),
                privacy_default: PrivacyClass::Any,
            })
            .unwrap();
        operator
            .install_workspace(&workspace, WorkspaceSensitivity::Private)
            .unwrap();
        operator
            .install_workspace_root(&workspace, root.to_str().unwrap())
            .unwrap();
        operator
            .bind_session_workspace(&session, &workspace)
            .unwrap();
    }
    fx.lease();
    fx.attach(IMAGE);
    Some((fx, seeded, values))
}

fn launch_call(executable: &str, args: &[&str], handle: Option<&str>) -> String {
    let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    let credential = handle.map_or_else(String::new, |h| format!(r#","credential_handle":"{h}""#));
    format!(
        r#"{{"executable":"{executable}","args":[{}]{credential}}}"#,
        args.join(",")
    )
}

impl Fixture {
    /// A version-6 `process.exec`, run to its answer.
    fn launch6(&mut self, run: &RunId, key: &str, call: &str) -> DwkpBody {
        let message = self.message(
            run,
            6,
            "direwolf.tool.invoke",
            Some(key),
            &format!(r#"{{"process_exec":{call}}}"#),
        );
        let caller = self.caller.unwrap();
        match self
            .authority()
            .dispatch_parkable(&caller, &message)
            .unwrap()
        {
            Dispatched::Answer(body) => body,
            Dispatched::Parked(parked) => self.settle(parked),
        }
    }

    fn preview6(&mut self, run: &RunId, call: &str) -> DwkpBody {
        let message = self.message(
            run,
            6,
            "direwolf.tool.preview",
            None,
            &format!(r#"{{"process_exec":{call}}}"#),
        );
        let caller = self.caller.unwrap();
        self.authority().dispatch(&caller, &message).unwrap()
    }

    /// The reason of the last `secret.denied` record.
    fn last_denial(&self) -> Option<String> {
        crate::state::read_audit_log(&self.state().join("audit.log"))
            .unwrap()
            .iter()
            .rev()
            .find(|r| r.event() == "secret.denied")
            .and_then(|r| r.text("reason").map(str::to_owned))
    }

    /// Whether any file of the state directory holds `needle`, raw or
    /// hex-encoded.
    fn durable_holds(&self, needle: &[u8]) -> bool {
        let hex: Vec<u8> = needle
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        std::fs::read_dir(self.state()).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            std::fs::read(&path).is_ok_and(|bytes| {
                [needle, &hex[..]]
                    .iter()
                    .any(|n| bytes.windows(n.len()).any(|w| w == *n))
            })
        })
    }

    fn secrets_handed(&self) -> Vec<SecretAsked> {
        self.fake.secrets.lock().unwrap().clone()
    }
}

fn plan6(body: &DwkpBody) -> &ToolPlanV6 {
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

fn output6(body: &DwkpBody) -> &SandboxedExecResult {
    match body {
        DwkpBody::ToolResultV6(r) => r.output.process_exec_sandboxed.as_ref().unwrap(),
        other => panic!("not a sandboxed result: {other:?}"),
    }
}

fn refused6(body: &DwkpBody) -> R {
    match body {
        DwkpBody::ToolRefusedV6(r) => r.reason,
        other => panic!("not refused: {other:?}"),
    }
}

fn failed6(body: &DwkpBody) -> (F, Option<bool>) {
    match body {
        DwkpBody::ToolFailedV6(f) => (f.reason, f.environment_destroyed),
        other => panic!("not failed: {other:?}"),
    }
}

/// One line of `make sandbox-secret-evidence`'s in-process half, printed
/// only after the assertions before it held. A fake broker: not delivery.
fn secret_evidence(case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"authority-workload-secret\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

#[test]
fn a_credential_is_read_only_after_both_intents_and_handed_over_once_as_a_pipe() {
    let Some((mut fx, _seeded, values)) = secret_fixture("deliver", ALLOW, None) else {
        return;
    };
    let run = fx.run("s1", GRANTS);
    for (handle, expected, delivery, variable) in [
        (DEPLOY, &values.deploy, SecretDelivery::FdAtSpawn, None),
        (
            ENV_TOKEN,
            &values.env,
            SecretDelivery::EnvAtSpawn,
            Some(VARIABLE),
        ),
        // Both allowed: C, a descriptor, before B, a variable.
        (BOTH, &values.both, SecretDelivery::FdAtSpawn, None),
    ] {
        let before = reads_on_this_thread();
        let key = format!("s1-{handle}");
        let body = fx.launch6(&run, &key, &launch_call(FIXTURE, &["status"], Some(handle)));
        assert_eq!(reads_on_this_thread() - before, 1, "{handle}: read once");
        let plan = plan6(&body);
        assert_eq!(plan.effect, DecisionEffect::Allow);
        assert_eq!(plan.actions.as_slice().len(), 2);
        let spawn = injection(plan).unwrap();
        assert_eq!(spawn.handle.as_str(), handle);
        assert_eq!(
            spawn.mode,
            match delivery {
                SecretDelivery::FdAtSpawn => SpawnInjection::FdAtSpawn,
                SecretDelivery::EnvAtSpawn => SpawnInjection::EnvAtSpawn,
            }
        );
        assert_eq!(spawn.decision.effect, DecisionEffect::Allow);
        assert_eq!(output6(&body).ending, SandboxEnding::Exited);
        // The broker received exactly the value, once, after both intents
        // were durable -- and the launcher is told the mode and variable,
        // never the value.
        let handed = fx.secrets_handed();
        let last = handed.last().unwrap();
        assert!(last.digest == digest(expected), "{handle}: another value");
        assert_eq!(last.len, expected.len());
        assert_eq!((last.intents, last.launching), (1, 1), "{handle}");
        assert_eq!(last.secret.delivery, delivery);
        assert_eq!(
            last.secret
                .env_name
                .as_ref()
                .map(dwk_proto::brokerp::SecretEnvName::as_str),
            variable
        );
        assert_eq!(last.secret.handle.as_str(), handle);
    }
    secret_evidence("read-once-after-both-intents", "1 read, 2 intents open");
    secret_evidence("kernel-chooses-c-before-b", "FD_AT_SPAWN");
    // Each delivery recorded, linked and counted once; the workload's own
    // intent names the injection; nothing durable holds a value.
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM secret_injection WHERE state = 'INJECTED' \
                  AND mode IN ('fd_at_spawn', 'env_at_spawn')"
        ),
        3
    );
    assert_eq!(fx.count("SELECT count(*) FROM workload_secret"), 3);
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM workload_secret ws JOIN workload w \
                  ON w.invocation_id = ws.workload_invocation_id WHERE w.state = 'COMPLETED'"
        ),
        3
    );
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'deploy-key'"),
        1
    );
    let consumer = fx.one("SELECT consumer FROM secret_injection WHERE handle = 'deploy-key'");
    assert_eq!(consumer, format!("{FIXTURE}@{FIXTURE_SHA}"));
    let records = crate::state::read_audit_log(&fx.state().join("audit.log")).unwrap();
    let intent = records
        .iter()
        .rev()
        .find(|r| r.event() == "workload.intent_recorded")
        .unwrap();
    assert_eq!(intent.text("credential_handle"), Some(BOTH));
    assert_eq!(intent.text("injection_mode"), Some("fd_at_spawn"));
    assert_eq!(intent.int("protocol_version"), Some(6));
    let used = records
        .iter()
        .filter(|r| r.event() == "secret.intent_recorded")
        .filter(|r| r.text("environment") == Some("sandbox"))
        .count();
    assert_eq!(used, 3);
    secret_evidence("intent-linked-recorded-counted", "3 injected, 3 links");
    for v in [&values.deploy, &values.env, &values.both] {
        assert!(!fx.durable_holds(v), "a value is durable");
    }
    secret_evidence("no-plaintext-in-kernel-db-or-audit", "absent");
    // A key names one invocation: never a second handoff or launch.
    let handed = fx.secrets_handed().len();
    let before = reads_on_this_thread();
    let again = fx.launch6(
        &run,
        "s1-deploy-key",
        &launch_call(FIXTURE, &["status"], Some(DEPLOY)),
    );
    assert_eq!(refused6(&again), R::IdempotencyKeyReused);
    assert_eq!(reads_on_this_thread() - before, 0);
    assert_eq!(fx.secrets_handed().len(), handed);
    secret_evidence("replay-never-hands-over-again", "IDEMPOTENCY_KEY_REUSED");
    // The ordinary launch is unchanged at version 6 and at version 5: one
    // action, an ordinary start, no pipe.
    let plain = fx.launch6(&run, "s1-plain", &call(FIXTURE, &["status"]));
    assert_eq!(plan6(&plain).actions.as_slice().len(), 1);
    assert!(injection(plan6(&plain)).is_none());
    let v5 = fx.ran(&run, "s1-v5", &call(FIXTURE, &["status"]));
    assert_eq!(result(&v5).0.actions.as_slice().len(), 1);
    assert_eq!(fx.secrets_handed().len(), handed);
    assert!(fx.fake.operations().contains(&"workload.start"));
    secret_evidence("ordinary-launch-unchanged", "one action, no pipe");
    // A preview decides both and reads, records and hands over nothing.
    let rows = fx.count("SELECT count(*) FROM secret_injection");
    let before = reads_on_this_thread();
    let preview = fx.preview6(&run, &launch_call(FIXTURE, &["status"], Some(DEPLOY)));
    assert_eq!(
        injection(plan6(&preview)).unwrap().decision.effect,
        DecisionEffect::Allow
    );
    assert_eq!(reads_on_this_thread() - before, 0);
    assert_eq!(fx.count("SELECT count(*) FROM secret_injection"), rows);
    secret_evidence("preview-reads-nothing", "both decided");
    // A version-5 call cannot name a credential at all.
    let v5 = format!(
        r#"{{"v":1,"id":"msg_{id}","type":"request","schema":"direwolf.tool.invoke","schema_version":5,"ts":"2026-10-18T10:00:02.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"idempotency_key":"s1-v5c","payload":{{"process_exec":{call}}}}}"#,
        id = encode_uuid(uuid(29_999)),
        session = fx.session.as_str(),
        run = run.as_str(),
        epoch = fx.epoch.get(),
        call = launch_call(FIXTURE, &[], Some(DEPLOY)),
    );
    assert!(
        dwkp::decode_body(v5.as_bytes()).is_err(),
        "version 5 has no credential_handle"
    );
    secret_evidence("v5-cannot-name-a-credential", "schema violation");
}

#[test]
fn every_refusal_and_denial_reads_nothing_records_no_use_and_runs_nothing() {
    let Some((mut fx, _seeded, _values)) = secret_fixture("refuse", ALLOW, None) else {
        return;
    };
    let run = fx.run("s2", GRANTS);
    let rows = |fx: &Fixture| {
        (
            fx.count("SELECT count(*) FROM secret_injection"),
            fx.count("SELECT count(*) FROM workload"),
        )
    };
    let quiet = rows(&fx);
    for (case, executable, handle, reason) in [
        (
            "not-configured",
            FIXTURE,
            "never-configured",
            "NOT_CONFIGURED",
        ),
        (
            "consumer-not-allowed",
            FIXTURE,
            ELSEWHERE,
            "CONSUMER_NOT_ALLOWED",
        ),
        ("another-executable", TRUE, DEPLOY, "CONSUMER_NOT_ALLOWED"),
        // An egress secret names no consumer: no process is one.
        ("egress-only", FIXTURE, API, "CONSUMER_NOT_ALLOWED"),
        (
            "reserved-variable",
            FIXTURE,
            PROXY,
            "SECRET_VARIABLE_RESERVED",
        ),
    ] {
        let before = reads_on_this_thread();
        let body = fx.launch6(
            &run,
            &format!("s2-{case}"),
            &launch_call(executable, &["x"], Some(handle)),
        );
        assert_eq!(refused6(&body), R::CredentialUnavailable, "{case}");
        assert_eq!(fx.last_denial().as_deref(), Some(reason), "{case}");
        assert_eq!(reads_on_this_thread() - before, 0, "{case}");
        assert_eq!(rows(&fx), quiet, "{case}");
        secret_evidence(&format!("refused-{case}"), reason);
    }
    // Not granted: both gates decide, the injection is denied, nothing runs.
    let before = reads_on_this_thread();
    let body = fx.launch6(
        &run,
        "s2-ungranted",
        &launch_call(FIXTURE, &["x"], Some(SPARE)),
    );
    let plan = plan6(&body);
    assert!(matches!(body, DwkpBody::ToolDeniedV6(_)));
    assert_eq!(plan.effect, DecisionEffect::Deny);
    let spawn = injection(plan).unwrap();
    assert_eq!(spawn.decision.effect, DecisionEffect::Deny);
    assert_eq!(spawn.decision.reason, ProcessDecisionReason::NoCapability);
    assert_eq!(
        plan.actions.as_slice()[0]
            .workload
            .as_ref()
            .unwrap()
            .decision
            .effect,
        DecisionEffect::Allow,
        "permission to run the executable is not permission to use the secret"
    );
    assert_eq!(fx.last_denial().as_deref(), Some("CAPABILITY_NOT_GRANTED"));
    assert_eq!(reads_on_this_thread() - before, 0);
    assert_eq!(rows(&fx), quiet);
    secret_evidence("not-granted-denied", "NO_CAPABILITY");
    // A revision the run was not admitted with: replaced, then revoked.
    for (revision, state, want) in [(2, "CONFIGURED", "REPLACED"), (3, "REVOKED", "REVOKED")] {
        let metadata = format!("{{\"r\":{revision}}}");
        let digest = crate::state::digest::DomainHash::new(crate::state::digest::SECRET_METADATA)
            .text(&metadata)
            .finish()
            .to_hex();
        fx.db()
            .execute(
                "INSERT INTO secret_revision (handle, revision, state, backend, metadata, \
                 metadata_sha256, recorded_ms) VALUES ('env-token', ?1, ?2, 'keychain', ?3, ?4, 0)",
                rusqlite::params![revision, state, metadata, digest],
            )
            .unwrap();
        let before = reads_on_this_thread();
        let body = fx.launch6(
            &run,
            &format!("s2-{want}"),
            &launch_call(FIXTURE, &["x"], Some(ENV_TOKEN)),
        );
        assert_eq!(refused6(&body), R::CredentialUnavailable);
        assert_eq!(fx.last_denial().as_deref(), Some(want));
        assert_eq!(reads_on_this_thread() - before, 0);
        secret_evidence(&format!("stored-grant-{}", want.to_lowercase()), want);
    }
    assert_eq!(rows(&fx), quiet);
    assert!(fx.secrets_handed().is_empty());
    assert!(!fx.fake.operations().contains(&"workload.secret_start"));
    secret_evidence("no-refusal-reaches-the-broker", "0 secret starts");
}

#[test]
fn policy_must_allow_the_use_in_a_sandbox_and_approvals_stay_closed_until_m6() {
    for (rule, case, reason) in [
        ("", "default-deny", ProcessDecisionReason::DefaultDeny),
        (
            HOST_ONLY,
            "host-rule-is-no-sandbox-rule",
            ProcessDecisionReason::DefaultDeny,
        ),
        (
            APPROVAL,
            "approval-required",
            ProcessDecisionReason::ApprovalRequired,
        ),
        (
            UNKEEPABLE,
            "obligation-unenforceable",
            ProcessDecisionReason::ObligationUnenforceable,
        ),
    ] {
        let Some((mut fx, _seeded, _values)) = secret_fixture(case, rule, None) else {
            return;
        };
        let run = fx.run("s3", GRANTS);
        let before = reads_on_this_thread();
        let body = fx.launch6(&run, "s3-1", &launch_call(FIXTURE, &["x"], Some(DEPLOY)));
        assert!(
            matches!(body, DwkpBody::ToolDeniedV6(_)),
            "{case}: {body:?}"
        );
        let spawn = injection(plan6(&body)).unwrap();
        assert_eq!(spawn.decision.effect, DecisionEffect::Deny, "{case}");
        assert_eq!(spawn.decision.reason, reason, "{case}");
        assert_eq!(reads_on_this_thread() - before, 0, "{case}");
        assert_eq!(
            fx.count("SELECT count(*) FROM secret_injection"),
            0,
            "{case}"
        );
        assert_eq!(fx.count("SELECT count(*) FROM workload"), 0, "{case}");
        secret_evidence(case, reason.as_str());
    }
}

#[test]
fn a_credential_that_cannot_be_read_or_carried_fails_the_launch_before_anything_runs() {
    let Some((mut fx, _seeded, values)) = secret_fixture("fail", ALLOW, None) else {
        return;
    };
    let run = fx.run("s4", GRANTS);
    // The backend has no such entry; a variable's value holds a NUL.
    for (case, handle, failure) in [
        ("backend-missing", GONE, "BACKEND_ITEM_MISSING"),
        ("nul-in-a-variable", NUL, "SECRET_MATERIAL_INVALID"),
    ] {
        let body = fx.launch6(
            &run,
            &format!("s4-{case}"),
            &launch_call(FIXTURE, &["x"], Some(handle)),
        );
        assert_eq!(failed6(&body).0, F::CredentialFailed, "{case}");
        let (workload, secret, stored): (String, String, Option<String>) = fx
            .db()
            .query_row(
                "SELECT w.state, s.state, s.failure FROM workload_secret ws \
                 JOIN workload w ON w.invocation_id = ws.workload_invocation_id \
                 JOIN secret_injection s ON s.invocation_id = ws.injection_invocation_id \
                 WHERE s.handle = ?1",
                [handle],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (workload.as_str(), secret.as_str()),
            ("FAILED", "FAILED"),
            "{case}"
        );
        assert_eq!(stored.as_deref(), Some(failure), "{case}");
        assert!(fx.secrets_handed().is_empty(), "{case}: handed over");
        secret_evidence(&format!("failed-{case}"), failure);
    }
    // The broker refuses what it would not carry: nothing ran.
    fx.fake
        .then_start(Err(BrokerError::after_sending(BrokerFailure::Refused(
            BrokerRefusal::SecretUnsafeBytes,
        ))));
    let body = fx.launch6(
        &run,
        "s4-broker",
        &launch_call(FIXTURE, &["x"], Some(ENV_TOKEN)),
    );
    assert_eq!(failed6(&body).0, F::CredentialFailed);
    assert_eq!(
        fx.one("SELECT state FROM secret_injection ORDER BY rowid DESC LIMIT 1"),
        "FAILED"
    );
    secret_evidence("broker-refusal-failed", "CREDENTIAL_FAILED");
    // A start nothing confirms: both UNKNOWN, the environment destroyed,
    // the use not counted.
    let environment = fx.one(&format!(
        "SELECT environment_id FROM environment WHERE run_id = '{}' AND state = 'READY'",
        run.as_str()
    ));
    fx.fake.then_start(Err(BrokerError::after_sending(
        BrokerFailure::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    )));
    let body = fx.launch6(
        &run,
        "s4-unknown",
        &launch_call(FIXTURE, &["x"], Some(DEPLOY)),
    );
    assert_eq!(failed6(&body), (F::OutcomeUnknown, Some(true)));
    assert_eq!(
        fx.one("SELECT state FROM secret_injection ORDER BY rowid DESC LIMIT 1"),
        "UNKNOWN"
    );
    assert_ne!(
        fx.one(&format!(
            "SELECT state FROM environment WHERE environment_id = '{environment}'"
        )),
        "READY"
    );
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_use WHERE handle = 'deploy-key'"),
        0
    );
    secret_evidence(
        "unknown-start-unknown-use",
        "UNKNOWN, environment destroyed",
    );
    // A collection that names no redaction count for a secret-bearing
    // workload is a broker that does not keep the protocol. (The launch
    // prepares the run's environment again.)
    fx.fake
        .then_collect(Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(
            ran(WorkloadEnding::Exited, b"ok", Verdict::Pass),
        ))));
    let body = fx.launch6(
        &run,
        "s4-count",
        &launch_call(FIXTURE, &["x"], Some(DEPLOY)),
    );
    assert_eq!(failed6(&body).0, F::OutcomeUnknown);
    secret_evidence("missing-redaction-count-unknown", "BROKER_PROTOCOL_ERROR");
    for v in [&values.deploy, &values.env] {
        assert!(!fx.durable_holds(v));
    }
}

#[test]
fn a_crash_in_every_window_leaves_the_use_unknown_and_never_hands_it_over_again() {
    use CrashPoint as P;
    // (point, the use's state after the restart, whether it was handed over)
    for (point, after, handed) in [
        (P::SecretBeforeMetadata, None, false),
        (P::SecretAfterMetadata, None, false),
        (P::WorkloadAfterIntent, Some("UNKNOWN"), false),
        (P::SecretAfterIntent, Some("UNKNOWN"), false),
        (P::SecretAfterBackend, Some("UNKNOWN"), false),
        (P::SecretAfterRegister, Some("UNKNOWN"), false),
        (P::SecretAfterHandoff, Some("UNKNOWN"), false),
        (P::SecretAfterBroker, Some("UNKNOWN"), true),
        (P::WorkloadAfterStart, Some("UNKNOWN"), true),
        (P::WorkloadAfterBroker, Some("UNKNOWN"), true),
        (P::SecretBeforeOutcome, Some("UNKNOWN"), true),
        (P::WorkloadAfterOutcome, Some("INJECTED"), true),
        (P::SecretAfterOutcome, Some("INJECTED"), true),
    ] {
        let Some((mut fx, _seeded, _values)) = secret_fixture(
            &format!("crash-{}", point.letter()),
            ALLOW,
            Some(stop_at(point)),
        ) else {
            return;
        };
        let run = fx.run("s5", GRANTS);
        let message = fx.message(
            &run,
            6,
            "direwolf.tool.invoke",
            Some("s5-1"),
            &format!(
                r#"{{"process_exec":{}}}"#,
                launch_call(FIXTURE, &["x"], Some(DEPLOY))
            ),
        );
        let caller = fx.caller.unwrap();
        let stopped = match fx.authority().dispatch_parkable(&caller, &message) {
            Err(_) => true,
            Ok(Dispatched::Parked(mut parked)) => {
                let mut stopped = false;
                for _ in 0..100 {
                    match fx.authority().resume(&mut parked) {
                        Err(_) => {
                            stopped = true;
                            break;
                        }
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                    }
                }
                stopped
            }
            Ok(Dispatched::Answer(_)) => false,
        };
        assert!(stopped, "{point:?}: stopped");
        let starts = fx.secrets_handed().len();
        assert_eq!(starts, usize::from(handed), "{point:?}");
        fx.restart(Some(IMAGE));
        let state: Option<String> = fx
            .db()
            .query_row("SELECT state FROM secret_injection", [], |row| row.get(0))
            .ok();
        assert_eq!(state.as_deref(), after, "{point:?}");
        if after == Some("UNKNOWN") {
            assert_eq!(fx.one("SELECT state FROM workload"), "UNKNOWN", "{point:?}");
            assert_eq!(fx.count("SELECT count(*) FROM secret_use"), 0, "{point:?}");
        }
        // Never again: the same key in a new run of the session.
        let run = fx.run("s5-again", GRANTS);
        let again = fx.launch6(&run, "s5-1", &launch_call(FIXTURE, &["x"], Some(DEPLOY)));
        if after.is_some() {
            assert_eq!(refused6(&again), R::IdempotencyKeyReused, "{point:?}");
            assert_eq!(
                fx.secrets_handed().len(),
                starts,
                "{point:?}: handed over again"
            );
        }
        secret_evidence(
            &format!("crash-{}", point.letter()),
            after.unwrap_or("nothing-recorded"),
        );
    }
}

#[test]
fn a_credential_reaches_no_process_without_an_execution_environment() {
    let Some((mut fx, _seeded, _values)) = secret_fixture("host", ALLOW, None) else {
        return;
    };
    // A new incarnation with no sandbox attached: the host's route.
    fx.restart(None);
    let run = fx.run("s6", GRANTS);
    let before = reads_on_this_thread();
    let body = fx.launch6(
        &run,
        "s6-1",
        &launch_call("/usr/bin/true", &[], Some(DEPLOY)),
    );
    assert_eq!(refused6(&body), R::CredentialUnavailable);
    assert_eq!(reads_on_this_thread() - before, 0);
    assert_eq!(fx.count("SELECT count(*) FROM secret_injection"), 0);
    assert!(
        fx.fake
            .operations()
            .iter()
            .all(|o| !o.starts_with("process"))
    );
    let refusal = crate::state::read_audit_log(&fx.state().join("audit.log"))
        .unwrap()
        .into_iter()
        .rev()
        .find(|r| r.event() == "tool.refused")
        .unwrap();
    assert_eq!(refusal.text("detail"), Some("NO_EXECUTION_ENVIRONMENT"));
    secret_evidence("no-host-fallback", "CREDENTIAL_UNAVAILABLE");
    let _ = NEXT_MESSAGE.load(Ordering::SeqCst);
}
