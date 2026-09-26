//! The mode A pipeline's state machine, in this crate's unit tests (ADR-0046
//! §§5, 17–20): a real authority — a store, a policy, a run admitted with
//! `secret.use:<handle>` — real values in the **kernel keyring**, read by the
//! real backend, and an **in-process fake broker** that reads the one-shot
//! pipe it is handed. The fake proves what the authority hands over and
//! when; the real broker's render is measured by the broker's own suites and
//! the secret evidence.
//!
//! Every value is generated at run time. Assertions compare digests and
//! booleans, never values, so no failure can print one (ADR-0046 §22).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::collections::VecDeque;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::dwkp::{self, DwkpMessage};
use dwk_proto::wire::id::{RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{AgentProfileName, Epoch, IdempotencyKey};
use sha2::{Digest as _, Sha256};

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation, Unreachable,
};
use crate::capability::PrivacyClass;
use crate::scratch::Scratch;
use crate::secret::backend::{keychain_test_support, reads_on_this_thread};
use crate::secret::metadata;
use crate::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, CrashHook, CrashPoint,
    EgressReply, EgressRequest, HookAction, ManualClock, Mode, PolicySet, PolicySource, Reply,
    StartOptions, StartupConfig, WorkspaceId, WorkspaceSensitivity,
};

const START_MS: u64 = 1_758_000_000_000;

/// One line of the secret evidence (`make secret-broker-evidence`), printed
/// only after the assertions before it held.
fn evidence(suite: &str, case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// Which policy the fixture runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// A dedicated operator test policy that allows `secret.use` on the host.
    /// **Not** a shipped pack: every shipped pack denies it (ADR-0046 §18).
    Allow,
    /// No rule allows it: the default denies.
    Deny,
    /// Allowed, with an obligation a secret use cannot keep.
    Obligation,
}

fn policy_text(policy: Policy) -> String {
    let rule = match policy {
        Policy::Allow => {
            "[[rule]]\nid = \"allow-secret-use\"\neffect = \"ALLOW\"\nwhen.verb = \"secret.use\"\nwhen.environment = \"host\"\nobligations = [\"audit_level=full\"]\n"
        }
        Policy::Deny => "",
        Policy::Obligation => {
            "[[rule]]\nid = \"allow-secret-use-no-network\"\neffect = \"ALLOW\"\nwhen.verb = \"secret.use\"\nobligations = [\"network_deny\"]\n"
        }
    };
    format!(
        "schema_version = 1\n\n[meta]\nname = \"m4e\"\n\n{rule}\n[[rule]]\nid = \"allow-host-process\"\neffect = \"ALLOW\"\nwhen.verb = [\"process.exec\", \"process.inspect\", \"process.signal\"]\nwhen.environment = \"host\"\n\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n"
    )
}

/// This test process's salt: fixed for its lifetime, different between runs.
fn salt() -> u32 {
    static SALT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        nanos ^ 0x5eed_1234
    })
}

/// A value: `len` bytes, printable, distinct per `seed` and per run.
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
    Sha256::digest(bytes).into()
}

/// What the fake received for one order.
#[derive(Debug, Clone)]
struct Asked {
    operation: &'static str,
    /// The digest of the pipe's content: the value, if it was the value.
    received: Option<[u8; 32]>,
    /// `secret_injection` INTENT rows when the order arrived.
    intents: i64,
}

#[derive(Debug, Default)]
struct Fake {
    script: Mutex<VecDeque<Result<BrokerDelivery, BrokerError>>>,
    asked: Mutex<Vec<Asked>>,
    store: Mutex<Option<PathBuf>>,
}

impl EffectBroker for Fake {
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        let name = order.operation().name();
        let intents = self.store.lock().unwrap().as_ref().map_or(0, |db| {
            rusqlite::Connection::open(db)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM secret_injection WHERE state = 'INTENT'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        });
        let (_, operation) = order.into_parts();
        let received = match operation {
            Operation::SecretEgress { secret, .. } => {
                let mut reader = std::io::PipeReader::from(secret.into_transfer_descriptor());
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                Some(digest(&bytes))
            }
            _ => None,
        };
        self.asked.lock().unwrap().push(Asked {
            operation: name,
            received,
            intents,
        });
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(BrokerDelivery::SecretEgress))
    }
}

fn uuid(n: u64) -> u128 {
    let ts = u128::from(START_MS);
    let n = u128::from(n);
    (ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | (n & ((1 << 62) - 1))
}

fn decode(json: &str) -> DwkpMessage {
    dwkp::decode_body(json.as_bytes()).unwrap_or_else(|e| panic!("decodes: {e}\n{json}"))
}

fn admit(session: &SessionId, epoch: Epoch, key: &str, requested: &[&str]) -> DwkpMessage {
    let caps: Vec<String> = requested.iter().map(|c| format!("\"{c}\"")).collect();
    decode(&format!(
        r#"{{"v":1,"id":"msg_{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-21T10:00:01.000Z","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"agent_profile":"operator","skills":[],"requested_capabilities":[{caps}]}}}}"#,
        id = encode_uuid(uuid(10_000 + u64::try_from(key.len()).unwrap())),
        session = session.as_str(),
        epoch = epoch.get(),
        caps = caps.join(","),
    ))
}

/// Keychain entries this fixture seeded, removed when it drops.
struct Entries(Vec<String>);

impl Drop for Entries {
    fn drop(&mut self) {
        for entry in &self.0 {
            keychain_test_support::remove(entry);
        }
    }
}

struct Fixture {
    scratch: Scratch,
    authority: Option<Authority>,
    fake: Arc<Fake>,
    caller: CallerContext,
    session: SessionId,
    epoch: Epoch,
    config: StartupConfig,
    entries: Entries,
    /// The digest of `api-token`'s value.
    api: [u8; 32],
    api_value_len: usize,
}

/// The handles every fixture configures:
///
/// * `api-token` — egress to `api.example.com:443`, `Authorization: Bearer`;
/// * `fd-key` — `fd_at_spawn` only, for `/usr/bin/env`;
/// * `old-token` — revoked;
/// * `broken-header` — egress, whose value holds a line feed.
fn secrets_toml(tag: &str) -> String {
    format!(
        r#"schema_version = 1

[secrets.api-token]
type = "bearer"
storage = "keychain"
keychain = "{tag}-api"
origins = ["api.example.com:443"]
header = "Authorization"
prefix = "Bearer "
injection = ["egress"]

[secrets.fd-key]
type = "generic"
storage = "keychain"
keychain = "{tag}-fd"
injection = ["fd_at_spawn"]
consumers = ["/usr/bin/env"]

[secrets.old-token]
type = "bearer"
storage = "keychain"
keychain = "{tag}-old"
origins = ["api.example.com:443"]
header = "Authorization"
injection = ["egress"]
revoked = true

[secrets.broken-header]
type = "bearer"
storage = "keychain"
keychain = "{tag}-broken"
origins = ["api.example.com:443"]
header = "X-Token"
injection = ["egress"]
"#
    )
}

fn start(
    state: &Path,
    config: &StartupConfig,
    fake: &Arc<Fake>,
    hook: Option<CrashHook>,
) -> Authority {
    let broker: Arc<dyn EffectBroker> = fake.clone();
    Authority::start(
        state,
        config,
        StartOptions {
            clock: Arc::new(ManualClock::new(START_MS)),
            crash_hook: hook,
            broker: Some(broker),
        },
    )
    .unwrap()
    .0
}

/// A real authority whose values live in the kernel keyring, or `None` when
/// this host has no usable keyring (NOT EXERCISED, said so).
fn fixture_with(tag: &str, policy: Policy, hook: Option<CrashHook>) -> Option<Fixture> {
    let prefix = format!("direwolf-test/{tag}-{}", salt());
    let api = value(1, 40);
    let mut broken = value(4, 24);
    broken[10] = b'\n';
    let mut entries = Entries(Vec::new());
    for (suffix, bytes) in [
        ("api", api.clone()),
        ("fd", value(2, 32)),
        ("old", value(3, 32)),
        ("broken", broken),
    ] {
        let entry = format!("{prefix}-{suffix}");
        if keychain_test_support::seed(&entry, &bytes).is_none() {
            println!("NOT EXERCISED: no usable kernel keyring on this host");
            return None;
        }
        entries.0.push(entry);
    }
    let scratch = Scratch::new("secret-use");
    let root = scratch.path().join("ws");
    std::fs::create_dir_all(&root).unwrap();
    let mut config = StartupConfig::new(
        PolicySet {
            profile: "m4e".to_owned(),
            sources: vec![PolicySource {
                name: "m4e.toml".to_owned(),
                text: policy_text(policy),
            }],
        },
        Mode::Balanced,
        vec![
            "secret.use:*".to_owned(),
            "fs.read:*".to_owned(),
            "process.exec:*".to_owned(),
            "process.inspect:*".to_owned(),
        ],
    );
    config.flags = crate::state::ConfigFlags {
        security_allow_host_execution: true,
    };
    config.secrets = metadata::parse(&secrets_toml(&prefix)).unwrap();
    let fake = Arc::new(Fake::default());
    let state = scratch.path().join("state");
    let mut authority = start(&state, &config, &fake, hook);
    *fake.store.lock().unwrap() = Some(state.join("kernel.db"));
    let workspace = WorkspaceId::new("ws").unwrap();
    let session = SessionId::from_uuid(uuid(1)).unwrap();
    {
        let mut operator = authority.operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: [
                    "secret.use:api-token",
                    "secret.use:fd-key",
                    "secret.use:old-token",
                    "secret.use:broken-header",
                    "secret.use:never-configured",
                    "process.exec:*",
                    "process.inspect:*",
                ]
                .map(str::to_owned)
                .to_vec(),
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
    let caller = authority.connect(AuthenticatedSubject::unix_uid(1000));
    let Reply::Done(epoch) = authority.acquire_lease(&caller, &session).unwrap() else {
        panic!("a lease")
    };
    Some(Fixture {
        scratch,
        authority: Some(authority),
        fake,
        caller,
        session,
        epoch,
        config,
        entries,
        api: digest(&api),
        api_value_len: api.len(),
    })
}

fn fixture(tag: &str, policy: Policy) -> Option<Fixture> {
    fixture_with(tag, policy, None)
}

impl Fixture {
    fn authority(&mut self) -> &mut Authority {
        self.authority.as_mut().unwrap()
    }

    fn state(&self) -> PathBuf {
        self.scratch.path().join("state")
    }

    fn run(&mut self, key: &str, requested: &[&str]) -> RunId {
        let message = admit(&self.session, self.epoch, key, requested);
        let caller = self.caller;
        match self.authority().admit_run(&caller, &message).unwrap() {
            Reply::Done(admission) => admission.run_id().clone(),
            Reply::Refused(why) => panic!("admitted: {why:?}"),
        }
    }

    fn egress(&mut self, run: &RunId, handle: &str, origin: &str, key: &str) -> EgressReply {
        let request = EgressRequest {
            handle: handle.to_owned(),
            origin: origin.to_owned(),
            key: IdempotencyKey::new(key.to_owned()).unwrap(),
        };
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .secret_egress(&caller, &session, run, epoch, &request)
            .unwrap()
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.state().join("kernel.db")).unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.db().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn asked(&self) -> Vec<Asked> {
        self.fake.asked.lock().unwrap().clone()
    }

    /// Whether any byte run of `needle` is in any file of the state directory
    /// (`kernel.db`, its WAL and shared memory, `audit.log`).
    fn durable_holds(&self, needle: &[u8]) -> bool {
        std::fs::read_dir(self.state()).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            path.is_file()
                && std::fs::read(&path)
                    .unwrap()
                    .windows(needle.len())
                    .any(|w| w == needle)
        })
    }
}

#[test]
fn admission_resolves_handles_from_the_index_and_reads_no_value() {
    let Some(mut fx) = fixture("admit", Policy::Allow) else {
        return;
    };
    let before = reads_on_this_thread();
    let requested = [
        "secret.use:api-token",
        "secret.use:old-token",
        "secret.use:never-configured",
    ];
    let message = admit(&fx.session, fx.epoch, "admit-1", &requested);
    let caller = fx.caller;
    let Reply::Done(admission) = fx.authority().admit_run(&caller, &message).unwrap() else {
        panic!("admitted")
    };
    let granted: Vec<String> = admission
        .granted()
        .iter()
        .map(|g| g.capability().to_canonical_string())
        .collect();
    assert_eq!(granted, ["secret.use:api-token"]);
    let withheld: Vec<(String, &str)> = admission
        .withheld()
        .iter()
        .map(|w| (w.requested().as_str().to_owned(), w.cause().code()))
        .collect();
    assert!(withheld.contains(&("secret.use:old-token".to_owned(), "NEEDS_CONFIGURED_SECRET")));
    assert!(withheld.contains(&(
        "secret.use:never-configured".to_owned(),
        "NEEDS_CONFIGURED_SECRET"
    )));
    // The same key again: the recorded admission, and still no read.
    let Reply::Done(again) = fx.authority().admit_run(&caller, &message).unwrap() else {
        panic!("replayed")
    };
    assert_eq!(again.run_id(), admission.run_id());
    assert_eq!(
        reads_on_this_thread() - before,
        0,
        "admission reads no value"
    );
    // The run is bound to the revision it was admitted with.
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_run_binding WHERE handle = 'api-token'"),
        1
    );
    evidence(
        "authority-secret-pipeline",
        "admission-new-declaration",
        "zero-backend-reads",
    );
    evidence(
        "authority-secret-pipeline",
        "admission-unconfigured-or-revoked",
        "NEEDS_CONFIGURED_SECRET",
    );
    evidence(
        "authority-secret-pipeline",
        "admission-replay",
        "zero-backend-reads",
    );
}

#[test]
fn a_use_reads_its_value_only_after_both_gates_and_a_durable_intent_and_hands_it_over_once() {
    let Some(mut fx) = fixture("inject", Policy::Allow) else {
        return;
    };
    let run = fx.run("inject-run", &["secret.use:api-token"]);
    let before = reads_on_this_thread();
    let reply = fx.egress(&run, "api-token", "api.example.com:443", "use-1");
    let EgressReply::Injected { invocation } = reply else {
        panic!("injected: {reply:?}")
    };
    assert_eq!(
        reads_on_this_thread() - before,
        1,
        "exactly one backend read"
    );
    let asked = fx.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].operation, "secret.egress");
    assert_eq!(
        asked[0].intents, 1,
        "the intent was durable before the handoff"
    );
    assert!(
        asked[0].received == Some(fx.api),
        "the pipe held exactly the value"
    );
    // The return path knows it, by its keyed fingerprint only.
    let handle = crate::secret::metadata::SecretHandle::new("api-token").unwrap();
    assert!(fx.authority().shared.secrets.indexed(&handle));
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM secret_injection WHERE state = 'INJECTED' AND mode = 'egress'"
        ),
        1
    );
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        1
    );

    // The same key: the recorded outcome. No read, no second handoff, no
    // second count.
    let again = fx.egress(&run, "api-token", "api.example.com:443", "use-1");
    assert_eq!(
        again,
        EgressReply::Replayed {
            invocation,
            state: "INJECTED".to_owned(),
            failure: None
        }
    );
    assert_eq!(reads_on_this_thread() - before, 1, "a replay reads nothing");
    assert_eq!(fx.asked().len(), 1, "a replay hands nothing over");
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        1
    );

    // A new key is a new use, counted once more.
    assert!(matches!(
        fx.egress(&run, "api-token", "api.example.com:443", "use-2"),
        EgressReply::Injected { .. }
    ));
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        2
    );

    // No durable file holds the value.
    let value = value(1, fx.api_value_len);
    assert!(!fx.durable_holds(&value), "no durable plaintext");
    assert!(!fx.durable_holds(&value[..16]), "no durable prefix");
    evidence(
        "authority-secret-pipeline",
        "intent-durable-before-read",
        "ordered",
    );
    evidence(
        "authority-secret-pipeline",
        "one-backend-read",
        "exactly-one",
    );
    evidence(
        "authority-secret-pipeline",
        "one-shot-handoff",
        "fake-broker-digest-equal",
    );
    evidence(
        "authority-secret-pipeline",
        "replay",
        "recorded-zero-reads-zero-handoff",
    );
    evidence(
        "authority-secret-pipeline",
        "use-count",
        "once-per-injection",
    );
    evidence(
        "authority-secret-pipeline",
        "durable-state",
        "no-plaintext-no-prefix",
    );
}

#[test]
fn every_denial_reads_nothing_and_hands_nothing_over() {
    let Some(mut fx) = fixture("deny", Policy::Allow) else {
        return;
    };
    let granted = fx.run("deny-run", &["secret.use:api-token", "secret.use:fd-key"]);
    let ungranted = fx.run("deny-other", &["fs.read:*"]);
    let before = reads_on_this_thread();
    let cases: [(&RunId, &str, &str, EgressReply); 11] = [
        // Origin binding over the endpoint grammar (ADR-0046 §15).
        (
            &granted,
            "api-token",
            "api.example.com.evil.test:443",
            EgressReply::Denied("ORIGIN_NOT_ALLOWED"),
        ),
        (
            &granted,
            "api-token",
            "evil-api.example.com:443",
            EgressReply::Denied("ORIGIN_NOT_ALLOWED"),
        ),
        (
            &granted,
            "api-token",
            "example.com:443",
            EgressReply::Denied("ORIGIN_NOT_ALLOWED"),
        ),
        (
            &granted,
            "api-token",
            "api.example.com:8443",
            EgressReply::Denied("ORIGIN_NOT_ALLOWED"),
        ),
        (
            &granted,
            "api-token",
            "user@api.example.com:443",
            EgressReply::Refused("MALFORMED_REQUEST"),
        ),
        (
            &granted,
            "api-token",
            "api.example.com",
            EgressReply::Refused("MALFORMED_REQUEST"),
        ),
        // The mode is the metadata's: an fd-only secret is never egressed.
        (
            &granted,
            "fd-key",
            "api.example.com:443",
            EgressReply::Denied("INJECTION_MODE_UNAVAILABLE"),
        ),
        // The index decides what a handle means.
        (
            &granted,
            "never-configured",
            "api.example.com:443",
            EgressReply::Denied("NOT_CONFIGURED"),
        ),
        (
            &granted,
            "old-token",
            "api.example.com:443",
            EgressReply::Denied("REVOKED"),
        ),
        // The capability gate: a run never granted the handle.
        (
            &ungranted,
            "api-token",
            "api.example.com:443",
            EgressReply::Denied("CAPABILITY_NOT_GRANTED"),
        ),
        (
            &granted,
            "Not-A-Handle",
            "api.example.com:443",
            EgressReply::Refused("MALFORMED_REQUEST"),
        ),
    ];
    for (n, (run, handle, origin, want)) in cases.iter().enumerate() {
        let got = fx.egress(run, handle, origin, &format!("deny-{n}"));
        assert_eq!(&got, want, "{handle} to {origin}");
    }
    assert_eq!(
        reads_on_this_thread() - before,
        0,
        "no denial reads a value"
    );
    assert!(fx.asked().is_empty(), "no denial reaches the broker");
    assert_eq!(fx.count("SELECT count(*) FROM secret_injection"), 0);
    assert_eq!(fx.count("SELECT count(*) FROM secret_use"), 0);
    evidence(
        "authority-secret-pipeline",
        "origin-suffix-attack",
        "ORIGIN_NOT_ALLOWED",
    );
    evidence(
        "authority-secret-pipeline",
        "origin-prefix-attack",
        "ORIGIN_NOT_ALLOWED",
    );
    evidence(
        "authority-secret-pipeline",
        "origin-parent-domain",
        "ORIGIN_NOT_ALLOWED",
    );
    evidence(
        "authority-secret-pipeline",
        "origin-wrong-port",
        "ORIGIN_NOT_ALLOWED",
    );
    evidence(
        "authority-secret-pipeline",
        "origin-userinfo",
        "MALFORMED_REQUEST",
    );
    evidence(
        "authority-secret-pipeline",
        "mode-downgrade-fd-only-to-egress",
        "INJECTION_MODE_UNAVAILABLE",
    );
    evidence(
        "authority-secret-pipeline",
        "not-configured",
        "NOT_CONFIGURED",
    );
    evidence("authority-secret-pipeline", "revoked", "REVOKED");
    evidence(
        "authority-secret-pipeline",
        "capability-gate",
        "CAPABILITY_NOT_GRANTED",
    );
}

#[test]
fn the_policy_gate_and_the_obligations_are_each_enough_to_deny() {
    for (policy, want) in [
        (Policy::Deny, "POLICY_DENIED"),
        (Policy::Obligation, "OBLIGATION_UNENFORCEABLE"),
    ] {
        let Some(mut fx) = fixture(&format!("gate-{}", want.len()), policy) else {
            return;
        };
        let run = fx.run("gate-run", &["secret.use:api-token"]);
        let before = reads_on_this_thread();
        assert_eq!(
            fx.egress(&run, "api-token", "api.example.com:443", "gate-1"),
            EgressReply::Denied(want)
        );
        assert_eq!(reads_on_this_thread() - before, 0);
        assert!(fx.asked().is_empty());
    }
    evidence("authority-secret-pipeline", "policy-gate", "POLICY_DENIED");
    evidence(
        "authority-secret-pipeline",
        "obligation-unenforceable",
        "OBLIGATION_UNENFORCEABLE",
    );
}

#[test]
fn a_revoked_replaced_or_removed_revision_fails_closed_for_a_run_admitted_before_it() {
    let Some(mut fx) = fixture("revision", Policy::Allow) else {
        return;
    };
    let run = fx.run("revision-run", &["secret.use:api-token"]);
    let digest_of = |text: &str| {
        crate::state::digest::DomainHash::new(crate::state::digest::SECRET_METADATA)
            .text(text)
            .finish()
            .to_hex()
    };
    // What a restart with changed metadata records: a later revision. The
    // run was bound to revision 1.
    let conn = fx.db();
    for (revision, state, backend) in [
        (2, "CONFIGURED", Some("keychain")),
        (3, "REVOKED", Some("keychain")),
        (4, "REMOVED", None),
    ] {
        let metadata = format!("{{\"r\":{revision}}}");
        conn.execute(
            "INSERT INTO secret_revision (handle, revision, state, backend, metadata, \
             metadata_sha256, recorded_ms) VALUES ('api-token', ?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![revision, state, backend, metadata, digest_of(&metadata)],
        )
        .unwrap();
        let want = match state {
            "CONFIGURED" => "REPLACED",
            "REVOKED" => "REVOKED",
            _ => "NOT_CONFIGURED",
        };
        let before = reads_on_this_thread();
        assert_eq!(
            fx.egress(
                &run,
                "api-token",
                "api.example.com:443",
                &format!("rev-{revision}")
            ),
            EgressReply::Denied(want),
            "revision {revision} {state}"
        );
        assert_eq!(reads_on_this_thread() - before, 0);
    }
    assert!(fx.asked().is_empty());
    evidence(
        "authority-secret-pipeline",
        "stored-grant-replaced",
        "REPLACED",
    );
    evidence(
        "authority-secret-pipeline",
        "stored-grant-revoked",
        "REVOKED",
    );
    evidence(
        "authority-secret-pipeline",
        "stored-grant-removed",
        "NOT_CONFIGURED",
    );
}

#[test]
fn a_backend_failure_or_a_value_unsafe_for_a_header_ends_failed_and_reaches_no_broker() {
    let Some(mut fx) = fixture("failures", Policy::Allow) else {
        return;
    };
    let run = fx.run(
        "failures-run",
        &["secret.use:api-token", "secret.use:broken-header"],
    );
    // A line feed in a header-bound value: refused in the authority, never
    // sent.
    assert!(matches!(
        fx.egress(&run, "broken-header", "api.example.com:443", "f-1"),
        EgressReply::Failed {
            reason: "SECRET_MATERIAL_INVALID",
            ..
        }
    ));
    // The item disappears from the keychain after start: a typed failure.
    let api_entry = fx.entries.0[0].clone();
    keychain_test_support::remove(&api_entry);
    assert!(matches!(
        fx.egress(&run, "api-token", "api.example.com:443", "f-2"),
        EgressReply::Failed {
            reason: "BACKEND_ITEM_MISSING",
            ..
        }
    ));
    assert!(fx.asked().is_empty(), "neither reached the broker");
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_injection WHERE state = 'FAILED'"),
        2
    );
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_use"),
        0,
        "a failure is not a use"
    );
    evidence(
        "authority-secret-pipeline",
        "backend-item-missing-after-intent",
        "FAILED-no-handoff",
    );
    evidence(
        "authority-secret-pipeline",
        "header-breaking-value",
        "SECRET_MATERIAL_INVALID-no-handoff",
    );
}

#[test]
fn the_brokers_answer_decides_injected_failed_or_unknown_and_only_injected_counts() {
    let Some(mut fx) = fixture("answers", Policy::Allow) else {
        return;
    };
    let run = fx.run("answers-run", &["secret.use:api-token"]);
    let cases = [
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::SecretUnsafeBytes,
            ))),
            "FAILED",
        ),
        (
            Err(BrokerError::before_sending(BrokerFailure::Unreachable(
                Unreachable::Connect,
            ))),
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Unreachable(
                Unreachable::Io,
            ))),
            "UNKNOWN",
        ),
        (Ok(BrokerDelivery::Move), "UNKNOWN"),
    ];
    for (n, (answer, state)) in cases.into_iter().enumerate() {
        fx.fake.script.lock().unwrap().push_back(answer);
        let reply = fx.egress(&run, "api-token", "api.example.com:443", &format!("a-{n}"));
        let got = match reply {
            EgressReply::Failed { .. } => "FAILED",
            EgressReply::Unknown { .. } => "UNKNOWN",
            other => panic!("{other:?}"),
        };
        assert_eq!(got, state, "answer {n}");
    }
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_use"),
        0,
        "only a confirmed injection counts"
    );
    evidence("authority-secret-pipeline", "broker-refused", "FAILED");
    evidence(
        "authority-secret-pipeline",
        "broker-unreachable-before-send",
        "FAILED",
    );
    evidence(
        "authority-secret-pipeline",
        "broker-lost-after-send",
        "UNKNOWN",
    );
    evidence(
        "authority-secret-pipeline",
        "broker-wrong-answer",
        "UNKNOWN",
    );
    evidence(
        "authority-secret-pipeline",
        "use-count-only-injected",
        "counted",
    );
}

/// What a crash left: every injection row's state and failure, how many
/// handoffs the broker saw, whether any durable file holds the value, and the
/// use count.
type Aftermath = (Vec<(String, Option<String>)>, usize, bool, i64);

/// Stop the first secret use at `point`, as a crash would; restart on the same
/// store; return what is recorded, what the broker was asked, and whether
/// any durable file holds the value.
fn crash_at(point: CrashPoint) -> Option<Aftermath> {
    let hook: CrashHook = Arc::new(move |at| {
        if at == point {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    let mut fx = fixture_with(
        &format!("crash-{}", point.letter()),
        Policy::Allow,
        Some(hook),
    )?;
    let run = fx.run("crash-run", &["secret.use:api-token"]);
    let request = EgressRequest {
        handle: "api-token".to_owned(),
        origin: "api.example.com:443".to_owned(),
        key: IdempotencyKey::new("crash-use".to_owned()).unwrap(),
    };
    let (caller, session, epoch) = (fx.caller, fx.session.clone(), fx.epoch);
    let result = fx
        .authority()
        .secret_egress(&caller, &session, &run, epoch, &request);
    assert!(result.is_err(), "{point}: stopped");
    drop(fx.authority.take());
    // The restart: a new incarnation reconciles what the old one left.
    let state = fx.state();
    let mut restarted = start(&state, &fx.config, &fx.fake, None);
    // The run died with its incarnation: a replay is refused, never re-run.
    let caller = restarted.connect(AuthenticatedSubject::unix_uid(1000));
    let Reply::Done(epoch) = restarted.acquire_lease(&caller, &fx.session).unwrap() else {
        panic!("a lease")
    };
    let replay = restarted
        .secret_egress(&caller, &fx.session, &run, epoch, &request)
        .unwrap();
    assert_eq!(replay, EgressReply::Refused("UNKNOWN_RUN"), "{point}");
    let conn = fx.db();
    let mut statement = conn
        .prepare("SELECT state, failure FROM secret_injection ORDER BY intent_ms")
        .unwrap();
    let rows: Vec<(String, Option<String>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let uses: i64 = conn
        .query_row("SELECT count(*) FROM secret_use", [], |row| row.get(0))
        .unwrap();
    let plaintext = fx.durable_holds(&value(1, fx.api_value_len));
    Some((rows, fx.asked().len(), plaintext, uses))
}

#[test]
fn a_crash_anywhere_in_a_use_leaves_no_plaintext_and_never_injects_twice() {
    for point in CrashPoint::SECRET {
        let Some((rows, handed, plaintext, uses)) = crash_at(point) else {
            return;
        };
        assert!(!plaintext, "{point}: no durable plaintext");
        let states: Vec<&str> = rows.iter().map(|(s, _)| s.as_str()).collect();
        let (want_rows, want_handed, want_uses): (&[&str], usize, i64) = match point {
            // Nothing was committed: no intent, no read.
            CrashPoint::SecretBeforeMetadata | CrashPoint::SecretAfterMetadata => (&[], 0, 0),
            // An intent, and possibly a value read, but nothing handed over.
            // The restart cannot know that, so it records UNKNOWN.
            CrashPoint::SecretAfterIntent
            | CrashPoint::SecretAfterBackend
            | CrashPoint::SecretAfterRegister
            | CrashPoint::SecretAfterHandoff => (&["UNKNOWN"], 0, 0),
            // The broker received it; the outcome never became durable.
            CrashPoint::SecretAfterBroker | CrashPoint::SecretBeforeOutcome => (&["UNKNOWN"], 1, 0),
            // Durable before the crash: the answer was lost, not the record.
            CrashPoint::SecretAfterOutcome => (&["INJECTED"], 1, 1),
            other => panic!("{other} is not a secret point"),
        };
        assert_eq!(states, want_rows, "{point}");
        assert_eq!(handed, want_handed, "{point}: handed to the broker");
        assert_eq!(uses, want_uses, "{point}: counted");
        let case = match point {
            CrashPoint::SecretBeforeMetadata => "crash-R1-before-metadata",
            CrashPoint::SecretAfterMetadata => "crash-R2-after-metadata",
            CrashPoint::SecretAfterIntent => "crash-R3-after-intent",
            CrashPoint::SecretAfterBackend => "crash-R4-backend-returned",
            CrashPoint::SecretAfterRegister => "crash-R5-redaction-registered",
            CrashPoint::SecretAfterHandoff => "crash-R6-descriptor-created",
            CrashPoint::SecretAfterBroker => "crash-R8-broker-may-have-consumed",
            CrashPoint::SecretBeforeOutcome => "crash-R10-outcome-before-durable",
            _ => "crash-S9-durable-before-response",
        };
        evidence(
            "authority-secret-pipeline",
            case,
            &format!(
                "{}-no-plaintext-no-second-injection",
                want_rows.first().unwrap_or(&"none")
            ),
        );
    }
}

fn process_request(
    call: dwk_proto::dwkp::procops::ToolCallV3,
    key: &str,
) -> crate::state::ProcessRequest {
    crate::state::ProcessRequest::new(call, Some(IdempotencyKey::new(key.to_owned()).unwrap()))
        .unwrap()
}

fn no_call() -> dwk_proto::dwkp::procops::ToolCallV3 {
    dwk_proto::dwkp::procops::ToolCallV3 {
        fs_read: None,
        fs_list: None,
        fs_search: None,
        fs_stat: None,
        fs_write: None,
        fs_patch: None,
        fs_move: None,
        fs_delete: None,
        process_exec: None,
        process_status: None,
        process_kill: None,
    }
}

impl Fixture {
    /// Launch `/usr/bin/env` (the fake broker says it started), then ask its
    /// status, which the fake answers with `stdout` and `stderr`: the reply's
    /// streams, as the runtime would receive them.
    fn process_output(&mut self, stdout: &[u8], stderr: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use dwk_proto::dwkp::procops::{ProcessArgs, ProcessExecCall, ProcessStatusCall};
        use dwk_proto::wire::scalar::{HostPath, ProcessState, WorkspacePath};

        use crate::broker::{ProcessStartDelivery, ProcessStatusDelivery, StreamDelivery};
        use crate::state::{ProcessOutput, ProcessReply};

        let run = self.run("process-run", &["process.exec:*", "process.inspect:*"]);
        let generation = dwk_proto::brokerp::BrokerGeneration::new("ab".repeat(16)).unwrap();
        self.fake
            .script
            .lock()
            .unwrap()
            .push_back(Ok(BrokerDelivery::ProcessStarted(ProcessStartDelivery {
                generation: generation.clone(),
                state: ProcessState::Running,
                exit_code: None,
                signal: None,
            })));
        let launch = dwk_proto::dwkp::procops::ToolCallV3 {
            process_exec: Some(ProcessExecCall {
                executable: HostPath::new("/usr/bin/env".to_owned()).unwrap(),
                args: ProcessArgs::new(Vec::new()).unwrap(),
                cwd: Some(WorkspacePath::new("/workspace".to_owned()).unwrap()),
            }),
            ..no_call()
        };
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        let reply = crate::state::process::with_test_approval(|| {
            self.authority()
                .process_invoke(
                    &caller,
                    &session,
                    &run,
                    epoch,
                    &process_request(launch, "p-launch"),
                )
                .unwrap()
        });
        let ProcessReply::Done { output, .. } = reply else {
            panic!("launched: {reply:?}")
        };
        let ProcessOutput::Launched { process_id, .. } = *output else {
            panic!("a launch")
        };
        let stream = |bytes: &[u8]| StreamDelivery {
            content: bytes.to_vec(),
            observed: u64::try_from(bytes.len()).unwrap(),
            truncated: false,
        };
        self.fake
            .script
            .lock()
            .unwrap()
            .push_back(Ok(BrokerDelivery::ProcessStatus(ProcessStatusDelivery {
                state: ProcessState::Exited,
                exit_code: Some(0),
                signal: None,
                timed_out: false,
                stdout: stream(stdout),
                stderr: stream(stderr),
            })));
        let status = dwk_proto::dwkp::procops::ToolCallV3 {
            process_status: Some(ProcessStatusCall { process_id }),
            ..no_call()
        };
        let reply = self
            .authority()
            .process_invoke(
                &caller,
                &session,
                &run,
                epoch,
                &process_request(status, "p-status"),
            )
            .unwrap();
        let ProcessReply::Done { output, .. } = reply else {
            panic!("observed: {reply:?}")
        };
        let ProcessOutput::Observed { stdout, stderr, .. } = *output else {
            panic!("a status")
        };
        (stdout.content, stderr.content)
    }
}

#[test]
fn process_output_holding_the_value_is_redacted_on_both_streams_before_it_is_answered() {
    let Some(mut fx) = fixture("process-out", Policy::Allow) else {
        return;
    };
    let secret = value(1, fx.api_value_len);
    let (stdout, stderr) = fx.process_output(
        &[b"out ".as_slice(), &secret, b"\n"].concat(),
        &[b"\x00\xff".as_slice(), &secret].concat(),
    );
    assert!(stdout == b"out [redacted:api-token]\n", "stdout redacted");
    assert!(stderr == b"\x00\xff[redacted:api-token]", "stderr redacted");
    let audit = std::fs::read(fx.state().join("audit.log")).unwrap();
    assert!(contains(&audit, b"secret.redaction_hit"));
    assert!(!contains(&audit, &secret) && !contains(&audit, &secret[..12]));
    assert!(!fx.durable_holds(&secret), "no durable plaintext");
    evidence(
        "authority-secret-pipeline",
        "process-stdout-live-value",
        "placeholder",
    );
    evidence(
        "authority-secret-pipeline",
        "process-stderr-live-value",
        "placeholder",
    );
    evidence(
        "authority-secret-pipeline",
        "audit-redaction-hit-no-bytes",
        "handle-and-count",
    );
}

#[test]
fn a_crash_while_output_holds_the_value_before_redaction_leaves_no_plaintext() {
    // R9: the broker's answer — the target's output, holding the value — is
    // in the authority's memory and not yet redacted when it stops. The
    // launch crosses the same point first; the status is the second.
    let Some(mut fx) = fixture_with("crash-r9", Policy::Allow, None) else {
        return;
    };
    let secret = value(1, fx.api_value_len);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let crossings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let armed: CrashHook = Arc::new(move |at| {
            if at == CrashPoint::ToolAfterBroker
                && crossings.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
            {
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        });
        let state = fx.state();
        drop(fx.authority.take());
        fx.authority = Some(start(&state, &fx.config, &fx.fake, Some(armed)));
        let caller = fx.authority().connect(AuthenticatedSubject::unix_uid(1000));
        let session = fx.session.clone();
        let Reply::Done(epoch) = fx.authority().acquire_lease(&caller, &session).unwrap() else {
            panic!("a lease")
        };
        fx.caller = caller;
        fx.epoch = epoch;
        fx.process_output(&[b"out ".as_slice(), &secret].concat(), b"")
    }));
    // The stop, and not some other panic: the poisoned authority names R9's
    // crash point (the message carries no value).
    let payload = caught.expect_err("stopped at the crash point");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .unwrap_or_default();
    assert!(message.contains("ToolAfterBroker"), "{message}");
    drop(fx.authority.take());
    let restarted = start(&fx.state(), &fx.config, &fx.fake, None);
    drop(restarted);
    assert!(!fx.durable_holds(&secret), "no durable plaintext after R9");
    let audit = std::fs::read(fx.state().join("audit.log")).unwrap();
    assert!(!contains(&audit, &secret[..12]));
    evidence(
        "authority-secret-pipeline",
        "crash-R9-output-before-redaction",
        "no-plaintext",
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
