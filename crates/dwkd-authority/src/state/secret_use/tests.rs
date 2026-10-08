//! The mode A pipeline's state machine, in this crate's unit tests (ADR-0046
//! §§5, 17–20; ADR-0050 §8): a real authority — a store, a policy, a run
//! admitted with `secret.use:<handle>` and `network.https` — real values in
//! the **kernel keyring**, read by the real backend, and an **in-process fake
//! broker** that resolves, and reads the one-shot pipe each credential
//! exchange hands it. Mode A's consumer is `net.http`: every use here is a
//! hop. The fake proves what the authority hands over, when, and to which
//! origin; the real broker's render is measured by the broker's own suites,
//! the secret evidence and the `net.http` evidence.
//!
//! Every value is generated at run time. Assertions compare digests and
//! booleans, never values, so no failure can print one (ADR-0046 §22).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use std::collections::VecDeque;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::http::{
    ExchangeDisposition, HeaderCount, HttpExchangeDone, HttpHeader, HttpHeaderName,
    HttpHeaderValue, HttpLocation, HttpResolveDone, HttpStatus, NetAddress, NetAddresses,
    ResolveDisposition, ResponseHeaders,
};
use dwk_proto::dwkp::netops::{
    CredentialHandle, HttpHeader as CallHeader, HttpHeaderName as CallName,
    HttpHeaderValue as CallValue, HttpMethod, HttpUrlText, NetHttpCall, RequestHeaders,
    ToolRefusalReasonV4 as R,
};
use dwk_proto::dwkp::{self, DwkpMessage};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::{RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{AgentProfileName, ByteCount, Epoch, HexContent, IdempotencyKey};
use sha2::{Digest as _, Sha256};

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation, Unreachable,
};
use crate::capability::PrivacyClass;
use crate::scratch::Scratch;
use crate::secret::backend::{keychain_test_support, reads_on_this_thread};
use crate::secret::metadata;
use crate::state::net_http::{NetReply, NetRequest};
use crate::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, CrashHook, CrashPoint,
    HookAction, ManualClock, Mode, PolicySet, PolicySource, Reply, StartOptions, StartupConfig,
    WorkspaceId, WorkspaceSensitivity,
};

const START_MS: u64 = 1_758_000_000_000;

/// One line of the secret evidence (`make secret-broker-evidence`), printed
/// only after the assertions before it held.
fn evidence(suite: &str, case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// One line of the `net.http` evidence's credential rows, printed only after
/// the assertions before it held. A fake broker: not transport evidence.
fn net_evidence(case: &str, outcome: &str) {
    println!(
        "NET-EVIDENCE {{\"suite\":\"authority-net-credential\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
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
        "schema_version = 1\n\n[meta]\nname = \"m4e\"\n\n{rule}\n[[rule]]\nid = \"allow-https\"\neffect = \"ALLOW\"\nwhen.verb = \"network.https\"\nwhen.environment = \"host\"\n\n[[rule]]\nid = \"allow-host-process\"\neffect = \"ALLOW\"\nwhen.verb = [\"process.exec\", \"process.inspect\", \"process.signal\"]\nwhen.environment = \"host\"\n\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n"
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
    /// The exchange's host.
    host: Option<String>,
    /// The exchange's hop.
    hop: Option<u8>,
    /// The credential header the exchange named, if any.
    header: Option<String>,
    /// The digest of the pipe's content: the value, if it was the value.
    received: Option<[u8; 32]>,
    /// `secret_injection` INTENT rows when the order arrived.
    intents: i64,
}

#[derive(Debug, Default)]
struct Fake {
    /// Answers to exchanges and process operations, in order.
    script: Mutex<VecDeque<Result<BrokerDelivery, BrokerError>>>,
    asked: Mutex<Vec<Asked>>,
    store: Mutex<Option<PathBuf>>,
    /// Echo the credential back in the body and an `etag`, as a hostile or
    /// careless origin would.
    echo: std::sync::atomic::AtomicBool,
}

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: HttpHeaderName::new(name).unwrap(),
        value: HttpHeaderValue::new(value).unwrap(),
    }
}

/// A complete response.
fn response(
    status: u16,
    headers: Vec<HttpHeader>,
    location: Option<&str>,
    body: &[u8],
) -> Result<BrokerDelivery, BrokerError> {
    Ok(BrokerDelivery::HttpExchanged(HttpExchangeDone {
        disposition: ExchangeDisposition::Completed,
        status: Some(HttpStatus::new(status).unwrap()),
        headers: ResponseHeaders::new(headers).unwrap(),
        location: location.map(|l| HttpLocation::new(l).unwrap()),
        body: HexContent::from_bytes(body).unwrap(),
        truncated: false,
        headers_dropped: HeaderCount::new(0).unwrap(),
        cookies_dropped: HeaderCount::new(0).unwrap(),
        credential_echoes: HeaderCount::new(0).unwrap(),
        bytes_sent: ByteCount::new(100).unwrap(),
        bytes_received: ByteCount::new(100).unwrap(),
    }))
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
        let mut asked = Asked {
            operation: name,
            host: None,
            hop: None,
            header: None,
            received: None,
            intents,
        };
        match operation {
            // Every name resolves to one public address: what is judged here
            // is the authority's handling of the credential, not the guard.
            Operation::HttpResolve { .. } => {
                self.asked.lock().unwrap().push(asked);
                Ok(BrokerDelivery::HttpResolved(HttpResolveDone {
                    disposition: ResolveDisposition::Resolved,
                    addresses: NetAddresses::new(vec![NetAddress::from_address(Address::V4([
                        151, 101, 0, 223,
                    ]))])
                    .unwrap(),
                }))
            }
            Operation::HttpExchange { hop, secret } => {
                asked.host = Some(hop.host.as_str().to_owned());
                asked.hop = Some(hop.hop.get());
                asked.header = hop
                    .credential
                    .as_ref()
                    .map(|c| c.header_name.as_str().to_owned());
                let mut bytes = Vec::new();
                if let Some(secret) = secret {
                    let mut reader = std::io::PipeReader::from(secret.into_transfer_descriptor());
                    reader.read_to_end(&mut bytes).unwrap();
                    asked.received = Some(digest(&bytes));
                }
                self.asked.lock().unwrap().push(asked);
                if let Some(answer) = self.script.lock().unwrap().pop_front() {
                    return answer;
                }
                if self.echo.load(std::sync::atomic::Ordering::SeqCst) && !bytes.is_empty() {
                    let text = String::from_utf8(bytes.clone()).unwrap();
                    let echoed = [b"you sent ".as_slice(), &bytes, b"\n"].concat();
                    return response(
                        200,
                        vec![header("etag", &text), header("content-type", "text/plain")],
                        None,
                        &echoed,
                    );
                }
                response(200, vec![header("content-type", "text/plain")], None, b"ok")
            }
            _ => {
                self.asked.lock().unwrap().push(asked);
                self.script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Err(BrokerError::before_sending(
                        BrokerFailure::NotConfigured,
                    )))
            }
        }
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
/// * `api-token` — egress to `api.example.com:443` and
///   `mirror.example.com:443`, `Authorization: Bearer`;
/// * `fd-key` — `fd_at_spawn` only, for `/usr/bin/env`;
/// * `old-token` — revoked;
/// * `broken-header` — egress, whose value holds a line feed, in `X-Token`.
fn secrets_toml(tag: &str) -> String {
    format!(
        r#"schema_version = 1

[secrets.api-token]
type = "bearer"
storage = "keychain"
keychain = "{tag}-api"
origins = ["api.example.com:443", "mirror.example.com:443"]
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
            "network.https:*".to_owned(),
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
                    "network.https:*",
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

/// A `net.http` that names `handle`.
fn fetch_call(handle: &str, url: &str, follow: bool) -> NetHttpCall {
    NetHttpCall {
        method: HttpMethod::Get,
        url: HttpUrlText::new(url).unwrap(),
        headers: None,
        body: None,
        credential_handle: Some(CredentialHandle::new(handle).unwrap()),
        follow_redirects: follow,
        max_response_bytes: None,
    }
}

/// What a use came to, as M4e's API stated it: the reply, read together with
/// what the secret side recorded and audited.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Use {
    /// The value went with the request.
    Injected,
    /// Refused before any decision, for a reason that is not the credential's.
    Refused(R),
    /// The metadata, the selector, a gate or an obligation refused it — the
    /// secret side's typed reason. Nothing was read.
    Denied(String),
    /// Authorised and recorded, provably not sent: the recorded reason.
    Failed(String),
    /// May have been sent.
    Unknown,
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

    fn request(&mut self, run: &RunId, call: NetHttpCall, key: &str) -> NetReply {
        let request = NetRequest {
            call,
            key: Some(IdempotencyKey::new(key.to_owned()).unwrap()),
        };
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .net_invoke(&caller, &session, run, epoch, &request)
            .unwrap()
    }

    /// One mode A use: a `GET` of `https://<origin>/v1` naming `handle`.
    fn egress(&mut self, run: &RunId, handle: &str, origin: &str, key: &str) -> Use {
        let reply = self.request(
            run,
            fetch_call(handle, &format!("https://{origin}/v1"), false),
            key,
        );
        self.outcome(&reply)
    }

    fn outcome(&self, reply: &NetReply) -> Use {
        let last_injection = || {
            let conn = self.db();
            conn.query_row(
                "SELECT state, failure FROM secret_injection ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap()
        };
        match reply {
            NetReply::Done { .. } | NetReply::Failed { .. } => match last_injection() {
                (state, _) if state == "INJECTED" => Use::Injected,
                (state, Some(failure)) if state == "FAILED" => Use::Failed(failure),
                (state, _) if state == "UNKNOWN" => Use::Unknown,
                other => panic!("{other:?}"),
            },
            NetReply::Refused(_, R::CredentialUnavailable) | NetReply::Denied(_) => Use::Denied(
                self.last_denial()
                    .expect("the secret side audited its denial"),
            ),
            NetReply::Refused(_, reason) => Use::Refused(*reason),
            NetReply::Previewed(_) => panic!("an invocation was previewed"),
        }
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

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.state().join("kernel.db")).unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.db().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn asked(&self) -> Vec<Asked> {
        self.fake.asked.lock().unwrap().clone()
    }

    /// The exchanges the fake was asked to perform.
    fn exchanges(&self) -> Vec<Asked> {
        self.asked()
            .into_iter()
            .filter(|a| a.operation == "http.exchange")
            .collect()
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

const API: &str = "network.https:api.example.com";

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
    let run = fx.run("inject-run", &["secret.use:api-token", API]);
    let before = reads_on_this_thread();
    assert_eq!(
        fx.egress(&run, "api-token", "api.example.com", "use-1"),
        Use::Injected
    );
    assert_eq!(
        reads_on_this_thread() - before,
        1,
        "exactly one backend read"
    );
    let asked = fx.asked();
    let operations: Vec<&str> = asked.iter().map(|a| a.operation).collect();
    assert_eq!(operations, ["http.resolve", "http.exchange"]);
    assert_eq!(
        asked[1].intents, 1,
        "the intent was durable before the handoff"
    );
    assert!(
        asked[1].received == Some(fx.api),
        "the pipe held exactly the value"
    );
    assert_eq!(asked[1].header.as_deref(), Some("Authorization"));
    // The return path knows it, by its keyed fingerprint only.
    let handle = crate::secret::metadata::SecretHandle::new("api-token").unwrap();
    assert!(fx.authority().shared.secrets.indexed(&handle));
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM secret_injection WHERE state = 'INJECTED' AND mode = 'egress'"
        ),
        1
    );
    // The hop names its injection; the injection names the hop's origin.
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM net_hop JOIN secret_injection \
             ON net_hop.injection_id = secret_injection.invocation_id \
             WHERE secret_injection.consumer = 'api.example.com:443'"
        ),
        1
    );
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        1
    );

    // The same key: refused, as every reused key is. No read, no second
    // handoff, no second count.
    assert_eq!(
        fx.egress(&run, "api-token", "api.example.com", "use-1"),
        Use::Refused(R::IdempotencyKeyReused)
    );
    assert_eq!(reads_on_this_thread() - before, 1, "a replay reads nothing");
    assert_eq!(fx.exchanges().len(), 1, "a replay hands nothing over");
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        1
    );

    // A new key is a new use, counted once more.
    assert_eq!(
        fx.egress(&run, "api-token", "api.example.com", "use-2"),
        Use::Injected
    );
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
        "IDEMPOTENCY_KEY_REUSED-zero-reads-zero-handoff",
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
    let granted = fx.run(
        "deny-run",
        &[
            "secret.use:api-token",
            "secret.use:fd-key",
            "network.https:*",
        ],
    );
    let ungranted = fx.run("deny-other", &["network.https:*"]);
    let before = reads_on_this_thread();
    let cases: [(&RunId, &str, &str, Use); 10] = [
        // Origin binding over the endpoint grammar (ADR-0046 §15): the hop's
        // origin, from the canonical URL.
        (
            &granted,
            "api-token",
            "api.example.com.evil.test",
            Use::Denied("ORIGIN_NOT_ALLOWED".to_owned()),
        ),
        (
            &granted,
            "api-token",
            "evil-api.example.com",
            Use::Denied("ORIGIN_NOT_ALLOWED".to_owned()),
        ),
        (
            &granted,
            "api-token",
            "example.com",
            Use::Denied("ORIGIN_NOT_ALLOWED".to_owned()),
        ),
        (
            &granted,
            "api-token",
            "api.example.com:8443",
            Use::Denied("ORIGIN_NOT_ALLOWED".to_owned()),
        ),
        // Userinfo is never an origin: the URL itself is refused.
        (
            &granted,
            "api-token",
            "user@api.example.com",
            Use::Refused(R::UrlInvalid),
        ),
        (
            &granted,
            "api-token",
            "api.example.com@evil.test",
            Use::Refused(R::UrlInvalid),
        ),
        // The mode is the metadata's: an fd-only secret is never egressed.
        (
            &granted,
            "fd-key",
            "api.example.com",
            Use::Denied("INJECTION_MODE_UNAVAILABLE".to_owned()),
        ),
        // The index decides what a handle means.
        (
            &granted,
            "never-configured",
            "api.example.com",
            Use::Denied("NOT_CONFIGURED".to_owned()),
        ),
        (
            &granted,
            "old-token",
            "api.example.com",
            Use::Denied("REVOKED".to_owned()),
        ),
        // The capability gate: a run never granted the handle.
        (
            &ungranted,
            "api-token",
            "api.example.com",
            Use::Denied("CAPABILITY_NOT_GRANTED".to_owned()),
        ),
    ];
    for (n, (run, handle, origin, want)) in cases.iter().enumerate() {
        let got = fx.egress(run, handle, origin, &format!("deny-{n}"));
        assert_eq!(&got, want, "{handle} to {origin}");
    }
    // A handle that is not one cannot be spelled on the wire.
    assert!(CredentialHandle::new("Not-A-Handle").is_none());
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
        "URL_INVALID",
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
        let run = fx.run("gate-run", &["secret.use:api-token", API]);
        let before = reads_on_this_thread();
        assert_eq!(
            fx.egress(&run, "api-token", "api.example.com", "gate-1"),
            Use::Denied(want.to_owned())
        );
        assert_eq!(reads_on_this_thread() - before, 0);
        assert!(
            fx.asked().is_empty(),
            "nothing is resolved for a denied use"
        );
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
    let run = fx.run("revision-run", &["secret.use:api-token", API]);
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
                "api.example.com",
                &format!("rev-{revision}")
            ),
            Use::Denied(want.to_owned()),
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
        &["secret.use:api-token", "secret.use:broken-header", API],
    );
    // A line feed in a header-bound value: refused in the authority, never
    // sent.
    assert_eq!(
        fx.egress(&run, "broken-header", "api.example.com", "f-1"),
        Use::Failed("SECRET_MATERIAL_INVALID".to_owned())
    );
    // The item disappears from the keychain after start: a typed failure.
    let api_entry = fx.entries.0[0].clone();
    keychain_test_support::remove(&api_entry);
    assert_eq!(
        fx.egress(&run, "api-token", "api.example.com", "f-2"),
        Use::Failed("BACKEND_ITEM_MISSING".to_owned())
    );
    assert!(
        fx.exchanges().is_empty(),
        "neither reached the broker's exchange"
    );
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_injection WHERE state = 'FAILED'"),
        2
    );
    assert_eq!(
        fx.count("SELECT count(*) FROM net_request WHERE failure = 'CREDENTIAL_FAILED'"),
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
    let run = fx.run("answers-run", &["secret.use:api-token", API]);
    let cases = [
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::SecretUnsafeBytes,
            ))),
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::HttpConnectFailed,
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
        let got = match fx.egress(&run, "api-token", "api.example.com", &format!("a-{n}")) {
            Use::Failed(_) => "FAILED",
            Use::Unknown => "UNKNOWN",
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

#[test]
fn a_credential_goes_only_to_the_requests_own_origin_each_time_its_own_use() {
    let Some(mut fx) = fixture("binding", Policy::Allow) else {
        return;
    };
    let run = fx.run(
        "binding-run",
        &["secret.use:api-token", "network.https:*.example.com"],
    );
    // A same-origin redirect carries it again: a second decided, recorded
    // use, with its own pipe and its own read.
    let before = reads_on_this_thread();
    fx.fake
        .script
        .lock()
        .unwrap()
        .push_back(response(302, Vec::new(), Some("/v2"), b""));
    let reply = fx.request(
        &run,
        fetch_call("api-token", "https://api.example.com/v1", true),
        "same-origin",
    );
    assert!(matches!(&reply, NetReply::Done { .. }), "{reply:?}");
    let exchanges = fx.exchanges();
    assert_eq!(exchanges.len(), 2);
    assert!(exchanges.iter().all(|a| a.received == Some(fx.api)));
    assert_eq!(reads_on_this_thread() - before, 2, "a read per use");
    assert_eq!(
        fx.count("SELECT count(*) FROM secret_injection WHERE state = 'INJECTED'"),
        2
    );
    assert_eq!(
        fx.count("SELECT uses FROM secret_use WHERE handle = 'api-token'"),
        2
    );
    let NetReply::Done { output, .. } = &reply else {
        unreachable!()
    };
    assert!(output.hops.iter().all(|h| h.injected));
    // A cross-origin redirect never carries it — not even to an origin its
    // metadata names, because the request did not ask for it there.
    fx.fake.script.lock().unwrap().push_back(response(
        307,
        Vec::new(),
        Some("https://mirror.example.com/v1"),
        b"",
    ));
    let reply = fx.request(
        &run,
        fetch_call("api-token", "https://api.example.com/start", true),
        "cross-origin",
    );
    let NetReply::Done { output, .. } = &reply else {
        panic!("{reply:?}")
    };
    let hops: Vec<(String, bool)> = output
        .hops
        .iter()
        .map(|h| (h.host.as_str().to_owned(), h.injected))
        .collect();
    assert_eq!(
        hops,
        [
            ("api.example.com".to_owned(), true),
            ("mirror.example.com".to_owned(), false)
        ]
    );
    let last = fx.exchanges().pop().unwrap();
    assert_eq!(last.host.as_deref(), Some("mirror.example.com"));
    assert!(
        last.received.is_none() && last.header.is_none(),
        "no pipe, no header"
    );
    net_evidence("credential-same-origin-redirect", "own-use-own-pipe");
    net_evidence("credential-cross-origin-redirect", "never-attached");
}

#[test]
fn a_secret_in_the_request_is_refused_and_an_echoed_one_is_redacted() {
    let Some(mut fx) = fixture("echo", Policy::Allow) else {
        return;
    };
    let run = fx.run("echo-run", &["secret.use:api-token", API]);
    let secret = value(1, fx.api_value_len);
    let text = String::from_utf8(secret.clone()).unwrap();
    // The value anywhere in what would be sent: exfiltration, refused.
    let mut in_url = fetch_call(
        "api-token",
        &format!("https://api.example.com/?t={text}"),
        false,
    );
    in_url.credential_handle = None;
    let mut in_header = fetch_call("api-token", "https://api.example.com/", false);
    in_header.credential_handle = None;
    in_header.headers = RequestHeaders::new(vec![CallHeader {
        name: CallName::new("x-note").unwrap(),
        value: CallValue::new(text.as_str()).unwrap(),
    }]);
    let mut in_body = fetch_call("api-token", "https://api.example.com/", false);
    in_body.method = HttpMethod::Post;
    in_body.body = HexContent::from_bytes(&[b"{\"k\":\"".as_slice(), &secret, b"\"}"].concat());
    // The operator's credential header, whatever its spelling there.
    let mut reserved = fetch_call("api-token", "https://api.example.com/", false);
    reserved.headers = RequestHeaders::new(vec![CallHeader {
        name: CallName::new("x-token").unwrap(),
        value: CallValue::new("anything").unwrap(),
    }]);
    for (n, (call, want)) in [
        (in_url, R::SecretInRequest),
        (in_header, R::SecretInRequest),
        (in_body, R::SecretInRequest),
        (reserved, R::HeaderForbidden),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = fx.request(&run, call, &format!("refuse-{n}"));
        assert!(
            matches!(reply, NetReply::Refused(_, got) if got == want),
            "{n}: {reply:?}"
        );
    }
    assert!(fx.asked().is_empty());
    // An origin that echoes the value back: the answer holds a placeholder,
    // and a kept header that held it is dropped whole.
    fx.fake
        .echo
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let reply = fx.request(
        &run,
        fetch_call("api-token", "https://api.example.com/echo", false),
        "echo-1",
    );
    let NetReply::Done { output, .. } = &reply else {
        panic!("{reply:?}")
    };
    let body = output.body.to_bytes();
    assert!(!body.windows(secret.len()).any(|w| w == secret.as_slice()));
    assert!(body.windows(20).any(|w| w == b"[redacted:api-token]"));
    assert!(output.headers.iter().all(|h| h.name.as_str() != "etag"));
    assert!(
        output
            .headers
            .iter()
            .any(|h| h.name.as_str() == "content-type")
    );
    assert!(!fx.durable_holds(&secret), "no durable plaintext");
    let audit = std::fs::read(fx.state().join("audit.log")).unwrap();
    assert!(contains(&audit, b"secret.redaction_hit"));
    // The real broker redacts an echo of the hop's own credential before it
    // answers (D11) and says how often: nothing raw arrives, and the audit
    // still counts the handle's hits.
    fx.fake
        .echo
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut redacted = match response(
        200,
        vec![header("content-type", "text/plain")],
        None,
        b"you sent Bearer [redacted:api-token]\n",
    ) {
        Ok(BrokerDelivery::HttpExchanged(done)) => done,
        other => panic!("{other:?}"),
    };
    redacted.credential_echoes = HeaderCount::new(2).unwrap();
    fx.fake
        .script
        .lock()
        .unwrap()
        .push_back(Ok(BrokerDelivery::HttpExchanged(redacted)));
    let reply = fx.request(
        &run,
        fetch_call("api-token", "https://api.example.com/echo", false),
        "echo-2",
    );
    let NetReply::Done { output, .. } = &reply else {
        panic!("{reply:?}")
    };
    assert!(contains(&output.body.to_bytes(), b"[redacted:api-token]"));
    let audit = String::from_utf8(std::fs::read(fx.state().join("audit.log")).unwrap()).unwrap();
    assert!(
        audit.lines().any(|l| l.contains("secret.redaction_hit")
            && l.contains(r#""handle":"api-token""#)
            && l.contains(r#""count":2"#)),
        "the broker's count is the handle's hits"
    );
    net_evidence("secret-in-request-url", "SECRET_IN_REQUEST-zero-broker");
    net_evidence("secret-in-request-header", "SECRET_IN_REQUEST-zero-broker");
    net_evidence("secret-in-request-body", "SECRET_IN_REQUEST-zero-broker");
    net_evidence("runtime-sets-credential-header", "HEADER_FORBIDDEN");
    net_evidence("echoed-credential", "redacted-body-header-dropped");
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
    let run = fx.run("crash-run", &["secret.use:api-token", API]);
    let request = NetRequest {
        call: fetch_call("api-token", "https://api.example.com/v1", false),
        key: Some(IdempotencyKey::new("crash-use".to_owned()).unwrap()),
    };
    let (caller, session, epoch) = (fx.caller, fx.session.clone(), fx.epoch);
    let result = fx
        .authority()
        .net_invoke(&caller, &session, &run, epoch, &request);
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
        .net_invoke(&caller, &fx.session, &run, epoch, &request)
        .unwrap();
    assert!(
        matches!(replay, NetReply::Refused(_, R::UnknownRun)),
        "{point}: {replay:?}"
    );
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
    Some((rows, fx.exchanges().len(), plaintext, uses))
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
