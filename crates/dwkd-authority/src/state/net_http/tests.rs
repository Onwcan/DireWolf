//! `net.http`'s state machine in this crate's unit tests (ADR-0050 §§5–7,
//! 10–14): a real authority — a store, a policy, a run admitted with
//! `network.https` grants — and an **in-process fake broker** that answers
//! resolutions and exchanges from a script and records what it was asked and
//! what was durable when it was. A fake dials nothing and these tests do not
//! claim it does: they prove what the authority decides, pins, records,
//! refuses and never repeats. The real broker, real TLS origins and the
//! fixture resolver are `make net-http-evidence`'s.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::http::{
    ExchangeDisposition, HeaderCount, HttpExchangeDone, HttpHeader, HttpHeaderName,
    HttpHeaderValue, HttpLocation, HttpResolveDone, HttpStatus, NetAddress, NetAddresses,
    ResolveDisposition, ResponseHeaders,
};
use dwk_proto::dwkp::netops::{
    HttpHeader as CallHeader, HttpHeaderName as CallName, HttpHeaderValue as CallValue, HttpMethod,
    HttpUrlText, NetDecisionReason, NetHttpCall, RedirectEnd, RequestHeaders, ResponseLimit,
    ToolFailureReasonV4 as F, ToolRefusalReasonV4 as R,
};
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::{RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{AgentProfileName, ByteCount, Epoch, HexContent, IdempotencyKey};

use super::{NetBudget, NetReply, NetRequest};
use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation, Unreachable,
};
use crate::capability::PrivacyClass;
use crate::scratch::Scratch;
use crate::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, CrashHook, CrashPoint,
    HookAction, ManualClock, Mode, PolicySet, PolicySource, Reply, StartOptions, StartupConfig,
    WorkspaceId, WorkspaceSensitivity,
};

const START_MS: u64 = 1_758_000_000_000;

/// A message id counter: every message this suite sends is distinct.
static NEXT_MESSAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The pack every test but one runs under: a per-address rule first (so no
/// decision is final before resolution), novelty under taint, a denying
/// rule by name, a capping and an unenforceable obligation, and HTTPS
/// allowed on the host. **Not** a shipped pack.
const POLICY: &str = r#"schema_version = 1

[meta]
name = "m5c"

[[rule]]
id = "deny-listed-range"
effect = "DENY"
reason = "SANDBOX_ESCAPE_VECTOR"
when.verb = ["network.https"]
when.ip_in = ["93.184.216.0/24"]

[[rule]]
id = "approve-novel-when-tainted"
effect = "REQUIRE_APPROVAL"
reason = "UNTRUSTED_CONTENT_IN_RUN"
when.verb = ["network.https"]
when.taint_level = ["EXTERNAL_UNTRUSTED"]
when.destination_novel = true
approval.scope = "exact_action"
approval.ttl = "10m"
approval.max_uses = 1

[[rule]]
id = "deny-named-host"
effect = "DENY"
reason = "PROFILE_CEILING"
when.verb = ["network.https"]
when.host_matches = ["denied.example.com"]

[[rule]]
id = "capped"
effect = "ALLOW"
when.verb = ["network.https"]
when.host_matches = ["capped.example.com"]
obligations = ["max_output_bytes=16", "audit_level=full"]

[[rule]]
id = "unenforceable"
effect = "ALLOW"
when.verb = ["network.https"]
when.host_matches = ["sandboxed.example.com"]
obligations = ["network_deny"]

[[rule]]
id = "allow-https"
effect = "ALLOW"
when.verb = ["network.https"]
when.environment = "host"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// A pack whose network rules need no address: a denial is final before
/// resolution.
const ADDRESSLESS: &str = r#"schema_version = 1

[meta]
name = "m5c"

[[rule]]
id = "deny-named-host"
effect = "DENY"
reason = "PROFILE_CEILING"
when.verb = ["network.https"]
when.host_matches = ["denied.example.com"]

[[rule]]
id = "allow-https"
effect = "ALLOW"
when.verb = ["network.https"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

/// One line of the `net.http` pipeline's evidence (`make net-http-evidence`),
/// printed only after the assertions before it held. A fake broker: not
/// transport evidence.
fn evidence(case: &str, outcome: &str) {
    println!(
        "NET-EVIDENCE {{\"suite\":\"authority-net-pipeline\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// What the fake was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Asked {
    operation: &'static str,
    host: String,
    port: Option<u16>,
    hop: Option<u8>,
    method: Option<HttpMethod>,
    target: Option<String>,
    addresses: Vec<String>,
    headers: Vec<String>,
    body: usize,
    response_limit: Option<u32>,
    /// `net_hop` rows open when the order arrived: an exchange's own intent
    /// is durable before it is sent.
    open_hops: i64,
}

#[derive(Debug, Default)]
struct Fake {
    /// Per host, the answers in order; the last repeats. None: one public
    /// address.
    resolve: Mutex<BTreeMap<String, VecDeque<Result<HttpResolveDone, BrokerError>>>>,
    exchange: Mutex<VecDeque<Result<BrokerDelivery, BrokerError>>>,
    asked: Mutex<Vec<Asked>>,
    store: Mutex<Option<PathBuf>>,
    /// Advanced by this much at every exchange.
    clock: Mutex<Option<(Arc<ManualClock>, u64)>>,
}

fn addresses(list: &[[u8; 4]]) -> NetAddresses {
    NetAddresses::new(
        list.iter()
            .map(|o| NetAddress::from_address(Address::V4(*o)))
            .collect(),
    )
    .unwrap()
}

fn resolved(list: &[[u8; 4]]) -> Result<HttpResolveDone, BrokerError> {
    Ok(HttpResolveDone {
        disposition: ResolveDisposition::Resolved,
        addresses: addresses(list),
    })
}

fn unresolved(disposition: ResolveDisposition) -> Result<HttpResolveDone, BrokerError> {
    Ok(HttpResolveDone {
        disposition,
        addresses: addresses(&[]),
    })
}

/// What the fake answers an exchange with.
type Answer = Result<BrokerDelivery, BrokerError>;

/// A public address no rule names.
const PUBLIC: [u8; 4] = [151, 101, 0, 223];
/// A public address `deny-listed-range` names.
const LISTED: [u8; 4] = [93, 184, 216, 34];

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: HttpHeaderName::new(name).unwrap(),
        value: HttpHeaderValue::new(value).unwrap(),
    }
}

/// A complete response.
fn response(
    status: u16,
    headers: &[(&str, &str)],
    location: Option<&str>,
    body: &[u8],
) -> Result<BrokerDelivery, BrokerError> {
    Ok(BrokerDelivery::HttpExchanged(done(
        ExchangeDisposition::Completed,
        Some(status),
        headers,
        location,
        body,
    )))
}

fn done(
    disposition: ExchangeDisposition,
    status: Option<u16>,
    headers: &[(&str, &str)],
    location: Option<&str>,
    body: &[u8],
) -> HttpExchangeDone {
    HttpExchangeDone {
        disposition,
        status: status.map(|s| HttpStatus::new(s).unwrap()),
        headers: ResponseHeaders::new(headers.iter().map(|(n, v)| header(n, v)).collect()).unwrap(),
        location: location.map(|l| HttpLocation::new(l).unwrap()),
        body: HexContent::from_bytes(body).unwrap(),
        truncated: false,
        headers_dropped: HeaderCount::new(0).unwrap(),
        cookies_dropped: HeaderCount::new(2).unwrap(),
        credential_echoes: HeaderCount::new(0).unwrap(),
        bytes_sent: ByteCount::new(120).unwrap(),
        bytes_received: ByteCount::new(240).unwrap(),
    }
}

impl EffectBroker for Fake {
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        let open_hops = self.store.lock().unwrap().as_ref().map_or(0, |db| {
            rusqlite::Connection::open(db)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM net_hop WHERE state = 'INTENT'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        });
        let (_, operation) = order.into_parts();
        match operation {
            Operation::HttpResolve { host } => {
                self.asked.lock().unwrap().push(Asked {
                    operation: "http.resolve",
                    host: host.as_str().to_owned(),
                    port: None,
                    hop: None,
                    method: None,
                    target: None,
                    addresses: Vec::new(),
                    headers: Vec::new(),
                    body: 0,
                    response_limit: None,
                    open_hops,
                });
                let mut answers = self.resolve.lock().unwrap();
                let answer = match answers.get_mut(host.as_str()) {
                    Some(queue) if queue.len() > 1 => queue.pop_front().unwrap(),
                    Some(queue) => queue.front().cloned().unwrap(),
                    None => resolved(&[PUBLIC]),
                };
                answer.map(BrokerDelivery::HttpResolved)
            }
            Operation::HttpExchange { hop, secret } => {
                assert!(secret.is_none(), "these tests name no credential");
                self.asked.lock().unwrap().push(Asked {
                    operation: "http.exchange",
                    host: hop.host.as_str().to_owned(),
                    port: Some(hop.port.get()),
                    hop: Some(hop.hop.get()),
                    method: Some(hop.method),
                    target: Some(hop.target.as_str().to_owned()),
                    addresses: hop
                        .addresses
                        .iter()
                        .map(|a| a.as_str().to_owned())
                        .collect(),
                    headers: hop
                        .headers
                        .iter()
                        .map(|h| h.name.as_str().to_owned())
                        .collect(),
                    body: hop.body.as_ref().map_or(0, HexContent::byte_len),
                    response_limit: Some(hop.response_limit.get()),
                    open_hops,
                });
                if let Some((clock, step)) = self.clock.lock().unwrap().as_ref() {
                    clock.advance(*step);
                }
                self.exchange
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| {
                        response(200, &[("content-type", "text/plain")], None, b"hello")
                    })
            }
            other => panic!("not a network operation: {}", other.name()),
        }
    }
}

impl Fake {
    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }

    fn operations(&self) -> Vec<&'static str> {
        self.asked().iter().map(|a| a.operation).collect()
    }

    fn answer(&self, host: &str, answers: Vec<Result<HttpResolveDone, BrokerError>>) {
        self.resolve
            .lock()
            .unwrap()
            .insert(host.to_owned(), answers.into());
    }

    fn then(&self, reply: Result<BrokerDelivery, BrokerError>) {
        self.exchange.lock().unwrap().push_back(reply);
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

struct Fixture {
    scratch: Scratch,
    authority: Option<Authority>,
    fake: Arc<Fake>,
    clock: Arc<ManualClock>,
    caller: CallerContext,
    session: SessionId,
    epoch: Epoch,
    config: StartupConfig,
}

fn config(policy: &str, budget: NetBudget) -> StartupConfig {
    let mut config = StartupConfig::new(
        PolicySet {
            profile: "m5c".to_owned(),
            sources: vec![PolicySource {
                name: "m5c.toml".to_owned(),
                text: policy.to_owned(),
            }],
        },
        Mode::Balanced,
        vec!["network.https:*".to_owned(), "fs.read:*".to_owned()],
    );
    config.net_budget = budget;
    config
}

fn start(
    state: &Path,
    config: &StartupConfig,
    fake: &Arc<Fake>,
    clock: &Arc<ManualClock>,
    hook: Option<CrashHook>,
) -> Authority {
    let broker: Arc<dyn EffectBroker> = fake.clone();
    let clock: Arc<dyn crate::state::Clock> = clock.clone();
    Authority::start(
        state,
        config,
        StartOptions {
            clock,
            crash_hook: hook,
            broker: Some(broker),
        },
    )
    .unwrap()
    .0
}

fn fixture_with(policy: &str, budget: NetBudget, hook: Option<CrashHook>) -> Fixture {
    let scratch = Scratch::new("net-http");
    let root = scratch.path().join("ws");
    std::fs::create_dir_all(&root).unwrap();
    let config = config(policy, budget);
    let fake = Arc::new(Fake::default());
    let clock = Arc::new(ManualClock::new(START_MS));
    let state = scratch.path().join("state");
    let mut authority = start(&state, &config, &fake, &clock, hook);
    *fake.store.lock().unwrap() = Some(state.join("kernel.db"));
    let workspace = WorkspaceId::new("ws").unwrap();
    let session = SessionId::from_uuid(uuid(1)).unwrap();
    {
        let mut operator = authority.operator();
        operator
            .install_agent_profile(&AgentProfileSpec {
                name: AgentProfileName::new("operator").unwrap(),
                declared: vec!["network.https:*".to_owned(), "fs.read:*".to_owned()],
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
    Fixture {
        scratch,
        authority: Some(authority),
        fake,
        clock,
        caller,
        session,
        epoch,
        config,
    }
}

fn fixture() -> Fixture {
    fixture_with(POLICY, NetBudget::default(), None)
}

fn call(method: HttpMethod, url: &str) -> NetHttpCall {
    NetHttpCall {
        method,
        url: HttpUrlText::new(url).unwrap(),
        headers: None,
        body: None,
        credential_handle: None,
        follow_redirects: false,
        max_response_bytes: None,
    }
}

fn following(mut call: NetHttpCall) -> NetHttpCall {
    call.follow_redirects = true;
    call
}

fn with_header(mut call: NetHttpCall, name: &str, value: &str) -> NetHttpCall {
    call.headers = RequestHeaders::new(vec![CallHeader {
        name: CallName::new(name).unwrap(),
        value: CallValue::new(value).unwrap(),
    }]);
    call
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

    fn invoke(&mut self, run: &RunId, call: NetHttpCall, key: &str) -> NetReply {
        let request = NetRequest {
            call,
            key: Some(IdempotencyKey::new(key.to_owned()).unwrap()),
        };
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .net_invoke(&caller, &session, run, epoch, &request)
            .unwrap()
    }

    fn preview(&mut self, run: &RunId, call: NetHttpCall) -> NetReply {
        let request = NetRequest { call, key: None };
        let (caller, session, epoch) = (self.caller, self.session.clone(), self.epoch);
        self.authority()
            .net_preview(&caller, &session, run, epoch, &request)
            .unwrap()
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.state().join("kernel.db")).unwrap()
    }

    fn rows(&self, sql: &str) -> Vec<String> {
        let conn = self.db();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.db().query_row(sql, [], |row| row.get(0)).unwrap()
    }

    /// A version-4 tool message for `run`.
    fn v4(&self, run: &RunId, schema: &str, key: Option<&str>, payload: &str) -> DwkpMessage {
        let n = NEXT_MESSAGE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        decode(&format!(
            r#"{{"v":1,"id":"msg_{id}","type":"request","schema":"{schema}","schema_version":4,"ts":"2026-09-21T10:00:02.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
            id = encode_uuid(uuid(20_000 + n)),
            session = self.session.as_str(),
            run = run.as_str(),
            epoch = self.epoch.get(),
            key = key.map_or_else(String::new, |k| format!(r#","idempotency_key":"{k}""#)),
        ))
    }

    /// Every audit record's event, in order.
    fn events(&self) -> Vec<String> {
        crate::state::read_audit_log(&self.state().join("audit.log"))
            .unwrap()
            .iter()
            .map(|r| r.event().to_owned())
            .collect()
    }
}

fn denied_reason(reply: &NetReply) -> NetDecisionReason {
    match reply {
        NetReply::Denied(plan) => plan
            .net
            .reported()
            .map(|g| g.reason(plan.net.resolved))
            .unwrap(),
        other => panic!("not a denial: {other:?}"),
    }
}

fn output(reply: &NetReply) -> &dwk_proto::dwkp::netops::NetHttpResult {
    match reply {
        NetReply::Done { output, .. } => output,
        other => panic!("not a result: {other:?}"),
    }
}

const GRANT: &str = "network.https:*.example.com";

#[test]
fn a_request_is_decided_resolved_guarded_recorded_and_only_then_sent() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let reply = fx.invoke(
        &run,
        with_header(
            call(HttpMethod::Get, "https://api.example.com/v1/items?q=1"),
            "accept",
            "application/json",
        ),
        "k1",
    );
    let out = output(&reply);
    assert_eq!(out.status.get(), 200);
    assert_eq!(out.body.to_bytes(), b"hello");
    assert_eq!(out.hops.len(), 1);
    assert!(!out.hops.as_slice()[0].injected);
    assert_eq!(out.redirect_ended, None);
    let asked = fx.fake.asked();
    assert_eq!(fx.fake.operations(), ["http.resolve", "http.exchange"]);
    assert_eq!(asked[0].host, "api.example.com");
    assert_eq!(
        asked[0].open_hops, 0,
        "nothing is recorded before the guard"
    );
    let exchange = &asked[1];
    assert_eq!(exchange.open_hops, 1, "the hop's intent was durable first");
    assert_eq!(exchange.addresses, ["976500df".to_owned()]);
    assert_eq!(exchange.target.as_deref(), Some("/v1/items?q=1"));
    assert_eq!(exchange.headers, ["accept"]);
    assert_eq!(exchange.port, Some(443));
    assert_eq!(exchange.response_limit, Some(262_144));
    assert_eq!(
        fx.rows("SELECT state FROM net_request"),
        ["COMPLETED".to_owned()]
    );
    assert_eq!(
        fx.rows("SELECT state || ':' || disposition || ':' || tls_established FROM net_hop"),
        ["COMPLETED:COMPLETED:1".to_owned()]
    );
    // The answer taints the run before it is delivered.
    let events = fx.events();
    let at = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(at("net.http.resolved") < at("net.http.intent"));
    assert!(at("net.http.intent") < at("net.http.hop"));
    assert!(at("run.taint_raised") < at("net.http.outcome"));
    // No path, no query in the durable state: the URL is its digest.
    for file in ["kernel.db", "audit.log"] {
        let bytes = std::fs::read(fx.state().join(file)).unwrap();
        assert!(!bytes.windows(9).any(|w| w == b"/v1/items"), "{file}");
    }
    evidence("order-guard-intent-exchange", "ordered");
    evidence("url-digest-only-in-audit", "no-path-no-query");
}

#[test]
fn nothing_is_resolved_for_a_host_no_grant_covers() {
    let mut fx = fixture();
    let run = fx.run("r1", &["network.https:api.example.com:443?methods=GET"]);
    for (n, (method, url)) in [
        (HttpMethod::Get, "https://evil.test/x"),
        (HttpMethod::Get, "https://api.example.com:8443/x"),
        (HttpMethod::Get, "https://other.example.com/x"),
        (HttpMethod::Post, "https://api.example.com/x"),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = fx.invoke(&run, call(method, url), &format!("k{n}"));
        assert_eq!(
            denied_reason(&reply),
            NetDecisionReason::NoCapability,
            "{url}"
        );
    }
    assert!(fx.fake.asked().is_empty(), "no resolution, no exchange");
    assert_eq!(fx.count("SELECT count(*) FROM net_request"), 0);
    evidence("no-resolution-without-grant", "NO_CAPABILITY-zero-broker");
}

#[test]
fn a_decision_that_needs_no_address_and_denies_resolves_nothing() {
    let mut fx = fixture_with(ADDRESSLESS, NetBudget::default(), None);
    let run = fx.run("r1", &[GRANT]);
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://denied.example.com/"),
        "k1",
    );
    assert_eq!(denied_reason(&reply), NetDecisionReason::DeniedByRule);
    assert!(fx.fake.asked().is_empty());
    evidence(
        "final-denial-before-resolution",
        "DENIED_BY_RULE-zero-broker",
    );
}

#[test]
fn every_pinned_address_must_pass_policy_and_a_preview_says_it_has_none() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    // A preview cannot know the address: the rule that needs it is
    // unevaluable, and nothing is resolved.
    let preview = fx.preview(&run, call(HttpMethod::Get, "https://api.example.com/"));
    let NetReply::Previewed(plan) = &preview else {
        panic!("{preview:?}")
    };
    assert!(!plan.permits());
    assert_eq!(
        plan.net.reported().unwrap().reason(false),
        NetDecisionReason::UnresolvedPolicyInput
    );
    assert!(fx.fake.asked().is_empty());
    // One listed address among the answer denies the whole request.
    fx.fake
        .answer("api.example.com", vec![resolved(&[PUBLIC, LISTED])]);
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://api.example.com/"),
        "k1",
    );
    assert_eq!(denied_reason(&reply), NetDecisionReason::DeniedByRule);
    assert_eq!(fx.fake.operations(), ["http.resolve"]);
    let NetReply::Denied(plan) = &reply else {
        unreachable!()
    };
    assert_eq!(plan.net.gates.len(), 2, "a gate per pinned address");
    assert!(plan.net.gates[0].permits() && !plan.net.gates[1].permits());
    evidence("preview-without-address", "UNRESOLVED_POLICY_INPUT");
    evidence("policy-per-pinned-address", "DENIED_BY_RULE-no-exchange");
}

#[test]
fn the_authority_judges_every_answer_again_and_refuses_what_the_broker_says_cannot_resolve() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let cases: [(&str, Result<HttpResolveDone, BrokerError>, R); 8] = [
        // A broker that says "resolved" to an address the guard blocks.
        (
            "lying.example.com",
            resolved(&[[127, 0, 0, 1]]),
            R::AddressBlocked,
        ),
        (
            "metadata-ip.example.com",
            resolved(&[[169, 254, 169, 254]]),
            R::AddressBlocked,
        ),
        (
            "mixed.example.com",
            resolved(&[PUBLIC, [10, 0, 0, 1]]),
            R::AddressMixed,
        ),
        (
            "blocked.example.com",
            unresolved(ResolveDisposition::AddressBlocked),
            R::AddressBlocked,
        ),
        (
            "named.example.com",
            unresolved(ResolveDisposition::NameBlocked),
            R::AddressBlocked,
        ),
        (
            "rebind.example.com",
            unresolved(ResolveDisposition::AddressMixed),
            R::AddressMixed,
        ),
        (
            "gone.example.com",
            unresolved(ResolveDisposition::ResolutionFailed),
            R::ResolutionFailed,
        ),
        (
            "slow.example.com",
            unresolved(ResolveDisposition::ResolutionTimeout),
            R::ResolutionTimeout,
        ),
    ];
    for (n, (host, answer, want)) in cases.into_iter().enumerate() {
        fx.fake.answer(host, vec![answer]);
        let reply = fx.invoke(
            &run,
            call(HttpMethod::Get, &format!("https://{host}/")),
            &format!("k{n}"),
        );
        assert!(
            matches!(reply, NetReply::Refused(_, got) if got == want),
            "{host}: {reply:?}"
        );
    }
    assert!(
        fx.fake
            .asked()
            .iter()
            .all(|a| a.operation == "http.resolve"),
        "no blocked answer reaches an exchange"
    );
    assert_eq!(fx.count("SELECT count(*) FROM net_request"), 0);
    // A broker that cannot be reached: nothing to resolve with.
    fx.fake.answer(
        "down.example.com",
        vec![Err(BrokerError::before_sending(
            BrokerFailure::Unreachable(Unreachable::Connect),
        ))],
    );
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://down.example.com/"),
        "k-down",
    );
    assert!(matches!(reply, NetReply::Refused(_, R::NetworkUnavailable)));
    evidence("guard-loopback-answer", "ADDRESS_BLOCKED");
    evidence("guard-metadata-ip-answer", "ADDRESS_BLOCKED");
    evidence("guard-mixed-answer", "ADDRESS_MIXED");
    evidence("resolution-failed", "RESOLUTION_FAILED");
    evidence("resolution-timeout", "RESOLUTION_TIMEOUT");
}

#[test]
fn a_malformed_url_a_metadata_name_or_a_forbidden_header_is_refused_before_anything() {
    let mut fx = fixture();
    let run = fx.run("r1", &["network.https:*"]);
    let cases = [
        (
            call(HttpMethod::Get, "http://api.example.com/"),
            R::PlaintextUnsupported,
        ),
        (
            call(HttpMethod::Get, "https://user@api.example.com/"),
            R::UrlInvalid,
        ),
        (call(HttpMethod::Get, "https://127.0.0.1/"), R::UrlInvalid),
        (call(HttpMethod::Get, "https://2130706433/"), R::UrlInvalid),
        (
            call(HttpMethod::Get, "https://api.example.com/%2e%2e/admin"),
            R::UrlInvalid,
        ),
        (
            call(
                HttpMethod::Get,
                "https://api.example.com.evil.test@other.test/",
            ),
            R::UrlInvalid,
        ),
        (
            call(HttpMethod::Get, "https://metadata.google.internal/"),
            R::AddressBlocked,
        ),
        (
            with_header(
                call(HttpMethod::Get, "https://api.example.com/"),
                "authorization",
                "x",
            ),
            R::HeaderForbidden,
        ),
        (
            with_header(
                call(HttpMethod::Get, "https://api.example.com/"),
                "cookie",
                "a=b",
            ),
            R::HeaderForbidden,
        ),
        (
            with_header(
                call(HttpMethod::Get, "https://api.example.com/"),
                "x-forwarded-for",
                "1.2.3.4",
            ),
            R::HeaderForbidden,
        ),
    ];
    for (n, (call, want)) in cases.into_iter().enumerate() {
        let url = call.url.as_str().to_owned();
        let reply = fx.invoke(&run, call, &format!("k{n}"));
        assert!(
            matches!(reply, NetReply::Refused(_, got) if got == want),
            "{url}: {reply:?}"
        );
    }
    let mut body = call(HttpMethod::Get, "https://api.example.com/");
    body.body = HexContent::from_bytes(b"x");
    assert!(matches!(
        fx.invoke(&run, body, "k-body"),
        NetReply::Refused(_, R::BodyNotPermitted)
    ));
    assert!(fx.fake.asked().is_empty());
    evidence(
        "metadata-name-before-resolution",
        "ADDRESS_BLOCKED-zero-broker",
    );
    evidence("userinfo-and-literals", "URL_INVALID-zero-broker");
    evidence("runtime-credential-header", "HEADER_FORBIDDEN-zero-broker");
}

#[test]
fn a_redirect_is_reported_unfollowed_unless_asked_and_then_decided_from_the_start() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    // Not asked to follow: the 3xx is the answer, its Location canonical —
    // and one with no single reading (a dot segment) is not returned at all.
    let locations = |reply: &NetReply| -> Vec<String> {
        output(reply)
            .headers
            .iter()
            .filter(|h| h.name.as_str() == "location")
            .map(|h| h.value.as_str().to_owned())
            .collect()
    };
    fx.fake.then(response(302, &[], Some("b?x=1"), b""));
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://api.example.com/v1/a"),
        "k1",
    );
    let out = output(&reply);
    assert_eq!(out.status.get(), 302);
    assert_eq!(out.redirect_ended, Some(RedirectEnd::NotFollowed));
    assert_eq!(locations(&reply), ["https://api.example.com:443/v1/b?x=1"]);
    fx.fake.then(response(302, &[], Some("../b"), b""));
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://api.example.com/v1/a"),
        "k1b",
    );
    assert_eq!(
        output(&reply).redirect_ended,
        Some(RedirectEnd::NotFollowed)
    );
    assert!(locations(&reply).is_empty());
    // Same origin: pinned, never resolved again, the caller's headers kept.
    fx.fake.answer(
        "api.example.com",
        vec![resolved(&[PUBLIC]), resolved(&[[127, 0, 0, 1]])],
    );
    fx.fake.then(response(301, &[], Some("/next"), b""));
    let before = fx.fake.asked().len();
    let reply = fx.invoke(
        &run,
        with_header(
            following(call(HttpMethod::Get, "https://api.example.com/first")),
            "accept",
            "*/*",
        ),
        "k2",
    );
    let out = output(&reply);
    assert_eq!(out.status.get(), 200);
    assert_eq!(out.hops.len(), 2);
    let asked = fx.fake.asked()[before..].to_vec();
    let since: Vec<_> = asked.iter().map(|a| (a.operation, a.hop)).collect();
    assert_eq!(
        since,
        [
            ("http.resolve", None),
            ("http.exchange", Some(1)),
            ("http.exchange", Some(2))
        ],
        "one resolution for the request: the rebinding second answer is never asked for"
    );
    assert_eq!(asked[2].addresses, asked[1].addresses);
    assert_eq!(asked[2].headers, ["accept"]);
    assert_eq!(asked[2].target.as_deref(), Some("/next"));
    // Another origin: decided, resolved, and sent without the caller's
    // headers. (Under a pack with no taint rule: this run is tainted now,
    // and `POLICY` would rightly deny it a new origin.)
    let mut fx = fixture_with(ADDRESSLESS, NetBudget::default(), None);
    let run = fx.run("r1", &[GRANT]);
    fx.fake.then(response(
        307,
        &[],
        Some("https://cdn.example.com/blob"),
        b"",
    ));
    let reply = fx.invoke(
        &run,
        with_header(
            following(call(HttpMethod::Get, "https://www.example.com/")),
            "accept",
            "*/*",
        ),
        "k3",
    );
    assert_eq!(output(&reply).hops.len(), 2);
    let asked = fx.fake.asked();
    let last = asked.last().unwrap();
    assert_eq!(last.host, "cdn.example.com");
    assert!(last.headers.is_empty(), "no caller header crosses origins");
    evidence("redirect-not-followed", "NOT_FOLLOWED-location-canonical");
    evidence("redirect-same-origin-pinned", "no-second-resolution");
    evidence("redirect-cross-origin-headers", "caller-headers-dropped");
}

#[test]
fn every_way_a_redirect_chain_can_end_is_typed_and_sends_nothing_further() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT, "network.https:example.com"]);
    let base = "https://api.example.com/a";
    let cases: Vec<(NetHttpCall, Vec<Answer>, RedirectEnd, usize)> = vec![
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("http://api.example.com/"), b"")],
            RedirectEnd::RedirectTargetInvalid,
            1,
        ),
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("https://127.0.0.1/"), b"")],
            RedirectEnd::RedirectTargetInvalid,
            1,
        ),
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("/a"), b"")],
            RedirectEnd::RedirectLoop,
            1,
        ),
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("https://evil.test/"), b"")],
            RedirectEnd::HopDenied,
            1,
        ),
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("https://metadata.goog/"), b"")],
            RedirectEnd::AddressBlocked,
            1,
        ),
        (
            following(call(HttpMethod::Get, base)),
            vec![response(302, &[], Some("https://denied.example.com/"), b"")],
            RedirectEnd::HopDenied,
            1,
        ),
        {
            let mut post = following(call(HttpMethod::Post, base));
            post.body = HexContent::from_bytes(b"{}");
            (
                post,
                vec![response(307, &[], Some("/b"), b"")],
                RedirectEnd::RedirectWouldResendBody,
                1,
            )
        },
        (
            following(call(HttpMethod::Get, base)),
            (1..=6)
                .map(|n| response(302, &[], Some(&format!("/hop{n}")), b""))
                .collect(),
            RedirectEnd::RedirectLimit,
            6,
        ),
    ];
    for (n, (call, script, want, exchanges)) in cases.into_iter().enumerate() {
        let before = fx
            .fake
            .asked()
            .iter()
            .filter(|a| a.operation == "http.exchange")
            .count();
        for answer in script {
            fx.fake.then(answer);
        }
        let reply = fx.invoke(&run, call, &format!("k{n}"));
        let out = output(&reply);
        assert_eq!(out.redirect_ended, Some(want), "case {n}");
        let sent = fx
            .fake
            .asked()
            .iter()
            .filter(|a| a.operation == "http.exchange")
            .count()
            - before;
        assert_eq!(sent, exchanges, "case {n}: nothing past the end is sent");
        fx.fake.exchange.lock().unwrap().clear();
    }
    // A blocked or mixed redirect target: resolved, judged, never sent to.
    for (n, (answer, want)) in [
        (resolved(&[[10, 1, 2, 3]]), RedirectEnd::AddressBlocked),
        (
            resolved(&[PUBLIC, [192, 168, 0, 1]]),
            RedirectEnd::AddressMixed,
        ),
        (
            unresolved(ResolveDisposition::ResolutionFailed),
            RedirectEnd::ResolutionFailed,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let host = format!("t{n}.example.com");
        fx.fake.answer(&host, vec![answer]);
        fx.fake
            .then(response(302, &[], Some(&format!("https://{host}/")), b""));
        let reply = fx.invoke(
            &run,
            following(call(HttpMethod::Get, base)),
            &format!("b{n}"),
        );
        assert_eq!(output(&reply).redirect_ended, Some(want));
        assert!(
            fx.fake
                .asked()
                .iter()
                .all(|a| !(a.operation == "http.exchange" && a.host == host))
        );
    }
    // 303 turns a POST into a GET without its body.
    let mut post = following(call(HttpMethod::Post, base));
    post.body = HexContent::from_bytes(b"{\"a\":1}");
    fx.fake.then(response(303, &[], Some("/done"), b""));
    assert_eq!(output(&fx.invoke(&run, post, "k-303")).status.get(), 200);
    let last = fx.fake.asked().last().cloned().unwrap();
    assert_eq!((last.method, last.body), (Some(HttpMethod::Get), 0));
    assert_eq!(
        fx.count("SELECT count(*) FROM net_request WHERE state != 'COMPLETED'"),
        0
    );
    evidence("redirect-downgrade", "REDIRECT_TARGET_INVALID");
    evidence("redirect-loop", "REDIRECT_LOOP");
    evidence("redirect-ungranted-host", "HOP_DENIED-not-resolved");
    evidence("redirect-metadata-name", "ADDRESS_BLOCKED-not-resolved");
    evidence("redirect-policy-denied", "HOP_DENIED");
    evidence("redirect-307-with-body", "REDIRECT_WOULD_RESEND_BODY");
    evidence("redirect-sixth-hop", "REDIRECT_LIMIT");
    evidence("redirect-blocked-target", "ADDRESS_BLOCKED-not-sent");
    evidence("redirect-mixed-target", "ADDRESS_MIXED-not-sent");
    evidence("redirect-303-to-get", "GET-without-body");
}

#[test]
fn a_grant_for_one_origin_does_not_authorise_another_and_a_spent_grant_ends_the_chain() {
    let mut fx = fixture();
    let run = fx.run("r1", &["network.https:api.example.com?max_requests=1"]);
    fx.fake.then(response(302, &[], Some("/again"), b""));
    let reply = fx.invoke(
        &run,
        following(call(HttpMethod::Get, "https://api.example.com/")),
        "k1",
    );
    let out = output(&reply);
    assert_eq!(out.redirect_ended, Some(RedirectEnd::HopDenied));
    assert_eq!(out.status.get(), 302);
    // The grant's one request is spent, for this run, for good.
    let again = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://api.example.com/"),
        "k2",
    );
    assert_eq!(denied_reason(&again), NetDecisionReason::NoCapability);
    evidence(
        "per-hop-reauthorisation-max-requests",
        "HOP_DENIED-then-NO_CAPABILITY",
    );
}

#[test]
fn budgets_are_charged_before_sending_never_refilled_and_survive_a_restart() {
    let budget = NetBudget {
        requests: 2,
        ..NetBudget::default()
    };
    let mut fx = fixture_with(POLICY, budget, None);
    let run = fx.run("r1", &[GRANT]);
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/1"),
            "k1"
        ),
        NetReply::Done { .. }
    ));
    // The second request's redirect would be the third hop.
    fx.fake.then(response(302, &[], Some("/3"), b""));
    let reply = fx.invoke(
        &run,
        following(call(HttpMethod::Get, "https://api.example.com/2")),
        "k2",
    );
    assert_eq!(
        output(&reply).redirect_ended,
        Some(RedirectEnd::BudgetExhausted)
    );
    let sent = fx
        .fake
        .asked()
        .iter()
        .filter(|a| a.operation == "http.exchange")
        .count();
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/4"),
            "k3"
        ),
        NetReply::Refused(_, R::BudgetExhausted)
    ));
    assert_eq!(
        fx.fake
            .asked()
            .iter()
            .filter(|a| a.operation == "http.exchange")
            .count(),
        sent
    );
    // A restart refills nothing.
    drop(fx.authority.take());
    let state = fx.state();
    let mut restarted = start(&state, &fx.config, &fx.fake, &fx.clock, None);
    let caller = restarted.connect(AuthenticatedSubject::unix_uid(1000));
    let Reply::Done(epoch) = restarted.acquire_lease(&caller, &fx.session).unwrap() else {
        panic!("a lease")
    };
    fx.authority = Some(restarted);
    fx.caller = caller;
    fx.epoch = epoch;
    let run = fx.run("r2", &[GRANT]);
    // A new run has its own budget; the old run's spend is still recorded.
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/5"),
            "k5"
        ),
        NetReply::Done { .. }
    ));
    assert_eq!(fx.count("SELECT count(*) FROM net_hop"), 3);
    // The origin and byte budgets refuse in the same way.
    let mut fx = fixture_with(
        POLICY,
        NetBudget {
            origins: 1,
            ..NetBudget::default()
        },
        None,
    );
    let run = fx.run("r1", &[GRANT]);
    fx.fake
        .then(response(302, &[], Some("https://cdn.example.com/"), b""));
    let reply = fx.invoke(
        &run,
        following(call(HttpMethod::Get, "https://api.example.com/")),
        "k1",
    );
    assert_eq!(
        output(&reply).redirect_ended,
        Some(RedirectEnd::BudgetExhausted)
    );
    let mut fx = fixture_with(
        POLICY,
        NetBudget {
            bytes_in: 1024,
            ..NetBudget::default()
        },
        None,
    );
    let run = fx.run("r1", &[GRANT]);
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/"),
            "k1"
        ),
        NetReply::Refused(_, R::BudgetExhausted)
    ));
    assert!(
        fx.fake.asked().is_empty(),
        "a spent budget resolves nothing"
    );
    evidence("budget-requests", "BUDGET_EXHAUSTED-before-send");
    evidence("budget-never-refilled", "restart-keeps-spend");
    evidence("budget-origins", "BUDGET_EXHAUSTED");
    evidence("budget-bytes", "BUDGET_EXHAUSTED-zero-broker");
}

#[test]
fn a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/"),
            "k1"
        ),
        NetReply::Done { .. }
    ));
    // The response tainted the run: a novel origin needs an approval, which
    // M5c denies; the origin it has reached is SEEN.
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://new.example.com/"),
        "k2",
    );
    assert_eq!(denied_reason(&reply), NetDecisionReason::ApprovalRequired);
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/again"),
            "k3"
        ),
        NetReply::Done { .. }
    ));
    // A redirect a tainted run is sent to a new origin: the same denial.
    fx.fake.then(response(
        302,
        &[],
        Some("https://elsewhere.example.com/"),
        b"",
    ));
    let reply = fx.invoke(
        &run,
        following(call(HttpMethod::Get, "https://api.example.com/r")),
        "k4",
    );
    assert_eq!(output(&reply).redirect_ended, Some(RedirectEnd::HopDenied));
    // max_output_bytes narrows the bound the broker is given.
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    fx.fake.then(response(200, &[], None, b"0123456789abcdef"));
    let reply = fx.invoke(
        &run,
        call(HttpMethod::Get, "https://capped.example.com/"),
        "k1",
    );
    assert_eq!(output(&reply).body.byte_len(), 16);
    assert_eq!(fx.fake.asked().last().unwrap().response_limit, Some(16));
    // The call's own narrowing reaches the broker too (on a run the network
    // has not tainted); it never widens what an obligation narrowed.
    let untainted = fx.run("r3", &[GRANT]);
    let mut narrowed = call(HttpMethod::Get, "https://api.example.com/narrow");
    narrowed.max_response_bytes = ResponseLimit::new(64);
    assert!(matches!(
        fx.invoke(&untainted, narrowed, "k-narrow"),
        NetReply::Done { .. }
    ));
    assert_eq!(fx.fake.asked().last().unwrap().response_limit, Some(64));
    let mut capped = call(HttpMethod::Get, "https://capped.example.com/narrow");
    capped.max_response_bytes = ResponseLimit::new(1024);
    assert!(matches!(
        fx.invoke(&run, capped, "k-capped"),
        NetReply::Done { .. }
    ));
    assert_eq!(fx.fake.asked().last().unwrap().response_limit, Some(16));
    // A run the network has not tainted yet: the obligation alone decides.
    let fresh = fx.run("r2", &[GRANT]);
    let reply = fx.invoke(
        &fresh,
        call(HttpMethod::Get, "https://sandboxed.example.com/"),
        "k2",
    );
    assert_eq!(
        denied_reason(&reply),
        NetDecisionReason::ObligationUnenforceable
    );
    evidence("taint-novel-destination", "APPROVAL_REQUIRED-denied");
    evidence("taint-seen-destination", "allowed");
    evidence("obligation-max-output-bytes", "narrowed");
    evidence("obligation-unenforceable", "OBLIGATION_UNENFORCEABLE");
}

#[test]
fn what_the_broker_answers_decides_failed_or_unknown_and_nothing_is_retried() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    let cases: Vec<(Result<BrokerDelivery, BrokerError>, F, &str)> = vec![
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::HttpConnectFailed,
            ))),
            F::ConnectFailed,
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::HttpTlsFailed,
            ))),
            F::TlsFailed,
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::HttpTimeout,
            ))),
            F::Timeout,
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Refused(
                BrokerRefusal::HttpAddressBlocked,
            ))),
            F::AddressBlocked,
            "FAILED",
        ),
        (
            Ok(BrokerDelivery::HttpExchanged(done(
                ExchangeDisposition::ResponseMalformed,
                Some(200),
                &[],
                None,
                b"",
            ))),
            F::ResponseMalformed,
            "FAILED",
        ),
        (
            Ok(BrokerDelivery::HttpExchanged(done(
                ExchangeDisposition::EncodingUnsupported,
                Some(200),
                &[],
                None,
                b"",
            ))),
            F::EncodingUnsupported,
            "FAILED",
        ),
        (
            Ok(BrokerDelivery::HttpExchanged(done(
                ExchangeDisposition::Timeout,
                None,
                &[],
                None,
                b"",
            ))),
            F::Timeout,
            "FAILED",
        ),
        (
            Err(BrokerError::before_sending(BrokerFailure::Unreachable(
                Unreachable::Connect,
            ))),
            F::BrokerUnavailable,
            "FAILED",
        ),
        (
            Err(BrokerError::after_sending(BrokerFailure::Unreachable(
                Unreachable::Io,
            ))),
            F::OutcomeUnknown,
            "UNKNOWN",
        ),
        (Ok(BrokerDelivery::Move), F::OutcomeUnknown, "UNKNOWN"),
    ];
    for (n, (answer, want, state)) in cases.into_iter().enumerate() {
        fx.fake.then(answer);
        let before = fx.fake.asked().len();
        let reply = fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/"),
            &format!("k{n}"),
        );
        assert!(
            matches!(reply, NetReply::Failed { reason, .. } if reason == want),
            "case {n}: {reply:?}"
        );
        // Once: resolved, sent, never again.
        assert_eq!(fx.fake.asked().len() - before, 2, "case {n}");
        let recorded = fx.rows(&format!(
            "SELECT state FROM net_request ORDER BY intent_ms, invocation_id LIMIT 1 OFFSET {n}"
        ));
        assert_eq!(recorded, [state.to_owned()], "case {n}");
    }
    evidence("broker-refusal-before-send", "FAILED-typed");
    evidence("broker-lost-after-send", "UNKNOWN-not-retried");
}

#[test]
fn a_key_names_one_invocation_across_every_tool_ledger() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT]);
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/"),
            "k1"
        ),
        NetReply::Done { .. }
    ));
    let asked = fx.fake.asked().len();
    assert!(matches!(
        fx.invoke(
            &run,
            call(HttpMethod::Get, "https://api.example.com/"),
            "k1"
        ),
        NetReply::Refused(_, R::IdempotencyKeyReused)
    ));
    assert_eq!(fx.fake.asked().len(), asked, "a reused key reaches nothing");
    // A key a filesystem tool bound first is the same namespace — and a key
    // this request bound is refused to a filesystem tool.
    let caller = fx.caller;
    let stat = fx.v4(
        &run,
        "direwolf.tool.invoke",
        Some("k-fs"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    let _ = fx.authority().dispatch(&caller, &stat).unwrap();
    if fx.count("SELECT count(*) FROM tool_idempotency WHERE idempotency_key = 'k-fs'") == 1 {
        assert!(matches!(
            fx.invoke(
                &run,
                call(HttpMethod::Get, "https://api.example.com/"),
                "k-fs"
            ),
            NetReply::Refused(_, R::IdempotencyKeyReused)
        ));
    }
    let stat = fx.v4(
        &run,
        "direwolf.tool.invoke",
        Some("k1"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    let body = fx.authority().dispatch(&caller, &stat).unwrap();
    assert!(
        matches!(&body, DwkpBody::ToolRefusedV4(r) if r.reason == R::IdempotencyKeyReused),
        "{body:?}"
    );
    assert_eq!(fx.fake.asked().len(), asked);
    evidence(
        "idempotency-key-reused",
        "IDEMPOTENCY_KEY_REUSED-zero-broker",
    );
    evidence(
        "idempotency-one-namespace",
        "IDEMPOTENCY_KEY_REUSED-across-tools",
    );
}

/// Stop the first request at `point`, as a crash would; restart; return the
/// request's and its hop's recorded states and how many exchanges were sent.
fn crash_at(point: CrashPoint) -> (Vec<String>, Vec<String>, usize) {
    let hook: CrashHook = Arc::new(move |at| {
        if at == point {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    let mut fx = fixture_with(POLICY, NetBudget::default(), Some(hook));
    let run = fx.run("r1", &[GRANT]);
    let request = NetRequest {
        call: call(HttpMethod::Post, "https://api.example.com/charge"),
        key: Some(IdempotencyKey::new("crash".to_owned()).unwrap()),
    };
    let (caller, session, epoch) = (fx.caller, fx.session.clone(), fx.epoch);
    let result = fx
        .authority()
        .net_invoke(&caller, &session, &run, epoch, &request);
    assert!(result.is_err(), "{point}: stopped");
    drop(fx.authority.take());
    let state = fx.state();
    let mut restarted = start(&state, &fx.config, &fx.fake, &fx.clock, None);
    let caller = restarted.connect(AuthenticatedSubject::unix_uid(1000));
    let Reply::Done(epoch) = restarted.acquire_lease(&caller, &fx.session).unwrap() else {
        panic!("a lease")
    };
    // The run died with its incarnation: the same request is refused, never
    // performed again.
    let replay = restarted
        .net_invoke(&caller, &fx.session, &run, epoch, &request)
        .unwrap();
    assert!(
        matches!(replay, NetReply::Refused(_, R::UnknownRun)),
        "{point}"
    );
    let sent = fx
        .fake
        .asked()
        .iter()
        .filter(|a| a.operation == "http.exchange")
        .count();
    (
        fx.rows("SELECT state FROM net_request"),
        fx.rows("SELECT state FROM net_hop"),
        sent,
    )
}

#[test]
fn a_crash_anywhere_in_a_hop_is_recorded_unknown_and_never_sent_again() {
    for point in CrashPoint::NET {
        let (requests, hops, sent) = crash_at(point);
        let (want_requests, want_hops, want_sent): (&[&str], &[&str], usize) = match point {
            // Resolved, nothing decided with it: nothing recorded.
            CrashPoint::NetAfterResolve => (&[], &[], 0),
            // Recorded, not sent: the restart cannot know that.
            CrashPoint::NetAfterIntent => (&["UNKNOWN"], &["UNKNOWN"], 0),
            // Sent, the outcome lost.
            CrashPoint::NetAfterBroker => (&["UNKNOWN"], &["UNKNOWN"], 1),
            // Durable before the crash: the answer was lost, not the record.
            CrashPoint::NetAfterOutcome => (&["COMPLETED"], &["COMPLETED"], 1),
            other => panic!("{other} is not a network point"),
        };
        assert_eq!(requests, want_requests, "{point}");
        assert_eq!(hops, want_hops, "{point}");
        assert_eq!(sent, want_sent, "{point}");
        let case = match point {
            CrashPoint::NetAfterResolve => "crash-N1-after-resolve",
            CrashPoint::NetAfterIntent => "crash-N2-after-intent",
            CrashPoint::NetAfterBroker => "crash-N3-after-exchange",
            _ => "crash-N4-after-outcome",
        };
        evidence(
            case,
            &format!("{}-never-resent", want_requests.first().unwrap_or(&"none")),
        );
    }
}

#[test]
fn version_four_carries_net_http_and_reshapes_the_other_tools() {
    let mut fx = fixture();
    let run = fx.run("r1", &[GRANT, "fs.read:*"]);
    let caller = fx.caller;
    let net = fx.v4(
        &run,
        "direwolf.tool.invoke",
        Some("w1"),
        r#"{"net_http":{"method":"GET","url":"https://api.example.com/","follow_redirects":false}}"#,
    );
    let body = fx.authority().dispatch(&caller, &net).unwrap();
    let DwkpBody::ToolResultV4(result) = body else {
        panic!("{body:?}")
    };
    assert!(result.output.net_http.is_some());
    assert_eq!(result.plan.actions.len(), 1);
    let preview = fx.v4(
        &run,
        "direwolf.tool.preview",
        None,
        r#"{"net_http":{"method":"GET","url":"https://api.example.com/","follow_redirects":false}}"#,
    );
    let body = fx.authority().dispatch(&caller, &preview).unwrap();
    assert!(matches!(body, DwkpBody::ToolPreviewedV4(_)), "{body:?}");
    // One of version 3's tools, asked at version 4, answered at version 4.
    let stat = fx.v4(
        &run,
        "direwolf.tool.invoke",
        Some("w2"),
        r#"{"fs_stat":{"path":"/workspace"}}"#,
    );
    let body = fx.authority().dispatch(&caller, &stat).unwrap();
    assert!(
        matches!(
            body,
            DwkpBody::ToolResultV4(_) | DwkpBody::ToolRefusedV4(_) | DwkpBody::ToolDeniedV4(_)
        ),
        "{body:?}"
    );
    evidence("protocol-v4-net-http", "ToolResultV4");
}
