//! M5c's `net.http` evidence on real processes (ADR-0050 §16), run by
//! `make net-http-evidence`: the authority's library — the same `dispatch`
//! the DWKP server calls, fed version-4 messages through the real decoder —
//! the released `dwkd-broker serve`, and local HTTPS origins
//! (`tests/net_http/origin.py`) under a PKI made for the run. No internet:
//! the broker resolves the evidence's names from a fixture file
//! (`--allow-evidence-egress`) and trusts the run's test authority
//! (`--allow-evidence-trust`); the authority's own guard lets `127.0.0.1`
//! through only because this harness attaches it
//! (`Authority::attach_net_evidence`), which no DWKP operation and no `serve`
//! option can do (TX035).
//!
//! Four groups, every case required (`scripts/dw.py`, `NET_HTTP_CASES`):
//!
//! * **SSRF and DNS** — every blocked answer refused by the authority after
//!   the broker judged it, a mixed answer refused whole, metadata names and
//!   address literals refused before anything is resolved, nothing resolved
//!   for an ungranted host, rebinding pinned within a request and refused on
//!   the next;
//! * **HTTP and redirects** — each hop decided from the start, never a
//!   downgrade, a loop or a sixth hop, never a body replayed, the caller's
//!   headers never across origins; strict framing, no decoding, bounded
//!   bodies, `Set-Cookie` dropped, TLS verified always;
//! * **secrets** — a credential at its bound origin only, each hop its own
//!   use, never across origins, an echo redacted, a secret in a request
//!   refused, no residue in the broker or in durable state;
//! * **lifecycle and budgets** — a crash after the intent or after the
//!   exchange is `UNKNOWN` and never sent again, a reused key reaches
//!   nothing, a spent budget stays spent, the shipped packs and taint decide.
//!
//! Locally every process is this uid (`--allow-shared-authority-uid`,
//! `--allow-dumpable` where this harness reads the broker's memory).

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use age as _;
use dwk_proto as _;
use getrandom as _;
use hmac as _;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
#[cfg(target_os = "linux")]
use nix as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;
use zeroize as _;

#[cfg(target_os = "linux")]
mod broker_support;
#[cfg(target_os = "linux")]
mod net_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::dwkp::netops::{
        NetDecisionReason as D, NetHttpResult, RedirectEnd as E, ToolFailureReasonV4 as F,
        ToolRefusalReasonV4 as R,
    };
    use dwk_proto::wire::guard::Address;
    use dwk_proto::wire::id::{RunId, SessionId};
    use dwk_proto::wire::scalar::Epoch;
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::state::{
        Authority, CallerContext, CrashHook, CrashPoint, HookAction, ManualClock, Mode, NetBudget,
        PolicySet, Reply, StartOptions, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };
    use linux_keyutils::{Key, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
    use sha2::{Digest as _, Sha256};

    use super::broker_support::Broker;
    use super::net_support::{
        Origin, authorization, body_bytes, fixture, header_names, pki, tools_present,
    };
    use super::state_support::{
        START_MS, TempDir, admit_msg, decode, id, policy, profile, session,
    };
    use super::transport_support::own_uid;

    const SUITE: &str = "net-http";

    fn evidence(case: &str, outcome: &str) {
        println!(
            "NET-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
             \"count\":1}}"
        );
    }

    /// HTTPS allowed on the host, and `secret.use`: an operator test policy,
    /// **not** a shipped pack (every shipped pack denies `secret.use`).
    const OPEN: &str = "schema_version = 1\n\n[meta]\nname = \"m5c\"\n\n[[rule]]\nid = \
        \"allow-secret-use\"\neffect = \"ALLOW\"\nwhen.verb = \"secret.use\"\nwhen.environment = \
        \"host\"\n\n[[rule]]\nid = \"allow-https\"\neffect = \"ALLOW\"\nwhen.verb = \
        \"network.https\"\nwhen.environment = \"host\"\n\n[[rule]]\nid = \"default\"\neffect = \
        \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";

    /// `OPEN`, with a tainted run's novel destination needing an approval.
    const TAINT: &str = "schema_version = 1\n\n[meta]\nname = \"m5c\"\n\n[[rule]]\nid = \
        \"approve-novel-when-tainted\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \
        \"UNTRUSTED_CONTENT_IN_RUN\"\nwhen.verb = [\"network.https\"]\nwhen.taint_level = \
        [\"EXTERNAL_UNTRUSTED\"]\nwhen.destination_novel = true\napproval.scope = \
        \"exact_action\"\napproval.ttl = \"10m\"\napproval.max_uses = 1\n\n[[rule]]\nid = \
        \"allow-https\"\neffect = \"ALLOW\"\nwhen.verb = \"network.https\"\nwhen.environment = \
        \"host\"\n\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";

    /// The evidence's names: the origins, and every SSRF shape.
    const NAMES: &str = "resolve origin.test 127.0.0.1\nresolve alt.origin.test 127.0.0.1\n\
        resolve wrongname.test 127.0.0.1\nresolve rebind.test 127.0.0.1;10.0.0.1\n\
        resolve private.test 10.0.0.5\nresolve lo2.test 127.0.0.2\n\
        resolve meta-ip.test 169.254.169.254\nresolve mapped.test ::ffff:10.0.0.1\n\
        resolve nat64.test 64:ff9b::a00:1\nresolve sixto4.test 2002:a00:1::1\n\
        resolve teredo.test 2001:0:4136:e378:8000:63bf:3fff:fdd2\nresolve v6lo.test ::1\n\
        resolve mixed.test 127.0.0.1,10.0.0.1\nresolve gone.test fail\n\
        resolve slow.test timeout\nallow 127.0.0.1\n";

    /// The run's PKI, the broker, and an origin per certificate.
    struct Bench {
        dir: TempDir,
        pki: PathBuf,
        /// `origin.test` (and `rebind.test`).
        origin: Origin,
        /// `alt.origin.test`.
        alt: Origin,
        /// `origin.test`, expired.
        expired: Origin,
        /// `origin.test`, signed by itself.
        selfsigned: Origin,
        /// `origin.test`, signed by an authority nothing trusts.
        rogue: Origin,
        broker: Broker,
        socket: PathBuf,
    }

    fn bench(tag: &str) -> Option<Bench> {
        if !tools_present() {
            println!("NOT EXERCISED: the net.http evidence needs bash, openssl and python3");
            return None;
        }
        let dir = TempDir::new(tag);
        let pki = pki(dir.path());
        let origin = Origin::start(&pki, "origin");
        let alt = Origin::start(&pki, "alt");
        let expired = Origin::start(&pki, "expired");
        let selfsigned = Origin::start(&pki, "selfsigned");
        let rogue = Origin::start(&pki, "rogue-origin");
        let fixture = fixture(dir.path(), NAMES);
        let socket = dir.path().join("bipc").join("broker.sock");
        let broker = Broker::start(
            &socket,
            own_uid(),
            &[
                "--allow-shared-authority-uid",
                "--allow-dumpable",
                "--allow-evidence-egress",
                fixture.to_str().unwrap(),
                "--allow-evidence-trust",
                pki.join("ca.pem").to_str().unwrap(),
            ],
        );
        Some(Bench {
            dir,
            pki,
            origin,
            alt,
            expired,
            selfsigned,
            rogue,
            broker,
            socket,
        })
    }

    /// Percent-encode a URL as one query value.
    fn enc(url: &str) -> String {
        url.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    fn sha(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    impl Bench {
        fn on(&self, origin: &Origin, host: &str, path: &str) -> String {
            format!("https://{host}:{}{path}", origin.port)
        }

        fn o(&self, path: &str) -> String {
            self.on(&self.origin, "origin.test", path)
        }

        fn a(&self, path: &str) -> String {
            self.on(&self.alt, "alt.origin.test", path)
        }

        /// How many resolutions the broker has performed.
        fn resolutions(&self) -> usize {
            std::thread::sleep(std::time::Duration::from_millis(100));
            self.broker
                .events()
                .iter()
                .filter(|e| e.contains("op=broker.http_resolve"))
                .count()
        }
    }

    /// One authority, its run and its caller.
    struct Host {
        authority: Option<Authority>,
        config: StartupConfig,
        state: PathBuf,
        socket: PathBuf,
        caller: CallerContext,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
        n: u64,
    }

    /// What a `net.http` came to.
    #[derive(Debug)]
    enum Got {
        Done(Box<NetHttpResult>),
        Refused(R),
        /// The network action's reason, and the injection action's.
        Denied(D, Option<D>),
        Failed(F),
    }

    impl Got {
        fn done(self) -> NetHttpResult {
            match self {
                Self::Done(output) => *output,
                other => panic!("not a result: {other:?}"),
            }
        }
    }

    fn launch(
        state: &Path,
        config: &StartupConfig,
        socket: &Path,
        hook: Option<CrashHook>,
    ) -> Authority {
        let link: Arc<dyn EffectBroker> =
            Arc::new(UnixBroker::new(socket.to_path_buf(), own_uid()));
        let mut authority = {
            let _guard = super::state_support::spawn_guard();
            Authority::start(
                state,
                config,
                StartOptions {
                    clock: Arc::new(ManualClock::new(START_MS)),
                    crash_hook: hook,
                    broker: Some(link),
                },
            )
            .unwrap()
            .0
        };
        authority
            .attach_net_evidence(vec![Address::V4([127, 0, 0, 1])])
            .unwrap();
        authority
    }

    #[derive(Clone)]
    struct HostSpec<'a> {
        tag: &'a str,
        policy: PolicySet,
        mode: Mode,
        budget: NetBudget,
        secrets: Option<String>,
        requested: &'a [&'a str],
        hook: Option<CrashHook>,
        socket: Option<PathBuf>,
    }

    impl<'a> HostSpec<'a> {
        fn open(tag: &'a str, requested: &'a [&'a str]) -> Self {
            Self {
                tag,
                policy: policy("m5c", OPEN),
                mode: Mode::Balanced,
                budget: NetBudget::default(),
                secrets: None,
                requested,
                hook: None,
                socket: None,
            }
        }
    }

    fn host(bench: &Bench, spec: HostSpec<'_>) -> Host {
        let mut config = StartupConfig::new(
            spec.policy,
            spec.mode,
            vec!["network.https:*".to_owned(), "secret.use:*".to_owned()],
        );
        config.net_budget = spec.budget;
        if let Some(text) = &spec.secrets {
            config.secrets = dwkd_authority::secret::metadata::parse(text).unwrap();
        }
        let dir = bench.dir.path().join(spec.tag);
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        let state = dir.join("state");
        let socket = spec.socket.unwrap_or_else(|| bench.socket.clone());
        let mut authority = launch(&state, &config, &socket, spec.hook);
        let workspace = WorkspaceId::new("ws").unwrap();
        {
            let mut operator = authority.operator();
            operator
                .install_agent_profile(&profile(
                    "operator",
                    &["network.https:*", "secret.use:origin-token"],
                    &[],
                    PrivacyClass::Any,
                ))
                .unwrap();
            operator
                .install_workspace(&workspace, WorkspaceSensitivity::Private)
                .unwrap();
            operator
                .install_workspace_root(&workspace, dir.join("ws").to_str().unwrap())
                .unwrap();
            operator
                .bind_session_workspace(&session(1), &workspace)
                .unwrap();
        }
        let caller = authority.connect(dwkd_authority::state::AuthenticatedSubject::unix_uid(1000));
        let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(1)).unwrap() else {
            panic!("a lease")
        };
        let Reply::Done(admission) = authority
            .admit_run(
                &caller,
                &admit_msg(
                    &session(1),
                    epoch,
                    "k-run",
                    "operator",
                    &[],
                    spec.requested,
                    1,
                ),
            )
            .unwrap()
        else {
            panic!("admitted")
        };
        Host {
            run: admission.run_id().clone(),
            authority: Some(authority),
            config,
            state,
            socket,
            caller,
            session: session(1),
            epoch,
            n: 0,
        }
    }

    /// A `net_http` call's JSON. The URL is a JSON string: a backslash in it
    /// is escaped, so the authority sees the backslash, not an escape.
    fn net(method: &str, url: &str, follow: bool, extra: &str) -> String {
        let url = url.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"{{"net_http":{{"method":"{method}","url":"{url}","follow_redirects":{follow}{extra}}}}}"#
        )
    }

    impl Host {
        fn authority(&mut self) -> &mut Authority {
            self.authority.as_mut().unwrap()
        }

        /// One version-4 message through the real decoder and `dispatch`.
        fn send(&mut self, payload: &str, key: Option<&str>) -> Result<DwkpBody, String> {
            self.n += 1;
            let (schema, key) = match key {
                Some(k) => (
                    "direwolf.tool.invoke",
                    format!(r#","idempotency_key":"{k}""#),
                ),
                None => ("direwolf.tool.preview", String::new()),
            };
            let message = decode(&format!(
                r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":4,"ts":"2026-09-21T10:01:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch}{key},"payload":{payload}}}"#,
                id = id("msg", 40_000 + self.n),
                session = self.session.as_str(),
                run = self.run.as_str(),
                epoch = self.epoch.get(),
            ));
            let caller = self.caller;
            self.authority()
                .dispatch(&caller, &message)
                .map_err(|e| e.to_string())
        }

        fn call(&mut self, payload: &str, key: &str) -> Got {
            match self.send(payload, Some(key)).unwrap() {
                DwkpBody::ToolResultV4(result) => {
                    Got::Done(Box::new(result.output.net_http.expect("a net.http result")))
                }
                DwkpBody::ToolRefusedV4(refusal) => Got::Refused(refusal.reason),
                DwkpBody::ToolFailedV4(failure) => Got::Failed(failure.reason),
                DwkpBody::ToolDeniedV4(denial) => {
                    let mut net = None;
                    let mut injection = None;
                    for action in denial.plan.actions.iter() {
                        if let Some(a) = &action.net {
                            net = Some(a.decision.reason);
                        }
                        if let Some(a) = &action.injection {
                            injection = Some(a.decision.reason);
                        }
                    }
                    Got::Denied(net.expect("a network action"), injection)
                }
                other => panic!("not a version-4 answer: {other:?}"),
            }
        }

        fn get(&mut self, url: &str, key: &str) -> Got {
            self.call(&net("GET", url, false, ""), key)
        }

        fn follow(&mut self, url: &str, key: &str) -> Got {
            self.call(&net("GET", url, true, ""), key)
        }

        fn db(&self) -> rusqlite::Connection {
            rusqlite::Connection::open(self.state.join("kernel.db")).unwrap()
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

        /// Drop the authority (as a crash leaves it) and start it again on
        /// the same store and broker: a new incarnation, a new lease.
        fn restart(&mut self) {
            drop(self.authority.take());
            let mut authority = launch(&self.state, &self.config, &self.socket, None);
            let caller =
                authority.connect(dwkd_authority::state::AuthenticatedSubject::unix_uid(1000));
            let Reply::Done(epoch) = authority.acquire_lease(&caller, &self.session).unwrap()
            else {
                panic!("a lease")
            };
            self.authority = Some(authority);
            self.caller = caller;
            self.epoch = epoch;
        }
    }

    fn header_values(result: &NetHttpResult, name: &str) -> Vec<String> {
        result
            .headers
            .iter()
            .filter(|h| h.name.as_str() == name)
            .map(|h| h.value.as_str().to_owned())
            .collect()
    }

    // ---- SSRF and DNS -------------------------------------------------------

    #[test]
    fn ssrf_and_dns_shapes_are_refused_before_any_origin_hears_of_them() {
        let Some(b) = bench("net-ssrf") else {
            return;
        };
        let mut h = host(&b, HostSpec::open("h", &["network.https:*"]));
        // A blocked answer, whatever its shape: the broker judges it, the
        // authority judges it again, nothing is dialled.
        for (n, (name, want, case)) in [
            ("private.test", R::AddressBlocked, "ssrf-private-answer"),
            ("lo2.test", R::AddressBlocked, "ssrf-loopback-not-excepted"),
            ("meta-ip.test", R::AddressBlocked, "ssrf-metadata-address"),
            ("mapped.test", R::AddressBlocked, "ssrf-ipv4-mapped"),
            ("nat64.test", R::AddressBlocked, "ssrf-nat64"),
            ("sixto4.test", R::AddressBlocked, "ssrf-6to4"),
            ("teredo.test", R::AddressBlocked, "ssrf-teredo"),
            ("v6lo.test", R::AddressBlocked, "ssrf-ipv6-loopback"),
            ("mixed.test", R::AddressMixed, "ssrf-mixed-answer"),
            ("gone.test", R::ResolutionFailed, "dns-resolution-failed"),
            ("slow.test", R::ResolutionTimeout, "dns-resolution-timeout"),
        ]
        .into_iter()
        .enumerate()
        {
            let got = h.get(&format!("https://{name}/x"), &format!("s{n}"));
            assert!(
                matches!(got, Got::Refused(r) if r == want),
                "{name}: {got:?}"
            );
            evidence(case, want.as_str());
        }
        assert_eq!(h.count("SELECT count(*) FROM net_request"), 0);
        // Refused before resolution: a metadata name, an address literal in
        // any spelling, userinfo, plaintext.
        let resolved = b.resolutions();
        for (n, (url, want, case)) in [
            (
                "https://metadata.google.internal/",
                R::AddressBlocked,
                "ssrf-metadata-name",
            ),
            (
                "https://127.0.0.1/",
                R::UrlInvalid,
                "ssrf-ip-literal-dotted",
            ),
            (
                "https://2130706433/",
                R::UrlInvalid,
                "ssrf-ip-literal-decimal",
            ),
            ("https://0x7f000001/", R::UrlInvalid, "ssrf-ip-literal-hex"),
            (
                "https://0177.0.0.1/",
                R::UrlInvalid,
                "ssrf-ip-literal-octal",
            ),
            ("https://[::1]/", R::UrlInvalid, "ssrf-ip-literal-v6"),
            (
                "https://origin.test@private.test/",
                R::UrlInvalid,
                "origin-confusion-userinfo",
            ),
            (
                "https://ORIGIN.test/",
                R::UrlInvalid,
                "origin-confusion-uppercase",
            ),
            (
                "https://origin.test./",
                R::UrlInvalid,
                "origin-confusion-trailing-dot",
            ),
            (
                "https://origin.test/%2e%2e/x",
                R::UrlInvalid,
                "origin-confusion-encoded-dot-segment",
            ),
            (
                "https://origin.test\\@private.test/",
                R::UrlInvalid,
                "origin-confusion-backslash",
            ),
            (
                "https://xn--rigin-0ra.test/",
                R::ResolutionFailed,
                "origin-confusion-idna-label",
            ),
            (
                "http://origin.test/",
                R::PlaintextUnsupported,
                "plaintext-refused",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            // An IDNA label is a host like any other, compared by its bytes:
            // resolved, and the fixture knows no such name.
            let got = h.get(url, &format!("p{n}"));
            assert!(
                matches!(got, Got::Refused(r) if r == want),
                "{url}: {got:?}"
            );
            evidence(case, want.as_str());
        }
        assert_eq!(
            b.resolutions(),
            resolved + 1,
            "only the IDNA host was resolved"
        );
        // Nothing is resolved for a host no grant covers, nor for a port a
        // port-bound grant does not name.
        let grant = format!("network.https:origin.test:{}", b.origin.port);
        let mut narrow = host(&b, HostSpec::open("narrow", &[grant.as_str()]));
        let resolved = b.resolutions();
        let got = narrow.get(&b.a("/ok"), "n1");
        assert!(matches!(got, Got::Denied(D::NoCapability, None)), "{got:?}");
        let got = narrow.get(&format!("https://origin.test:{}/ok", b.alt.port), "n2");
        assert!(
            matches!(got, Got::Denied(D::NoCapability, None)),
            "port confusion: {got:?}"
        );
        assert_eq!(b.resolutions(), resolved, "no resolution without a grant");
        evidence(
            "ssrf-ungranted-host-not-resolved",
            "NO_CAPABILITY-zero-resolutions",
        );
        evidence("origin-confusion-port", "NO_CAPABILITY");
        // Rebinding: pinned across one request's hops, judged afresh on the
        // next request.
        let mut h = host(&b, HostSpec::open("rebind", &["network.https:*"]));
        let first = h
            .follow(
                &b.on(
                    &b.origin,
                    "rebind.test",
                    &format!(
                        "/redirect?status=302&to={}",
                        enc(&b.on(&b.origin, "rebind.test", "/ok"))
                    ),
                ),
                "r1",
            )
            .done();
        assert_eq!((first.status.get(), first.hops.len()), (200, 2));
        let second = h.get(&b.on(&b.origin, "rebind.test", "/ok"), "r2");
        assert!(
            matches!(second, Got::Refused(R::AddressBlocked)),
            "{second:?}"
        );
        evidence(
            "dns-rebinding-pinned-within-request",
            "two-hops-one-resolution",
        );
        evidence("dns-rebinding-next-request", "ADDRESS_BLOCKED");
        assert!(b.origin.requests().iter().all(|r| !r.contains("/x\"")));
        assert!(
            b.alt.requests().is_empty(),
            "no SSRF case reached an origin"
        );
    }

    // ---- HTTP, redirects, TLS -------------------------------------------------

    #[test]
    fn requests_and_redirects_are_decided_hop_by_hop_against_real_origins() {
        let Some(b) = bench("net-http") else {
            return;
        };
        let mut h = host(&b, HostSpec::open("h", &["network.https:*"]));
        let ok = h
            .call(
                &net(
                    "GET",
                    &b.o("/ok"),
                    false,
                    r#","headers":[{"name":"accept","value":"text/plain"}]"#,
                ),
                "k1",
            )
            .done();
        assert_eq!((ok.status.get(), ok.body.to_bytes()), (200, b"ok".to_vec()));
        let seen = b.origin.to("/ok");
        assert_eq!(seen.len(), 1);
        let names = header_names(&seen[0]);
        assert!(
            names.contains(&"accept".to_owned()) && names.contains(&"accept-encoding".to_owned())
        );
        assert_eq!(authorization(&seen[0]), None);
        assert_eq!(h.rows("SELECT state FROM net_request"), ["COMPLETED"]);
        evidence("https-get-pinned", "200-one-request");
        // Not followed unless asked: the 3xx is the answer.
        let r = h.get(&b.o("/redirect?status=302&to=%2Fok"), "k2").done();
        assert_eq!(r.redirect_ended, Some(E::NotFollowed));
        assert_eq!(header_values(&r, "location"), [b.o("/ok")]);
        assert_eq!(b.origin.to("/ok").len(), 1);
        evidence("redirect-not-followed", "NOT_FOLLOWED-location-canonical");
        // Same origin: followed, pinned, one resolution for the request.
        let resolved = b.resolutions();
        let r = h.follow(&b.o("/redirect?status=301&to=%2Fok"), "k3").done();
        assert_eq!((r.status.get(), r.hops.len()), (200, 2));
        assert_eq!(b.resolutions(), resolved + 1);
        evidence("redirect-same-origin", "followed-one-resolution");
        // Another origin: decided again, resolved, the caller's headers left
        // behind.
        let r = h
            .call(
                &net(
                    "GET",
                    &b.o(&format!("/redirect?status=302&to={}", enc(&b.a("/ok")))),
                    true,
                    r#","headers":[{"name":"accept","value":"text/plain"}]"#,
                ),
                "k4",
            )
            .done();
        assert_eq!((r.status.get(), r.hops.len()), (200, 2));
        let at_alt = b.alt.to("/ok");
        assert_eq!(at_alt.len(), 1);
        assert!(!header_names(&at_alt[0]).contains(&"accept".to_owned()));
        evidence(
            "redirect-cross-origin",
            "decided-again-caller-headers-dropped",
        );
        // Every way a chain ends: typed, and nothing further sent.
        for (n, (path, want, sent, case)) in [
            ("/loop", E::RedirectLoop, 1usize, "redirect-loop"),
            ("/chain", E::RedirectLimit, 6, "redirect-sixth-hop"),
            (
                &*format!(
                    "/redirect?status=302&to={}",
                    enc(&format!("http://origin.test:{}/ok", b.origin.port))
                ),
                E::RedirectTargetInvalid,
                1,
                "redirect-downgrade",
            ),
            (
                "/redirect?status=302&to=https%3A%2F%2Fprivate.test%2F",
                E::AddressBlocked,
                1,
                "redirect-blocked-address",
            ),
            (
                "/redirect?status=302&to=https%3A%2F%2Fmetadata.google.internal%2F",
                E::AddressBlocked,
                1,
                "redirect-metadata-name",
            ),
            (
                "/redirect?status=302&to=https%3A%2F%2Fmixed.test%2F",
                E::AddressMixed,
                1,
                "redirect-mixed-address",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let before = b.origin.requests().len();
            let r = h.follow(&b.o(path), &format!("e{n}")).done();
            assert_eq!(r.redirect_ended, Some(want), "{case}");
            assert_eq!(b.origin.requests().len() - before, sent, "{case}");
            evidence(case, want.as_str());
        }
        // A grant for one origin does not authorise another.
        let mut narrow = host(&b, HostSpec::open("narrow", &["network.https:origin.test"]));
        let before = b.alt.requests().len();
        let r = narrow
            .follow(
                &b.o(&format!("/redirect?status=302&to={}", enc(&b.a("/ok")))),
                "g1",
            )
            .done();
        assert_eq!(r.redirect_ended, Some(E::HopDenied));
        assert_eq!(
            b.alt.requests().len(),
            before,
            "the ungranted origin heard nothing"
        );
        evidence("redirect-ungranted-origin", "HOP_DENIED-not-sent");
        // A body is never sent again; 303 is a GET without it.
        let before = b.origin.requests().len();
        let r = h
            .call(
                &net(
                    "POST",
                    &b.o("/redirect?status=307&to=%2Fok"),
                    true,
                    r#","body":"7b7d""#,
                ),
                "b1",
            )
            .done();
        assert_eq!(r.redirect_ended, Some(E::RedirectWouldResendBody));
        assert_eq!(b.origin.requests().len() - before, 1);
        evidence(
            "redirect-307-with-body",
            "REDIRECT_WOULD_RESEND_BODY-sent-once",
        );
        let r = h
            .call(
                &net(
                    "POST",
                    &b.o("/redirect?status=303&to=%2Fok"),
                    true,
                    r#","body":"7b7d""#,
                ),
                "b2",
            )
            .done();
        assert_eq!(r.status.get(), 200);
        let last = b.origin.requests().pop().unwrap();
        assert!(last.contains("\"method\": \"GET\"") && body_bytes(&last) == Some(0));
        evidence("redirect-303-to-get", "GET-without-body");
        // The response: strict framing, no decoding, bounded, no cookies.
        for (n, (path, want, case)) in [
            (
                "/bad-status",
                F::ResponseMalformed,
                "response-malformed-status",
            ),
            (
                "/both-framings",
                F::ResponseMalformed,
                "response-length-and-chunked",
            ),
            (
                "/bad-chunk",
                F::ResponseMalformed,
                "response-bad-chunk-size",
            ),
            ("/header-bomb", F::ResponseMalformed, "response-header-bomb"),
            (
                "/close-delimited",
                F::ResponseMalformed,
                "response-close-delimited",
            ),
            ("/switch", F::ResponseMalformed, "response-101"),
            ("/gzip", F::EncodingUnsupported, "response-encoded"),
        ]
        .into_iter()
        .enumerate()
        {
            let got = h.get(&b.o(path), &format!("f{n}"));
            assert!(
                matches!(got, Got::Failed(f) if f == want),
                "{path}: {got:?}"
            );
            evidence(case, want.as_str());
        }
        let big = h
            .call(
                &net(
                    "GET",
                    &b.o("/big?n=5000"),
                    false,
                    r#","max_response_bytes":1024"#,
                ),
                "c1",
            )
            .done();
        assert_eq!((big.body.byte_len(), big.truncated), (1024, true));
        evidence("response-past-the-bound", "cut-truncated");
        let cookie = h.get(&b.o("/cookie"), "c2").done();
        assert!(header_values(&cookie, "set-cookie").is_empty());
        evidence("response-set-cookie", "dropped");
        let started = std::time::Instant::now();
        let got = h.get(&b.o("/never"), "c3");
        assert!(matches!(got, Got::Failed(F::Timeout)), "{got:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(40));
        evidence("response-never-answers", "TIMEOUT");
        // TLS: verified always; a name, a date, a chain or a root that is
        // wrong refuses before a byte of the request.
        for (n, (url, case)) in [
            (b.on(&b.origin, "wrongname.test", "/ok"), "tls-wrong-name"),
            (b.on(&b.expired, "origin.test", "/ok"), "tls-expired"),
            (b.on(&b.selfsigned, "origin.test", "/ok"), "tls-self-signed"),
            (b.on(&b.rogue, "origin.test", "/ok"), "tls-untrusted-root"),
        ]
        .into_iter()
        .enumerate()
        {
            let got = h.get(&url, &format!("t{n}"));
            assert!(matches!(got, Got::Failed(F::TlsFailed)), "{case}: {got:?}");
            evidence(case, "TLS_FAILED");
        }
        assert!(b.expired.requests().is_empty() && b.selfsigned.requests().is_empty());
        assert!(b.rogue.requests().is_empty());
        // A broker that does not trust the evidence's authority: Mozilla's
        // roots, and nothing else, ever.
        let fixture = b.dir.path().join("egress.fixture");
        let production_socket = b.dir.path().join("pipc").join("broker.sock");
        let _production = Broker::start(
            &production_socket,
            own_uid(),
            &[
                "--allow-shared-authority-uid",
                "--allow-evidence-egress",
                fixture.to_str().unwrap(),
            ],
        );
        let mut spec = HostSpec::open("prod-trust", &["network.https:*"]);
        spec.socket = Some(production_socket);
        let mut p = host(&b, spec);
        let got = p.get(&b.o("/ok"), "pt1");
        assert!(matches!(got, Got::Failed(F::TlsFailed)), "{got:?}");
        evidence("tls-test-authority-under-production-trust", "TLS_FAILED");
        let _ = &b.pki;
    }

    // ---- secrets ------------------------------------------------------------

    /// A kernel-keyring entry and its key, removed when dropped.
    struct Seeded(String, Key);

    impl Seeded {
        fn new(tag: &str, value: &[u8]) -> Option<Self> {
            let name = format!("direwolf-evidence/{tag}-{}", std::process::id());
            let staging = KeyRing::from_special_id(KeyRingIdentifier::Process, true).ok()?;
            let user = KeyRing::from_special_id(KeyRingIdentifier::User, true).ok()?;
            let key = staging.add_key(&name, value).ok()?;
            let perms = KeyPermissionsBuilder::builder()
                .posessor(Permission::ALL)
                .user(Permission::VIEW | Permission::READ | Permission::SEARCH)
                .build();
            let placed = user.link_key(key).and_then(|()| key.set_perms(perms));
            let _ = staging.unlink_key(key);
            if placed.is_err() {
                let _ = user.unlink_key(key);
                return None;
            }
            Some(Self(name, key))
        }
    }

    impl Drop for Seeded {
        fn drop(&mut self) {
            let _ = self.1.invalidate();
            if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false) {
                let _ = ring.unlink_key(self.1);
            }
        }
    }

    /// `len` printable bytes, fresh per call and per process.
    fn fresh(len: usize) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        Sha256::digest(format!("net-{nanos}-{}", std::process::id()))
            .iter()
            .chain(Sha256::digest(format!("net2-{nanos}")).iter())
            .take(len)
            .map(|b| char::from(alphabet[usize::from(*b) % alphabet.len()]))
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Whether any readable mapping of `pid` holds `needle`.
    fn memory_holds(pid: u32, needle: &[u8]) -> Option<bool> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
        let mut scanned = 0u64;
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !perms.starts_with('r') {
                continue;
            }
            let (start, end) = range.split_once('-').unwrap();
            let (start, end) = (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            );
            let mut offset = start;
            let mut carry: Vec<u8> = Vec::new();
            while offset < end {
                let len = usize::try_from((end - offset).min(1 << 20)).unwrap();
                let mut chunk = vec![0u8; len];
                if mem.seek(SeekFrom::Start(offset)).is_err() || mem.read_exact(&mut chunk).is_err()
                {
                    break;
                }
                scanned += u64::try_from(len).unwrap();
                carry.extend_from_slice(&chunk);
                if contains(&carry, needle) {
                    return Some(true);
                }
                let keep = carry.len().saturating_sub(needle.len());
                carry.drain(..keep);
                offset += u64::try_from(len).unwrap();
            }
        }
        (scanned > 0).then_some(false)
    }

    #[test]
    fn a_credential_reaches_only_its_bound_origin_and_leaves_nothing_behind() {
        let Some(b) = bench("net-secret") else {
            return;
        };
        let value = fresh(40);
        let Some(seeded) = Seeded::new("net", value.as_bytes()) else {
            println!("NOT EXERCISED: no usable kernel keyring on this host");
            return;
        };
        let secrets = format!(
            "schema_version = 1\n\n[secrets.origin-token]\ntype = \"bearer\"\nstorage = \
             \"keychain\"\nkeychain = \"{entry}\"\norigins = [\"origin.test:{port}\"]\n\
             header = \"Authorization\"\nprefix = \"Bearer \"\ninjection = [\"egress\"]\n",
            entry = seeded.0,
            port = b.origin.port,
        );
        let mut spec = HostSpec::open("h", &["network.https:*", "secret.use:origin-token"]);
        spec.secrets = Some(secrets);
        let mut h = host(&b, spec);
        let bearer = sha(&format!("Bearer {value}"));
        let with = |url: &str, follow: bool| {
            net("GET", url, follow, r#","credential_handle":"origin-token""#)
        };
        // Sent once to an origin that does not echo it: once the exchange
        // has closed, the broker's memory does not hold it.
        let r = h.call(&with(&b.o("/ok?plain"), false), "s0").done();
        assert_eq!(
            authorization(&b.origin.to("/ok?plain")[0]),
            Some(bearer.clone())
        );
        assert!(r.hops.as_slice()[0].injected);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            memory_holds(b.broker.pid, value.as_bytes()),
            Some(false),
            "broker residue after a sent credential"
        );
        evidence("credential-broker-residue-after-send", "absent");
        // At its bound origin: the header arrives; the echo is redacted.
        let r = h.call(&with(&b.o("/echo-auth"), false), "s1").done();
        let seen = b.origin.to("/echo-auth");
        assert_eq!(seen.len(), 1);
        assert_eq!(authorization(&seen[0]), Some(bearer.clone()));
        let body = r.body.to_bytes();
        assert!(!contains(&body, value.as_bytes()));
        assert!(contains(&body, b"[redacted:origin-token]"));
        assert!(
            header_values(&r, "etag").is_empty(),
            "a header holding it is dropped"
        );
        assert!(r.hops.as_slice()[0].injected);
        evidence("credential-bound-origin", "header-at-origin-digest-equal");
        evidence("credential-echo-redacted", "placeholder-header-dropped");
        // A same-origin redirect: again, as its own use.
        let r = h
            .call(
                &with(&b.o("/redirect?status=302&to=%2Fecho-auth"), true),
                "s2",
            )
            .done();
        assert!(r.hops.iter().all(|hop| hop.injected));
        let last_two: Vec<_> = b.origin.requests().into_iter().rev().take(2).collect();
        assert!(
            last_two
                .iter()
                .all(|req| authorization(req) == Some(bearer.clone()))
        );
        assert_eq!(
            h.count("SELECT uses FROM secret_use WHERE handle = 'origin-token'"),
            4
        );
        evidence("credential-same-origin-redirect", "own-use-each-hop");
        // Another origin: never, whatever the redirect says.
        let before = b.alt.requests().len();
        let r = h
            .call(
                &with(
                    &b.o(&format!("/redirect?status=307&to={}", enc(&b.a("/ok")))),
                    true,
                ),
                "s3",
            )
            .done();
        let hops: Vec<bool> = r.hops.iter().map(|hop| hop.injected).collect();
        assert_eq!(hops, [true, false]);
        let at_alt = b.alt.requests();
        assert_eq!(at_alt.len() - before, 1);
        assert_eq!(authorization(at_alt.last().unwrap()), None);
        evidence("credential-cross-origin-redirect", "never-attached");
        // Asked for at an origin its metadata does not name, or a port that is
        // not its: refused, nothing sent.
        for (n, (url, case)) in [
            (b.a("/ok"), "credential-unbound-origin"),
            (
                format!("https://origin.test:{}/ok", b.alt.port),
                "credential-port-confusion",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let before = b.alt.requests().len();
            let got = h.call(&with(&url, false), &format!("u{n}"));
            assert!(
                matches!(got, Got::Refused(R::CredentialUnavailable)),
                "{case}: {got:?}"
            );
            assert_eq!(b.alt.requests().len(), before);
            evidence(case, "CREDENTIAL_UNAVAILABLE");
        }
        // The runtime can neither write the header nor send the value.
        for (n, (payload, want, case)) in [
            (
                net(
                    "GET",
                    &b.o("/ok"),
                    false,
                    r#","headers":[{"name":"authorization","value":"Bearer x"}]"#,
                ),
                R::HeaderForbidden,
                "runtime-authorization-header",
            ),
            (
                net(
                    "GET",
                    &b.o("/ok"),
                    false,
                    r#","headers":[{"name":"cookie","value":"a=b"}]"#,
                ),
                R::HeaderForbidden,
                "runtime-cookie-header",
            ),
            (
                net("GET", &b.o(&format!("/ok?t={value}")), false, ""),
                R::SecretInRequest,
                "secret-in-request",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let before = b.origin.requests().len();
            let got = h.call(&payload, &format!("w{n}"));
            assert!(
                matches!(got, Got::Refused(r) if r == want),
                "{case}: {got:?}"
            );
            assert_eq!(b.origin.requests().len(), before);
            evidence(case, want.as_str());
        }
        // Residue: the broker's memory and every durable file.
        std::thread::sleep(std::time::Duration::from_millis(200));
        // An origin that echoes the credential back hands the broker response
        // plaintext holding it, and response plaintext passes through
        // `rustls`'s received-plaintext and deframer buffers and the `http`
        // crate's header map, which are freed without being zeroed: a
        // documented residual (ADR-0050 §20, SECRETS.md), measured here and
        // reported as it is — never asserted away. What the credential's own
        // path leaves is asserted absent above.
        let echo_residue = memory_holds(b.broker.pid, value.as_bytes());
        assert!(echo_residue.is_some(), "the broker's memory was read");
        evidence(
            "credential-echo-broker-residue",
            if echo_residue == Some(true) {
                "PRESENT-documented-limitation-response-library-buffers"
            } else {
                "absent"
            },
        );
        let state = std::fs::read_dir(&h.state).unwrap();
        for entry in state.filter_map(Result::ok) {
            if let Ok(bytes) = std::fs::read(entry.path()) {
                assert!(
                    !contains(&bytes, value.as_bytes()),
                    "{}",
                    entry.path().display()
                );
                assert!(!contains(&bytes, &value.as_bytes()[..16]));
            }
        }
        assert!(!b.broker.stderr().contains(&value));
        evidence("credential-durable-state", "no-plaintext-no-prefix");
    }

    // ---- lifecycle, budgets, policy -----------------------------------------

    fn stop_at(point: CrashPoint) -> CrashHook {
        Arc::new(move |at| {
            if at == point {
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        })
    }

    #[test]
    fn crashes_replays_budgets_and_policies_hold_against_the_real_broker() {
        let Some(b) = bench("net-life") else {
            return;
        };
        // A crash after the exchange, and one after the intent: recorded
        // UNKNOWN, and never sent again.
        for (n, (point, sent, case)) in [
            (CrashPoint::NetAfterBroker, 1usize, "crash-after-exchange"),
            (CrashPoint::NetAfterIntent, 0, "crash-after-intent"),
            (CrashPoint::NetAfterResolve, 0, "crash-after-resolve"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut spec = HostSpec::open(case, &["network.https:*"]);
            spec.hook = Some(stop_at(point));
            let mut h = host(&b, spec);
            let path = format!("/ok?crash={n}");
            let payload = net("POST", &b.o(&path), false, r#","body":"7b7d""#);
            assert!(h.send(&payload, Some("once")).is_err(), "{case}: stopped");
            assert_eq!(b.origin.to(&path).len(), sent, "{case}");
            h.restart();
            let recorded = h.rows("SELECT state FROM net_request");
            let want: &[&str] = if point == CrashPoint::NetAfterResolve {
                &[]
            } else {
                &["UNKNOWN"]
            };
            assert_eq!(recorded, want, "{case}");
            // The run died with its incarnation: refused, never re-run.
            let replay = h.call(&payload, "once");
            assert!(
                matches!(replay, Got::Refused(R::UnknownRun)),
                "{case}: {replay:?}"
            );
            assert_eq!(b.origin.to(&path).len(), sent, "{case}: never sent again");
            evidence(
                case,
                &format!("{}-never-resent", want.first().unwrap_or(&"none")),
            );
        }
        // A reused key reaches nothing.
        let mut h = host(&b, HostSpec::open("keys", &["network.https:*"]));
        assert!(matches!(h.get(&b.o("/ok?key"), "same"), Got::Done(_)));
        assert!(matches!(
            h.get(&b.o("/ok?key"), "same"),
            Got::Refused(R::IdempotencyKeyReused)
        ));
        assert_eq!(b.origin.to("/ok?key").len(), 1);
        evidence("idempotency-key-reused", "IDEMPOTENCY_KEY_REUSED-sent-once");
        // A spent budget stays spent: a request, and a redirect's hop.
        let mut spec = HostSpec::open("budget", &["network.https:*"]);
        spec.budget = NetBudget {
            requests: 2,
            ..NetBudget::default()
        };
        let mut h = host(&b, spec);
        assert!(matches!(h.get(&b.o("/ok?b=1"), "b1"), Got::Done(_)));
        let r = h
            .follow(&b.o("/redirect?status=302&to=%2Fok%3Fb%3D3"), "b2")
            .done();
        assert_eq!(r.redirect_ended, Some(E::BudgetExhausted));
        assert!(matches!(
            h.get(&b.o("/ok?b=4"), "b3"),
            Got::Refused(R::BudgetExhausted)
        ));
        assert!(b.origin.to("/ok?b=3").is_empty() && b.origin.to("/ok?b=4").is_empty());
        h.restart();
        assert!(matches!(
            h.get(&b.o("/ok?b=5"), "b5"),
            Got::Refused(R::UnknownRun)
        ));
        assert_eq!(
            h.count("SELECT count(*) FROM net_hop"),
            2,
            "nothing refunded or forgotten"
        );
        evidence("budget-requests", "BUDGET_EXHAUSTED-not-sent");
        evidence("budget-redirect-hop", "BUDGET_EXHAUSTED");
        // The shipped packs decide real requests.
        for (pack, mode, want, resolves, case) in [
            ("safe", Mode::Safe, D::DeniedByRule, false, "policy-safe"),
            (
                "balanced",
                Mode::Balanced,
                D::DefaultDeny,
                false,
                "policy-balanced",
            ),
            (
                "power",
                Mode::Power,
                D::DeniedByRule,
                true,
                "policy-power-internal-range",
            ),
        ] {
            let mut spec = HostSpec::open(case, &["network.https:*"]);
            spec.policy = PolicySet::shipped(pack).unwrap();
            spec.mode = mode;
            let mut h = host(&b, spec);
            let resolved = b.resolutions();
            let got = h.get(&b.o("/ok?pack"), "p1");
            assert!(
                matches!(got, Got::Denied(d, None) if d == want),
                "{pack}: {got:?}"
            );
            assert_eq!(b.resolutions() > resolved, resolves, "{pack}");
            evidence(case, want.as_str());
        }
        assert!(b.origin.to("/ok?pack").is_empty());
        // Taint: a response raises it, and a novel origin then needs an
        // approval no build has.
        let mut spec = HostSpec::open("taint", &["network.https:*"]);
        spec.policy = policy("m5c", TAINT);
        let mut h = host(&b, spec);
        assert!(matches!(h.get(&b.o("/ok?taint"), "t1"), Got::Done(_)));
        let got = h.get(&b.a("/ok?taint"), "t2");
        assert!(
            matches!(got, Got::Denied(D::ApprovalRequired, None)),
            "{got:?}"
        );
        assert!(matches!(h.get(&b.o("/ok?taint=again"), "t3"), Got::Done(_)));
        assert!(b.alt.to("/ok?taint").is_empty());
        evidence("taint-novel-destination", "APPROVAL_REQUIRED-denied");
        evidence("taint-seen-destination", "allowed");
    }
}
