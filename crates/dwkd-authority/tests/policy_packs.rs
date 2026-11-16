//! F-12 (ADR-0066, Proposed): the three shipped policy packs through the
//! authority's own decision path -- the in-process authority, a real
//! workspace tree beneath a pinned root, the real resolver, and a broker that
//! records whether it was asked. Every case prints one `F12-MATRIX` line: the
//! pack, the canonical action, both gates, the rule, the obligations, the
//! reason and what the invocation did.
//!
//! Policy `ALLOW` is not permission: an action is performed only when both
//! gates pass and every obligation is one this build enforces. The broker
//! here performs nothing; the real reads are `broker_fs_read.rs`'s.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::dwkp::fsops::ToolCall;
    use dwk_proto::wire::id::{RunId, SessionId};
    use dwk_proto::wire::scalar::{Epoch, IdempotencyKey};
    use dwkd_authority::broker::{
        BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Unreachable,
    };
    use dwkd_authority::state::{
        Authority, CallerContext, HostAnchors, ManualClock, Mode, PolicySet, Reply, StartOptions,
        StartupConfig, ToolPlan, ToolReply, ToolRequest,
    };

    use super::broker_support::{FSOPS_CAPABILITIES, Setup, fsops_ceiling};
    use super::state_support::{START_MS, admit_msg, decode, session, subject};
    use super::transport_support::own_uid;

    /// A broker that performs nothing and counts what it was asked.
    #[derive(Debug, Default)]
    struct Recording {
        orders: AtomicUsize,
    }

    impl EffectBroker for Recording {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            self.orders.fetch_add(1, Ordering::SeqCst);
            drop(order);
            Err(BrokerError::before_sending(BrokerFailure::Unreachable(
                Unreachable::Connect,
            )))
        }
    }

    struct Live {
        caller: CallerContext,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
    }

    fn mode(pack: &str) -> Mode {
        match pack {
            "safe" => Mode::Safe,
            "balanced" => Mode::Balanced,
            _ => Mode::Power,
        }
    }

    fn start(setup: &Setup, pack: &str, anchors: HostAnchors) -> (Authority, Arc<Recording>) {
        let broker = Arc::new(Recording::default());
        let mut config = StartupConfig::new(
            PolicySet::shipped(pack).unwrap(),
            mode(pack),
            fsops_ceiling(),
        );
        config.anchors = anchors;
        let performer: Arc<dyn EffectBroker> = broker.clone();
        let options = StartOptions {
            clock: Arc::new(ManualClock::new(START_MS)),
            crash_hook: None,
            broker: Some(performer),
        };
        let _guard = super::state_support::spawn_guard();
        let (authority, _) =
            Authority::start(&setup.state(), &config, options).expect("the authority starts");
        (authority, broker)
    }

    fn live(authority: &mut Authority, n: u64, capabilities: &[&str]) -> Live {
        let caller = authority.connect(subject(own_uid()));
        let session = session(n);
        let Reply::Done(epoch) = authority.acquire_lease(&caller, &session).unwrap() else {
            panic!("a lease")
        };
        let admit = admit_msg(
            &session,
            epoch,
            &format!("k{n}"),
            "maintainer",
            &[],
            capabilities,
            n,
        );
        let Reply::Done(admission) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("an admission")
        };
        Live {
            caller,
            session,
            epoch,
            run: admission.run_id().clone(),
        }
    }

    fn request(payload: &str, key: &str) -> ToolRequest {
        let text = format!(
            r#"{{"v":1,"id":"{}","type":"request","schema":"direwolf.tool.invoke","schema_version":2,"ts":"2026-09-24T10:00:00.000Z","session_id":"{}","run_id":"{}","epoch":1,"idempotency_key":"k","payload":{payload}}}"#,
            super::state_support::id("msg", 1),
            session(1).as_str(),
            super::state_support::run_id(1).as_str()
        );
        let call: ToolCall = match decode(&text).body {
            DwkpBody::ToolInvokeV2(call) => call,
            other => panic!("{other:?}"),
        };
        ToolRequest::v2(call, Some(IdempotencyKey::new(key).unwrap()))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// One case: a call, and what is expected of its first decisive action.
    struct Case {
        name: &'static str,
        payload: String,
    }

    fn read(name: &'static str, path: &str) -> Case {
        Case {
            name,
            payload: format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":64}}}}"#),
        }
    }

    fn cases() -> Vec<Case> {
        vec![
            read("read", "/workspace/a.txt"),
            Case {
                name: "list",
                payload: r#"{"fs_list":{"path":"/workspace/src","max_entries":16}}"#.to_owned(),
            },
            Case {
                name: "stat",
                payload: r#"{"fs_stat":{"path":"/workspace/a.txt"}}"#.to_owned(),
            },
            Case {
                name: "write",
                payload: format!(
                    r#"{{"fs_write":{{"path":"/workspace/a.txt","content":"{}"}}}}"#,
                    hex(b"changed\n")
                ),
            },
            Case {
                name: "create",
                payload: format!(
                    r#"{{"fs_write":{{"path":"/workspace/new.txt","content":"{}"}}}}"#,
                    hex(b"new\n")
                ),
            },
            Case {
                name: "delete",
                payload: r#"{"fs_delete":{"path":"/workspace/empty"}}"#.to_owned(),
            },
            // The resolver's refusals: a symlink out of the workspace, a host
            // path, a traversal. Policy is never consulted for any of them.
            read("symlink-out", "/workspace/link"),
            read("host-absolute", "/etc/shadow"),
            read("traversal", "/workspace/../outside/secret"),
        ]
    }

    /// What a preview decided and an invocation did, as one comparable line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Row {
        /// The reason of each action, in plan order, or the refusal.
        decided: Vec<String>,
        /// The rule each action was decided by.
        rules: Vec<String>,
        /// What the invocation came to.
        outcome: String,
        /// How many orders the broker received for it.
        orders: usize,
    }

    fn decided(plan: &ToolPlan) -> (Vec<String>, Vec<String>) {
        plan.actions()
            .iter()
            .map(|action| {
                (
                    format!("{:?}", action.reason()),
                    action.record().policy().rule_id().as_str().to_owned(),
                )
            })
            .unzip()
    }

    fn row(authority: &mut Authority, broker: &Recording, l: &Live, case: &Case, key: &str) -> Row {
        let preview = authority
            .tool_preview(
                &l.caller,
                &l.session,
                &l.run,
                l.epoch,
                &request(&case.payload, &format!("{key}p")),
            )
            .expect("the authority answers");
        let (decided, rules) = match &preview {
            ToolReply::Previewed(plan) => decided(plan),
            ToolReply::Refused(_, reason) => (vec![format!("Refused({reason:?})")], Vec::new()),
            other => panic!("a preview answered {other:?}"),
        };
        let before = broker.orders.load(Ordering::SeqCst);
        let invoked = authority
            .tool_invoke(
                &l.caller,
                &l.session,
                &l.run,
                l.epoch,
                &request(&case.payload, key),
            )
            .expect("the authority answers");
        let orders = broker.orders.load(Ordering::SeqCst) - before;
        let outcome = match invoked {
            ToolReply::Done { .. } => "DONE".to_owned(),
            ToolReply::Denied(_) => "DENIED".to_owned(),
            ToolReply::Refused(_, reason) => format!("REFUSED({reason:?})"),
            ToolReply::Failed { reason, .. } => format!("FAILED({reason:?})"),
            ToolReply::Previewed(_) => "PREVIEWED".to_owned(),
        };
        Row {
            decided,
            rules,
            outcome,
            orders,
        }
    }

    fn matrix(pack: &str, variant: &str, case: &str, row: &Row) {
        println!(
            "F12-MATRIX {{\"pack\":\"{pack}\",\"variant\":\"{variant}\",\"case\":\"{case}\",\"reasons\":\"{}\",\"rules\":\"{}\",\"outcome\":\"{}\",\"broker_orders\":{}}}",
            row.decided.join("+"),
            row.rules.join("+"),
            row.outcome,
            row.orders
        );
    }

    /// A home directory beside the workspace: the ordinary deployment.
    fn beside(setup: &Setup) -> HostAnchors {
        let home = setup.dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        HostAnchors {
            home: vec![home.to_str().unwrap().to_owned()],
            ..HostAnchors::default()
        }
    }

    fn expect(row: &Row, decided: &[&str], outcome: &str, orders: usize, what: &str) {
        assert_eq!(
            (
                row.decided.iter().map(String::as_str).collect::<Vec<_>>(),
                row.outcome.as_str(),
                row.orders
            ),
            (decided.to_vec(), outcome, orders),
            "{what}: {row:?}"
        );
    }

    /// Every case under one pack, with a home configured beside the
    /// workspace: what each pack is for, and nothing more.
    fn run_pack(pack: &'static str) -> Vec<(&'static str, Row)> {
        let setup = Setup::fsops(&format!("f12-{pack}"));
        let (mut authority, broker) = start(&setup, pack, beside(&setup));
        let l = live(&mut authority, 1, FSOPS_CAPABILITIES);
        cases()
            .iter()
            .enumerate()
            .map(|(n, case)| {
                let row = row(&mut authority, &broker, &l, case, &format!("{pack}{n}"));
                matrix(pack, "home-beside", case.name, &row);
                (case.name, row)
            })
            .collect()
    }

    const ALLOWED: &str = "AllowedByRule";
    const BROKER: &str = "FAILED(BrokerUnavailable)";

    #[test]
    fn safe_reads_the_workspace_and_changes_nothing() {
        let rows = run_pack("safe");
        let by = |name: &str| &rows.iter().find(|(n, _)| *n == name).unwrap().1;
        for name in ["read", "list", "stat"] {
            expect(by(name), &[ALLOWED], BROKER, 1, name);
            assert_eq!(by(name).rules, ["allow-workspace-read"]);
        }
        expect(by("write"), &["DeniedByRule"], "DENIED", 0, "write");
        assert_eq!(by("write").rules, ["deny-workspace-mutation"]);
        expect(
            by("create"),
            &["DeniedByRule", "DeniedByRule"],
            "DENIED",
            0,
            "create",
        );
        expect(by("delete"), &["DeniedByRule"], "DENIED", 0, "delete");
        resolver_refusals(&rows);
    }

    #[test]
    fn balanced_reads_and_refuses_the_writes_it_cannot_capture() {
        let rows = run_pack("balanced");
        let by = |name: &str| &rows.iter().find(|(n, _)| *n == name).unwrap().1;
        for name in ["read", "list", "stat"] {
            expect(by(name), &[ALLOWED], BROKER, 1, name);
        }
        // ALLOW in policy, refused by the authority: `require_artifact_capture`
        // has nothing to capture into before M8, and an obligation this build
        // cannot enforce is not a permission (ADR-0044).
        expect(
            by("write"),
            &["ObligationUnenforceable"],
            "DENIED",
            0,
            "write",
        );
        assert_eq!(by("write").rules, ["allow-workspace-write"]);
        expect(
            by("create"),
            &["ObligationUnenforceable", "ObligationUnenforceable"],
            "DENIED",
            0,
            "create",
        );
        // A delete needs a human; an admitted run's origin is unattended, so
        // the postcondition denies -- approval never becomes ALLOW.
        expect(by("delete"), &["DeniedByRule"], "DENIED", 0, "delete");
        assert_eq!(by("delete").rules, ["deny-approval-needed-when-unattended"]);
        resolver_refusals(&rows);
    }

    #[test]
    fn power_writes_the_workspace_and_is_still_policy() {
        let rows = run_pack("power");
        let by = |name: &str| &rows.iter().find(|(n, _)| *n == name).unwrap().1;
        for name in ["read", "list", "stat", "write", "delete"] {
            expect(by(name), &[ALLOWED], BROKER, 1, name);
        }
        expect(by("create"), &[ALLOWED, ALLOWED], BROKER, 1, "create");
        resolver_refusals(&rows);
    }

    fn resolver_refusals(rows: &[(&str, Row)]) {
        for (name, refusal) in [
            ("symlink-out", "Symlink"),
            ("host-absolute", "OutsideWorkspace"),
            ("traversal", "Traversal"),
        ] {
            let row = &rows.iter().find(|(n, _)| *n == name).unwrap().1;
            assert_eq!(row.orders, 0, "{name}");
            assert!(row.outcome.starts_with("REFUSED("), "{name}: {row:?}");
            assert!(
                row.decided[0].contains(refusal),
                "{name}: expected {refusal}, got {row:?}"
            );
        }
    }

    /// One read under BALANCED with `anchors`, and its row.
    fn balanced_read(tag: &str, anchors: impl FnOnce(&Setup) -> HostAnchors) -> Row {
        let setup = Setup::fsops(tag);
        let anchors = anchors(&setup);
        let (mut authority, broker) = start(&setup, "balanced", anchors);
        let l = live(&mut authority, 1, FSOPS_CAPABILITIES);
        row(
            &mut authority,
            &broker,
            &l,
            &read("read", "/workspace/a.txt"),
            "r",
        )
    }

    #[test]
    fn without_a_home_every_pack_still_refuses_every_read() {
        // No `--path-anchor home=`: `~/.ssh` stands for nothing, and the deny
        // rule naming it is unresolved -- the read is refused, never let
        // through because its first rule could not be evaluated.
        for pack in ["safe", "balanced", "power"] {
            let setup = Setup::fsops(&format!("f12-nohome-{pack}"));
            let (mut authority, broker) = start(&setup, pack, HostAnchors::default());
            let l = live(&mut authority, 1, FSOPS_CAPABILITIES);
            let row = row(
                &mut authority,
                &broker,
                &l,
                &read("read", "/workspace/a.txt"),
                "r",
            );
            matrix(pack, "no-home", "read", &row);
            expect(&row, &["UnresolvedPolicyInput"], "DENIED", 0, pack);
            assert_eq!(row.rules, ["deny-credential-paths"]);
        }
    }

    #[test]
    fn a_home_that_is_the_workspace_is_not_guessed_at() {
        // The home's `.ssh` would be inside the workspace: which paths are
        // under it is not decided by this build, so the rule is not
        // evaluated, and the read is refused.
        let row = balanced_read("f12-home-is-ws", |setup| HostAnchors {
            home: vec![setup.root.to_str().unwrap().to_owned()],
            ..HostAnchors::default()
        });
        matrix("balanced", "home-is-workspace", "read", &row);
        expect(
            &row,
            &["UnresolvedPolicyInput"],
            "DENIED",
            0,
            "home is the workspace",
        );
    }

    #[test]
    fn a_protected_name_that_leads_into_the_workspace_denies_all_of_it() {
        // `~/.ssh` is a symbolic link to the workspace root: followed, the
        // protected location is the workspace, and every path in it is a
        // credential path.
        let row = balanced_read("f12-ssh-link", |setup| {
            let home = setup.dir.path().join("home");
            std::fs::create_dir_all(&home).unwrap();
            std::os::unix::fs::symlink(&setup.root, home.join(".ssh")).unwrap();
            HostAnchors {
                home: vec![home.to_str().unwrap().to_owned()],
                ..HostAnchors::default()
            }
        });
        matrix("balanced", "ssh-links-to-workspace", "read", &row);
        expect(
            &row,
            &["DeniedByRule"],
            "DENIED",
            0,
            "ssh leads into the workspace",
        );
        assert_eq!(row.rules, ["deny-credential-paths"]);
    }

    #[test]
    fn a_workspace_that_holds_direwolfs_configuration_is_not_written_by_power() {
        let setup = Setup::fsops("f12-config-in-ws");
        let mut anchors = beside(&setup);
        anchors.direwolf_config = vec![setup.root.to_str().unwrap().to_owned()];
        let (mut authority, broker) = start(&setup, "power", anchors);
        let l = live(&mut authority, 1, FSOPS_CAPABILITIES);
        let write = &cases()[3];
        let row = row(&mut authority, &broker, &l, write, "w");
        matrix("power", "config-in-workspace", "write", &row);
        expect(&row, &["DeniedByRule"], "DENIED", 0, "self-modification");
        assert_eq!(row.rules, ["deny-direwolf-self-modification"]);
        // Reading it is not modification.
        let read = row_of(
            &mut authority,
            &broker,
            &l,
            &read("read", "/workspace/a.txt"),
            "r",
        );
        expect(&read, &[ALLOWED], BROKER, 1, "read of the configuration");
    }

    fn row_of(
        authority: &mut Authority,
        broker: &Recording,
        l: &Live,
        case: &Case,
        key: &str,
    ) -> Row {
        row(authority, broker, l, case, key)
    }

    #[test]
    fn power_does_not_reach_past_the_capability_gate() {
        // A run admitted with read capabilities only: POWER allows the write
        // in policy, and the authority refuses it -- the run holds no grant.
        let setup = Setup::fsops("f12-nocap");
        let (mut authority, broker) = start(&setup, "power", beside(&setup));
        let l = live(
            &mut authority,
            1,
            &[
                "fs.read:/workspace",
                "fs.list:/workspace",
                "fs.stat:/workspace",
            ],
        );
        let row = row(&mut authority, &broker, &l, &cases()[3], "w");
        matrix("power", "read-only-grants", "write", &row);
        expect(&row, &["NoCapability"], "DENIED", 0, "no write grant");
        assert_eq!(row.rules, ["allow-workspace-write"]);
    }

    #[test]
    fn an_unexaminable_home_refuses_the_start() {
        let setup = Setup::fsops("f12-bad-home");
        for home in [setup.dir.path().join("absent"), setup.root.join("a.txt")] {
            let mut config = StartupConfig::new(
                PolicySet::shipped("balanced").unwrap(),
                Mode::Balanced,
                fsops_ceiling(),
            );
            config.anchors = HostAnchors {
                home: vec![home.to_str().unwrap().to_owned()],
                ..HostAnchors::default()
            };
            let _guard = super::state_support::spawn_guard();
            let Err(error) = Authority::start(&setup.state(), &config, StartOptions::default())
            else {
                panic!("an unexaminable home {home:?} is a start that does not happen")
            };
            assert!(error.to_string().contains("path anchor ~"), "{error}");
        }
    }
}
