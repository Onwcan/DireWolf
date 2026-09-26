//! M4c race and crash campaigns (ADR-0044 §10): the in-process authority,
//! the real broker binary on the private channel, and the real kernel.
//!
//! **Races.** A wrapper around the real channel changes the workspace after
//! the authority checked and handed the objects over and before the broker
//! acts — the widest window a concurrent writer of the workspace has, were the
//! permission model to admit one (ADR-0044 §8 excludes an untrusted one). In
//! every case the substituted object survives exactly as it was left, and no
//! persistent change is made: the broker's check immediately before its change
//! refuses it. What a substitution *after* that check does — a transient
//! change, undone — is measured in the broker's own unit tests, where that
//! instant can be chosen.
//!
//! **Crashes.** The authority is stopped at each point between an
//! invocation's phases (a crash hook), and the broker is aborted at each point
//! inside the operations that change names (`DWKD_BROKER_CRASH_AT`, a debug
//! build). Afterwards the store says what it can prove — `COMPLETED`,
//! `FAILED`, or `UNKNOWN` for an effect nothing proves — the authority, on
//! restart, performs nothing, and a runtime's retry (with a new key) of a
//! retry-safe tool converges while a non-retryable one finds its effect done.
//!
//! **Staging.** Every staging directory a crash leaves is tracked from the
//! intent, and judged once a broker is at hand: removed when it provably holds
//! only the broker's uncommitted data, retained — the displaced or taken
//! object identified, or the evidence of the effect — otherwise; never judged
//! for its spelling, and never more than one per invocation. A reclamation
//! re-pins the workspace root by its recorded fingerprint and resolves the
//! recorded parent beneath it by identity: a root or a parent renamed,
//! replaced or redirected by a symlink leaves the record `EXPECTED` and the
//! directory found there untouched.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::dwkp::fsops::ToolCall;
    use dwk_proto::wire::id::{RunId, SessionId};
    use dwk_proto::wire::scalar::{
        Epoch, FsFailureReason, FsRefusalReason, IdempotencyKey, PatchOutcome,
    };
    use std::os::unix::fs::PermissionsExt as _;

    use dwk_proto::brokerp::Indeterminate;
    use dwkd_authority::broker::{
        BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation,
        UnixBroker,
    };
    use dwkd_authority::state::{
        Authority, CallerContext, CrashHook, CrashPoint, HookAction, MAX_RECLAIMS_PER_SWEEP,
        ManualClock, Mode, Reply, StartOptions, StartReport, StartupConfig, ToolReply, ToolRequest,
    };
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, FSOPS_CAPABILITIES, FSOPS_POLICY, Setup, fsops_ceiling};
    use super::state_support::{
        START_MS, admit_msg, audit_records, decode, policy, raw, session, subject,
    };
    use super::transport_support::own_uid;

    fn fsop(category: &str, case: &str, outcome: &str) {
        println!(
            "FSOP-EVIDENCE {{\"suite\":\"fs-ops-state\",\"category\":\"{category}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
    }

    // ---- the authority, in process ---------------------------------------------

    fn start(
        setup: &Setup,
        at_ms: u64,
        hook: Option<CrashHook>,
        broker: Arc<dyn EffectBroker>,
    ) -> (Authority, StartReport) {
        let options = StartOptions {
            clock: Arc::new(ManualClock::new(at_ms)),
            crash_hook: hook,
            broker: Some(broker),
        };
        let config =
            StartupConfig::new(policy("m4c", FSOPS_POLICY), Mode::Balanced, fsops_ceiling());
        let _guard = super::state_support::spawn_guard();
        Authority::start(&setup.state(), &config, options).expect("the authority starts")
    }

    struct Live {
        caller: CallerContext,
        session: SessionId,
        epoch: Epoch,
        run: RunId,
    }

    fn live(authority: &mut Authority, n: u64) -> Live {
        let caller = authority.connect(subject(1000));
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
            FSOPS_CAPABILITIES,
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

    /// A version-2 call from its JSON payload, decoded as the server would.
    fn call(payload: &str) -> ToolCall {
        let text = format!(
            r#"{{"v":1,"id":"{}","type":"request","schema":"direwolf.tool.invoke","schema_version":2,"ts":"2026-09-24T10:00:00.000Z","session_id":"{}","run_id":"{}","epoch":1,"idempotency_key":"k","payload":{payload}}}"#,
            super::state_support::id("msg", 1),
            session(1).as_str(),
            super::state_support::run_id(1).as_str()
        );
        match decode(&text).body {
            DwkpBody::ToolInvokeV2(call) => call,
            other => panic!("{other:?}"),
        }
    }

    fn invoke(authority: &mut Authority, l: &Live, payload: &str, key: &str) -> ToolReply {
        let request = ToolRequest::v2(call(payload), Some(IdempotencyKey::new(key).unwrap()));
        authority
            .tool_invoke(&l.caller, &l.session, &l.run, l.epoch, &request)
            .expect("the authority answers")
    }

    fn try_invoke(authority: &mut Authority, l: &Live, payload: &str, key: &str) -> bool {
        let request = ToolRequest::v2(call(payload), Some(IdempotencyKey::new(key).unwrap()));
        authority
            .tool_invoke(&l.caller, &l.session, &l.run, l.epoch, &request)
            .is_ok()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn revision(bytes: &[u8]) -> String {
        format!(
            r#"{{"sha256":"{}","length":{}}}"#,
            hex(&Sha256::digest(bytes)),
            bytes.len()
        )
    }

    fn write(path: &str, content: &[u8]) -> String {
        format!(
            r#"{{"fs_write":{{"path":"{path}","content":"{}"}}}}"#,
            hex(content)
        )
    }

    fn patch(path: &str, base: &[u8], post: &[u8], edit: (u32, u32, &[u8])) -> String {
        format!(
            r#"{{"fs_patch":{{"path":"{path}","base":{},"post":{},"edits":[{{"offset":{},"delete":{},"insert":"{}"}}]}}}}"#,
            revision(base),
            revision(post),
            edit.0,
            edit.1,
            hex(edit.2)
        )
    }

    fn moved(source: &str, destination: &str) -> String {
        format!(r#"{{"fs_move":{{"source":"{source}","destination":"{destination}"}}}}"#)
    }

    fn delete(path: &str) -> String {
        format!(r#"{{"fs_delete":{{"path":"{path}"}}}}"#)
    }

    fn read(path: &str, max: u32) -> String {
        format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":{max}}}}}"#)
    }

    fn failed(reply: &ToolReply) -> FsFailureReason {
        match reply {
            ToolReply::Failed { reason, .. } => *reason,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    fn done(reply: &ToolReply) -> &dwk_proto::dwkp::fsops::ToolOutput {
        match reply {
            ToolReply::Done { output, .. } => output,
            other => panic!("expected a result, got {other:?}"),
        }
    }

    /// `(tool, state)` for every invocation row.
    fn rows(state: &Path) -> Vec<(String, String)> {
        let conn = raw(state);
        let mut statement = conn
            .prepare("SELECT tool, state FROM tool_invocation ORDER BY intent_ms, invocation_id")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// The broker's staging directories left in `dir`.
    fn debris(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".dwkd-"))
            })
            .collect()
    }

    fn local_broker(setup: &Setup) -> Broker {
        Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        )
    }

    // ---- races --------------------------------------------------------------------

    /// The real channel, with something done to the tree after the authority
    /// handed the objects over and before the broker acts.
    #[derive(Debug)]
    struct Racing {
        inner: UnixBroker,
        root: PathBuf,
        change: fn(&Path),
        armed: AtomicBool,
    }

    impl EffectBroker for Racing {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                (self.change)(&self.root);
            }
            self.inner.perform(order)
        }
    }

    /// One race: set up, arm, invoke, return the reply.
    fn race(
        tag: &str,
        prepare: fn(&Path),
        change: fn(&Path),
        payload: &str,
    ) -> (Setup, Broker, ToolReply) {
        let setup = Setup::fsops(tag);
        prepare(&setup.root);
        let broker = local_broker(&setup);
        let racing = Arc::new(Racing {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
            root: setup.root.clone(),
            change,
            armed: AtomicBool::new(true),
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, racing);
        let l = live(&mut authority, 1);
        let reply = invoke(&mut authority, &l, payload, "race");
        (setup, broker, reply)
    }

    const ATTACKER: &[u8] = b"ATTACKER";

    fn swap_in_attacker(root: &Path, name: &str) {
        std::fs::rename(
            root.join(name),
            root.join(format!("{name}.moved-by-attacker")),
        )
        .unwrap();
        std::fs::write(root.join(name), ATTACKER).unwrap();
    }

    fn attacker_at(root: &Path, name: &str) -> bool {
        std::fs::symlink_metadata(root.join(name)).is_ok_and(|m| m.file_type().is_file())
            && std::fs::read(root.join(name)).unwrap() == ATTACKER
    }

    fn nothing(_: &Path) {}

    fn with_target(root: &Path) {
        std::fs::write(root.join("t"), b"checked").unwrap();
        std::fs::create_dir(root.join("d")).unwrap();
    }

    #[test]
    fn a_racing_substitution_is_never_replaced_removed_or_moved_away() {
        type Case = (
            &'static str,
            fn(&Path),
            fn(&Path),
            String,
            FsFailureReason,
            fn(&Path) -> bool,
        );
        let cases: Vec<Case> = vec![
            (
                "R1-write-existing-target-swapped",
                with_target,
                |root| swap_in_attacker(root, "t"),
                write("/workspace/t", b"new"),
                FsFailureReason::ObjectChanged,
                |root| attacker_at(root, "t"),
            ),
            (
                "R2-write-vacant-name-occupied",
                nothing,
                |root| std::fs::write(root.join("fresh"), ATTACKER).unwrap(),
                write("/workspace/fresh", b"new"),
                FsFailureReason::TargetOccupied,
                |root| attacker_at(root, "fresh"),
            ),
            (
                "R3-move-destination-occupied",
                with_target,
                |root| std::fs::write(root.join("d/dest"), ATTACKER).unwrap(),
                moved("/workspace/t", "/workspace/d/dest"),
                FsFailureReason::TargetOccupied,
                |root| {
                    attacker_at(&root.join("d"), "dest")
                        && std::fs::read(root.join("t")).unwrap() == b"checked"
                },
            ),
            (
                "R4-move-source-swapped",
                with_target,
                |root| swap_in_attacker(root, "t"),
                moved("/workspace/t", "/workspace/d/dest"),
                FsFailureReason::ObjectChanged,
                |root| attacker_at(root, "t") && !root.join("d/dest").exists(),
            ),
            (
                "R5-delete-target-swapped",
                with_target,
                |root| swap_in_attacker(root, "t"),
                delete("/workspace/t"),
                FsFailureReason::ObjectChanged,
                |root| attacker_at(root, "t"),
            ),
            (
                "R6-delete-empty-dir-swapped-for-a-full-one",
                with_target,
                |root| {
                    std::fs::rename(root.join("d"), root.join("d.moved")).unwrap();
                    std::fs::create_dir(root.join("d")).unwrap();
                    std::fs::write(root.join("d/f"), ATTACKER).unwrap();
                },
                delete("/workspace/d"),
                FsFailureReason::ObjectChanged,
                |root| attacker_at(&root.join("d"), "f"),
            ),
            (
                "R7-patch-rewritten-in-place",
                |root| std::fs::write(root.join("t"), b"hello, world").unwrap(),
                |root| std::fs::write(root.join("t"), ATTACKER).unwrap(),
                patch(
                    "/workspace/t",
                    b"hello, world",
                    b"hello, there",
                    (7, 5, b"there"),
                ),
                FsFailureReason::Conflict,
                |root| attacker_at(root, "t"),
            ),
            (
                "R8-target-swapped-for-a-symlink",
                with_target,
                |root| {
                    std::fs::remove_file(root.join("t")).unwrap();
                    std::os::unix::fs::symlink(
                        root.parent().unwrap().join("outside/secret"),
                        root.join("t"),
                    )
                    .unwrap();
                },
                write("/workspace/t", b"new"),
                FsFailureReason::ObjectChanged,
                |root| {
                    std::fs::symlink_metadata(root.join("t"))
                        .unwrap()
                        .file_type()
                        .is_symlink()
                        && std::fs::read(root.parent().unwrap().join("outside/secret")).unwrap()
                            == b"OUTSIDE-SECRET"
                },
            ),
        ];
        for (tag, prepare, change, payload, expected, intact) in cases {
            let (setup, broker, reply) = race(tag, prepare, change, &payload);
            assert_eq!(failed(&reply), expected, "{tag}: {}", broker.stderr());
            assert!(
                intact(&setup.root),
                "{tag}: the substituted object did not survive"
            );
            assert!(debris(&setup.root).is_empty(), "{tag}: debris");
            assert_eq!(rows(&setup.state())[0].1, "FAILED", "{tag}");
            fsop("race", tag, "zero-persistent-effect");
        }
    }

    #[test]
    fn a_parent_renamed_away_changes_only_the_checked_directory() {
        // The name the broker changes is the name in the directory the
        // authority checked -- the held descriptor -- not whatever the path
        // spells by the time it acts.
        let setup = Setup::fsops("R9-parent-swapped-run");
        std::fs::create_dir(setup.root.join("d")).unwrap();
        std::fs::write(setup.root.join("d/t"), b"checked, in d").unwrap();
        let broker = local_broker(&setup);
        let racing = Arc::new(Racing {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
            root: setup.root.clone(),
            change: |root| {
                std::fs::rename(root.join("d"), root.join("d.moved")).unwrap();
                std::fs::create_dir(root.join("d")).unwrap();
                std::fs::write(root.join("d/t"), ATTACKER).unwrap();
            },
            armed: AtomicBool::new(true),
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, racing);
        let l = live(&mut authority, 1);
        let reply = invoke(
            &mut authority,
            &l,
            &write("/workspace/d/t", b"replaced"),
            "r9",
        );
        assert!(
            done(&reply).fs_write.is_some(),
            "{reply:?}\n{}",
            broker.stderr()
        );
        assert!(
            attacker_at(&setup.root.join("d"), "t"),
            "the new d/ is untouched"
        );
        assert_eq!(
            std::fs::read(setup.root.join("d.moved/t")).unwrap(),
            b"replaced",
            "the checked directory's name was changed"
        );
        fsop("race", "R9-parent-swapped", "checked-directory-only");
    }

    // ---- crashes of the authority ---------------------------------------------------

    /// A hook that stops at the first `point` once armed.
    fn stop_at(point: CrashPoint) -> (CrashHook, Arc<AtomicBool>) {
        let armed = Arc::new(AtomicBool::new(false));
        let on = armed.clone();
        let hook: CrashHook = Arc::new(move |at| {
            if on.load(Ordering::SeqCst) && at == point {
                on.store(false, Ordering::SeqCst);
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        });
        (hook, armed)
    }

    /// The real channel, counting the **invocations** it is asked to perform.
    /// A staging reclamation is the authority's housekeeping after an
    /// outcome is recorded — never an invocation performed — and is not
    /// counted.
    #[derive(Debug)]
    struct Counting {
        inner: UnixBroker,
        calls: AtomicUsize,
    }

    impl EffectBroker for Counting {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            if !matches!(order.operation(), Operation::Reclaim { .. }) {
                self.calls.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.perform(order)
        }
    }

    /// One staging record: its operation, state, what it holds and the held
    /// object's inode.
    type StagingRow = (String, String, Option<String>, Option<String>);

    /// Every staging record, in order.
    fn staging(state: &Path) -> Vec<StagingRow> {
        let conn = raw(state);
        let mut statement = conn
            .prepare(
                "SELECT operation, state, holds, held_inode FROM tool_staging \
                 ORDER BY recorded_ms, invocation_id",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn row(operation: &str, state: &str) -> StagingRow {
        (operation.to_owned(), state.to_owned(), None, None)
    }

    fn inode(path: &Path) -> String {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(path).unwrap().ino().to_string()
    }

    /// What an authority crash campaign leaves: the setup, the broker, the
    /// store's rows, the invocations performed before and after the restart,
    /// the start report and the restarted authority.
    type Crashed = (
        Setup,
        Broker,
        Vec<(String, String)>,
        usize,
        usize,
        StartReport,
        Authority,
    );

    /// Crash the authority at `point` during `payload`, restart it, and
    /// return the setup, the store's rows, the invocations performed before
    /// and after the restart, and the start report.
    fn authority_crash(tag: &str, prepare: fn(&Path), point: CrashPoint, payload: &str) -> Crashed {
        let setup = Setup::fsops(tag);
        prepare(&setup.root);
        let broker = local_broker(&setup);
        let counting = Arc::new(Counting {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
            calls: AtomicUsize::new(0),
        });
        let (hook, armed) = stop_at(point);
        let (mut authority, _) = start(&setup, START_MS + 10_000, Some(hook), counting.clone());
        let l = live(&mut authority, 1);
        armed.store(true, Ordering::SeqCst);
        assert!(
            !try_invoke(&mut authority, &l, payload, "crash"),
            "{tag}: a stopped invocation answers nothing"
        );
        drop(authority);
        let before = counting.calls.load(Ordering::SeqCst);
        let (authority, report) = start(&setup, START_MS + 20_000, None, counting.clone());
        let after = counting.calls.load(Ordering::SeqCst) - before;
        let rows = rows(&setup.state());
        (setup, broker, rows, before, after, report, authority)
    }

    #[test]
    fn an_authority_crash_is_never_turned_into_a_second_effect() {
        // A: intent durable, nothing handed over -- UNKNOWN, because nothing
        // on this side can prove more, and nothing was done.
        let (setup, _b, rows, before, after, report, mut authority) = authority_crash(
            "A-write-after-intent",
            with_target,
            CrashPoint::ToolAfterIntent,
            &write("/workspace/t", b"new"),
        );
        assert_eq!(rows, [("fs.write".to_owned(), "UNKNOWN".to_owned())]);
        assert_eq!((before, after), (0, 0));
        assert_eq!(report.invocations_unknown, 1);
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"checked");
        // Its staging record was written with the intent; the start-up sweep
        // found no directory (nothing was sent) and settled it.
        assert_eq!(staging(&setup.state()), [row("REPLACE", "CLEARED")]);
        assert_eq!(report.staging.absent, 1);
        // Retry-safe: the runtime's retry, with a new key, converges.
        let l = live(&mut authority, 2);
        let reply = invoke(&mut authority, &l, &write("/workspace/t", b"new"), "retry");
        assert!(done(&reply).fs_write.is_some());
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"new");
        let unknown = audit_records(&setup.state(), "tool.outcome_unknown");
        assert_eq!(
            super::state_support::text(&unknown[0], "cause"),
            Some("restart")
        );
        assert!(debris(&setup.root).is_empty());
        fsop(
            "crash",
            "A-write-after-intent",
            "UNKNOWN-no-effect-retry-converges",
        );

        // B: descriptors made, nothing sent.
        let (setup, _b, rows, before, after, _, _a) = authority_crash(
            "B-move-after-open",
            with_target,
            CrashPoint::ToolAfterOpen,
            &moved("/workspace/t", "/workspace/d/t"),
        );
        assert_eq!(rows, [("fs.move".to_owned(), "UNKNOWN".to_owned())]);
        assert_eq!((before, after), (0, 0), "never performed, before or after");
        assert!(setup.root.join("t").exists() && !setup.root.join("d/t").exists());
        assert!(staging(&setup.state()).is_empty(), "a move stages nothing");
        fsop("crash", "B-move-after-open", "UNKNOWN-not-performed");

        // C: the broker deleted it; the outcome was never recorded.
        let (setup, _b, rows, before, after, report, mut authority) = authority_crash(
            "C-delete-after-broker",
            with_target,
            CrashPoint::ToolAfterBroker,
            &delete("/workspace/t"),
        );
        assert_eq!(rows, [("fs.delete".to_owned(), "UNKNOWN".to_owned())]);
        assert_eq!((before, after), (1, 0), "performed once, and never again");
        assert!(!setup.root.join("t").exists());
        // The broker cleaned up before it answered; the sweep found nothing.
        assert_eq!(staging(&setup.state()), [row("DELETE", "CLEARED")]);
        assert_eq!(report.staging.absent, 1);
        // The runtime's retry finds the effect done, and performs nothing.
        let l = live(&mut authority, 2);
        let reply = invoke(&mut authority, &l, &delete("/workspace/t"), "retry");
        assert!(
            matches!(reply, ToolReply::Refused(_, FsRefusalReason::NotFound)),
            "{reply:?}"
        );
        fsop("crash", "C-delete-after-broker", "UNKNOWN-never-repeated");

        // D: the outcome is durable: it stays COMPLETED.
        let (setup, _b, rows, before, after, report, _a) = authority_crash(
            "D-patch-after-outcome",
            |root| std::fs::write(root.join("t"), b"hello, world").unwrap(),
            CrashPoint::ToolAfterOutcome,
            &patch(
                "/workspace/t",
                b"hello, world",
                b"hello, there",
                (7, 5, b"there"),
            ),
        );
        assert_eq!(rows, [("fs.patch".to_owned(), "COMPLETED".to_owned())]);
        assert_eq!((before, after, report.invocations_unknown), (1, 0, 0));
        assert_eq!(
            std::fs::read(setup.root.join("t")).unwrap(),
            b"hello, there"
        );
        assert_eq!(staging(&setup.state()), [row("REPLACE", "CLEARED")]);
        fsop("crash", "D-patch-after-outcome", "COMPLETED-durable");

        // E: a read has no effect to be unsure of: INTERRUPTED.
        let (_setup, _b, rows, _, after, report, _a) = authority_crash(
            "E-read-after-broker",
            with_target,
            CrashPoint::ToolAfterBroker,
            &read("/workspace/t", 64),
        );
        assert_eq!(rows, [("fs.read".to_owned(), "INTERRUPTED".to_owned())]);
        assert_eq!(
            (
                after,
                report.invocations_interrupted,
                report.invocations_unknown
            ),
            (0, 1, 0)
        );
        fsop("crash", "E-read-after-broker", "INTERRUPTED");
    }

    // ---- crashes of the broker --------------------------------------------------------

    /// Run `payload` against a broker that aborts at `point`; return the
    /// setup, the reply, and the authority (still running) with a live run.
    fn broker_crash(
        tag: &str,
        prepare: fn(&Path),
        point: &str,
        payload: &str,
    ) -> (Setup, ToolReply, Authority, Live) {
        let setup = Setup::fsops(tag);
        prepare(&setup.root);
        let link = Arc::new(UnixBroker::new(setup.broker_socket(), own_uid()));
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, link);
        let l = live(&mut authority, 1);
        let reply = crash_once(&setup, &mut authority, &l, point, payload, "first");
        (setup, reply, authority, l)
    }

    /// One invocation against a broker started to abort at `point`: wait
    /// until it has.
    fn crash_once(
        setup: &Setup,
        authority: &mut Authority,
        l: &Live,
        point: &str,
        payload: &str,
        key: &str,
    ) -> ToolReply {
        let mut broker = Broker::start_crashing_at(&setup.broker_socket(), point);
        let reply = invoke(authority, l, payload, key);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !broker.exited() {
            assert!(
                std::time::Instant::now() < deadline,
                "{point}: the broker did not abort\n{}",
                broker.stderr()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The broker wrote the line before it aborted, but its stderr reaches
        // this process through a reader thread that may not have taken the
        // last line yet: wait for it, bounded, then require it.
        let expected = format!("crash_point point={point}");
        while !broker.stderr().contains(&expected) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(broker.stderr().contains(&expected), "{}", broker.stderr());
        reply
    }

    /// The one staging directory `dir` holds.
    fn the_staging_directory(dir: &Path) -> PathBuf {
        let left = debris(dir);
        assert_eq!(left.len(), 1, "{left:?}");
        left[0].clone()
    }

    #[test]
    fn a_broker_crash_is_unknown_and_a_retry_safe_retry_converges() {
        // F: before the exchange -- the new file is only in the staging
        // directory; the name still holds the old content.
        let (setup, reply, mut authority, l) = broker_crash(
            "F-write-before-exchange",
            with_target,
            "replace.before_exchange",
            &write("/workspace/t", b"new"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert_eq!(
            rows(&setup.state()),
            [("fs.write".to_owned(), "UNKNOWN".to_owned())]
        );
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"checked");
        let left = the_staging_directory(&setup.root);
        // Tracked from the intent, and not yet judged: no broker to ask.
        assert_eq!(staging(&setup.state()), [row("REPLACE", "EXPECTED")]);
        assert!(left.join("record").exists() && left.join("new").exists());
        let _broker = local_broker(&setup);
        let again = invoke(&mut authority, &l, &write("/workspace/t", b"new"), "second");
        assert!(done(&again).fs_write.is_some());
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"new");
        // After the retry, the run's open record was judged: only the
        // broker's own uncommitted file was there, and it is gone.
        assert_eq!(
            staging(&setup.state()),
            [row("REPLACE", "REMOVED"), row("REPLACE", "CLEARED")]
        );
        assert!(debris(&setup.root).is_empty());
        fsop(
            "crash",
            "F-write-before-exchange",
            "UNKNOWN-old-content-retry-converges",
        );
        fsop(
            "staging",
            "staging-F-write-before-exchange",
            "REMOVED-pre-effect",
        );

        // G: after the exchange -- the name holds the new content already,
        // and the staging directory holds the file it displaced.
        let (setup, reply, mut authority, l) = broker_crash(
            "G-write-after-exchange",
            with_target,
            "replace.after_exchange",
            &write("/workspace/t", b"new"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"new");
        let left = the_staging_directory(&setup.root);
        let _broker = local_broker(&setup);
        let again = invoke(&mut authority, &l, &write("/workspace/t", b"new"), "second");
        assert!(!done(&again).fs_write.as_ref().unwrap().created);
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"new");
        // Retained -- the replaced file, identified by the record for the
        // operator and M9 -- and the invocation stays UNKNOWN.
        let displaced = left.join("new");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"checked");
        assert_eq!(
            staging(&setup.state())[0],
            (
                "REPLACE".to_owned(),
                "RETAINED".to_owned(),
                Some("DISPLACED".to_owned()),
                Some(inode(&displaced))
            )
        );
        assert_eq!(rows(&setup.state())[0].1, "UNKNOWN");
        fsop("crash", "G-write-after-exchange", "UNKNOWN-retry-converges");
        fsop(
            "staging",
            "staging-G-write-after-exchange",
            "RETAINED-DISPLACED-identified",
        );

        // H: a patch made durable and not reported: the retry recognises it.
        let (setup, reply, mut authority, l) = broker_crash(
            "H-patch-after-sync",
            |root| std::fs::write(root.join("t"), b"hello, world").unwrap(),
            "replace.after_sync",
            &patch(
                "/workspace/t",
                b"hello, world",
                b"hello, there",
                (7, 5, b"there"),
            ),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert_eq!(
            std::fs::read(setup.root.join("t")).unwrap(),
            b"hello, there"
        );
        let left = the_staging_directory(&setup.root);
        let _broker = local_broker(&setup);
        let again = invoke(
            &mut authority,
            &l,
            &patch(
                "/workspace/t",
                b"hello, world",
                b"hello, there",
                (7, 5, b"there"),
            ),
            "second",
        );
        assert_eq!(
            done(&again).fs_patch.as_ref().unwrap().outcome,
            PatchOutcome::AlreadyApplied
        );
        assert_eq!(std::fs::read(left.join("new")).unwrap(), b"hello, world");
        assert_eq!(staging(&setup.state())[0].2.as_deref(), Some("DISPLACED"));
        fsop(
            "crash",
            "H-patch-after-sync",
            "UNKNOWN-retry-ALREADY_APPLIED",
        );

        // I: a creation renamed in and not reported.
        let (setup, reply, mut authority, l) = broker_crash(
            "I-create-after-rename",
            nothing,
            "create.after_rename",
            &write("/workspace/fresh", b"new"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert_eq!(std::fs::read(setup.root.join("fresh")).unwrap(), b"new");
        let _broker = local_broker(&setup);
        let again = invoke(
            &mut authority,
            &l,
            &write("/workspace/fresh", b"new"),
            "second",
        );
        assert!(
            !done(&again).fs_write.as_ref().unwrap().created,
            "a replacement now"
        );
        assert_eq!(std::fs::read(setup.root.join("fresh")).unwrap(), b"new");
        // The record, and nothing else: the evidence that the rename happened.
        assert_eq!(
            staging(&setup.state())[0],
            (
                "CREATE".to_owned(),
                "RETAINED".to_owned(),
                Some("EVIDENCE".to_owned()),
                None
            )
        );
        fsop("crash", "I-create-after-rename", "UNKNOWN-retry-converges");
        fsop(
            "staging",
            "staging-I-create-after-rename",
            "RETAINED-EVIDENCE",
        );
    }

    #[test]
    fn a_broker_crash_in_a_non_retryable_tool_is_unknown_and_never_repeated() {
        // J: the move happened; nothing says so. The authority never
        // repeats it, and a runtime's retry finds the source gone.
        let (setup, reply, mut authority, l) = broker_crash(
            "J-move-after-rename",
            with_target,
            "move.after_rename",
            &moved("/workspace/t", "/workspace/d/t"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert_eq!(
            rows(&setup.state()),
            [("fs.move".to_owned(), "UNKNOWN".to_owned())]
        );
        assert!(!setup.root.join("t").exists());
        assert_eq!(std::fs::read(setup.root.join("d/t")).unwrap(), b"checked");
        let broker = local_broker(&setup);
        let again = invoke(
            &mut authority,
            &l,
            &moved("/workspace/t", "/workspace/d/t"),
            "second",
        );
        assert!(
            matches!(again, ToolReply::Refused(_, FsRefusalReason::NotFound)),
            "{again:?}"
        );
        assert_eq!(broker.count("connection"), 0);
        assert!(staging(&setup.state()).is_empty());
        fsop("crash", "J-move-after-rename", "UNKNOWN-never-repeated");

        // K: the name taken into the staging directory, not yet removed: the
        // object is still there, under the invocation's own name.
        let (setup, reply, mut authority, _l) = broker_crash(
            "K-delete-after-stage",
            with_target,
            "delete.after_stage",
            &delete("/workspace/t"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert!(!setup.root.join("t").exists());
        let left = the_staging_directory(&setup.root);
        assert_eq!(
            std::fs::read(left.join("held")).unwrap(),
            b"checked",
            "recoverable"
        );
        // A sweep, with a broker back: retained, the taken object named.
        let _broker = local_broker(&setup);
        let sweep = authority
            .reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)
            .unwrap();
        assert_eq!((sweep.retained, sweep.removed), (1, 0));
        assert_eq!(
            staging(&setup.state()),
            [(
                "DELETE".to_owned(),
                "RETAINED".to_owned(),
                Some("TAKEN".to_owned()),
                Some(inode(&left.join("held")))
            )]
        );
        assert_eq!(std::fs::read(left.join("held")).unwrap(), b"checked");
        let settled = audit_records(&setup.state(), "tool.staging_settled");
        assert_eq!(
            super::state_support::text(&settled[0], "holds"),
            Some("TAKEN")
        );
        fsop(
            "crash",
            "K-delete-after-stage",
            "UNKNOWN-object-recoverable",
        );
        fsop(
            "staging",
            "staging-K-delete-after-stage",
            "RETAINED-TAKEN-identified",
        );

        // K': after the removal.
        let (setup, reply, authority, _l) = broker_crash(
            "K2-delete-after-unlink",
            with_target,
            "delete.after_unlink",
            &delete("/workspace/t"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        assert!(!setup.root.join("t").exists());
        fsop("crash", "K2-delete-after-unlink", "UNKNOWN");

        // And on restart the authority performs none of them: its sweep
        // judges the staging directory — the evidence of the removal — and
        // keeps it; no invocation is sent.
        let _broker = local_broker(&setup);
        let counting = Arc::new(Counting {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
            calls: AtomicUsize::new(0),
        });
        drop(authority);
        let (_again, report) = start(&setup, START_MS + 30_000, None, counting.clone());
        assert_eq!(counting.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            report.invocations_unknown, 0,
            "already UNKNOWN, not left open"
        );
        assert_eq!(report.staging.retained, 1);
        let unknown: Vec<String> = rows(&setup.state()).into_iter().map(|r| r.1).collect();
        assert_eq!(unknown, ["UNKNOWN"]);
        assert_eq!(
            staging(&setup.state())[0].2.as_deref(),
            Some("EVIDENCE"),
            "the mark says the object was removed"
        );
        fsop(
            "staging",
            "staging-K2-delete-after-unlink",
            "RETAINED-EVIDENCE",
        );
    }

    /// The real channel, except that a change is answered as a broker whose
    /// undo could not be proved answers it: `indeterminate`, `RESTORE_FAILED`.
    #[derive(Debug)]
    struct RestoreFails {
        inner: UnixBroker,
    }

    impl EffectBroker for RestoreFails {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            match order.operation() {
                Operation::Write { .. } | Operation::Move { .. } | Operation::Delete { .. } => {
                    Err(BrokerError::after_sending(BrokerFailure::Indeterminate(
                        Indeterminate::RestoreFailed,
                    )))
                }
                _ => self.inner.perform(order),
            }
        }
    }

    #[test]
    fn an_undo_the_broker_cannot_prove_is_unknown_never_failed() {
        let setup = Setup::fsops("U-restore-failed");
        with_target(&setup.root);
        let _broker = local_broker(&setup);
        let link = Arc::new(RestoreFails {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, link);
        let l = live(&mut authority, 1);
        for (payload, key) in [
            (write("/workspace/t", b"new"), "w"),
            (moved("/workspace/t", "/workspace/d/t"), "m"),
            (delete("/workspace/t"), "d"),
        ] {
            let reply = invoke(&mut authority, &l, &payload, key);
            assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown, "{payload}");
        }
        let states: Vec<String> = rows(&setup.state()).into_iter().map(|r| r.1).collect();
        assert_eq!(states, ["UNKNOWN", "UNKNOWN", "UNKNOWN"]);
        let unknown = audit_records(&setup.state(), "tool.outcome_unknown");
        assert_eq!(unknown.len(), 3);
        for record in &unknown {
            assert_eq!(
                super::state_support::text(record, "indeterminate"),
                Some("RESTORE_FAILED")
            );
        }
        assert!(audit_records(&setup.state(), "tool.failed").is_empty());
        fsop("crash", "U-restore-failed", "UNKNOWN-never-FAILED");
    }

    // ---- the staging lifecycle (ADR-0044 §10) ---------------------------------------

    #[test]
    fn staging_left_before_any_effect_is_removed_and_nothing_is_performed_again() {
        for (tag, point, payload, operation) in [
            (
                "staging-S1-replace-before-record",
                "replace.before_record",
                write("/workspace/t", b"new"),
                "REPLACE",
            ),
            (
                "staging-S2-patch-before-check",
                "replace.before_check",
                patch("/workspace/t", b"checked", b"checkeD", (6, 1, b"D")),
                "REPLACE",
            ),
            (
                "staging-S3-create-before-check",
                "create.before_check",
                write("/workspace/fresh", b"new"),
                "CREATE",
            ),
            (
                "staging-S4-delete-before-check",
                "delete.before_check",
                delete("/workspace/t"),
                "DELETE",
            ),
        ] {
            let (setup, reply, mut authority, _l) = broker_crash(tag, with_target, point, &payload);
            assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown, "{tag}");
            assert_eq!(debris(&setup.root).len(), 1, "{tag}: left by the crash");
            assert_eq!(
                staging(&setup.state()),
                [row(operation, "EXPECTED")],
                "{tag}"
            );
            let _broker = local_broker(&setup);
            let sweep = authority
                .reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)
                .unwrap();
            assert_eq!((sweep.removed, sweep.retained), (1, 0), "{tag}");
            assert!(debris(&setup.root).is_empty(), "{tag}: gone");
            assert_eq!(
                staging(&setup.state()),
                [row(operation, "REMOVED")],
                "{tag}"
            );
            // The workspace is as it was, and the invocation stays UNKNOWN:
            // removing the broker's own data is not performing it.
            assert_eq!(
                std::fs::read(setup.root.join("t")).unwrap(),
                b"checked",
                "{tag}"
            );
            assert!(!setup.root.join("fresh").exists(), "{tag}");
            assert_eq!(rows(&setup.state())[0].1, "UNKNOWN", "{tag}");
            fsop("staging", tag, "REMOVED-pre-effect");
        }
    }

    #[test]
    fn repeated_crashes_leave_only_tracked_staging_one_per_invocation() {
        let setup = Setup::fsops("S5-repeated-crashes");
        with_target(&setup.root);
        let link = Arc::new(UnixBroker::new(setup.broker_socket(), own_uid()));
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, link);
        let l = live(&mut authority, 1);
        let points = [
            "replace.before_check",
            "replace.after_exchange",
            "replace.before_record",
            "replace.after_sync",
            "replace.before_exchange",
            "replace.after_exchange",
        ];
        let tracked = |state: &Path| {
            let conn = raw(state);
            conn.query_row(
                "SELECT count(*) FROM tool_staging WHERE state IN ('EXPECTED', 'RETAINED')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        for (i, point) in points.iter().enumerate() {
            let content = format!("version {i}");
            let reply = crash_once(
                &setup,
                &mut authority,
                &l,
                point,
                &write("/workspace/t", content.as_bytes()),
                &format!("crash-{i}"),
            );
            assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown, "{point}");
            // Every directory on disk is a tracked record; never more than
            // one per invocation.
            let on_disk = i64::try_from(debris(&setup.root).len()).unwrap();
            assert_eq!(on_disk, tracked(&setup.state()), "{point}");
            assert!(on_disk <= i64::try_from(i + 1).unwrap());
        }
        let _broker = local_broker(&setup);
        let sweep = authority
            .reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)
            .unwrap();
        // Three crashed before any effect: removed. Three after: retained,
        // and still exactly the directories on disk.
        assert_eq!((sweep.removed, sweep.retained, sweep.pending), (3, 3, 0));
        let left = debris(&setup.root);
        assert_eq!(left.len(), 3);
        assert_eq!(tracked(&setup.state()), 3);
        let conn = raw(&setup.state());
        for dir in &left {
            let name = dir.file_name().unwrap().to_str().unwrap();
            let invocation = name.strip_prefix(".dwkd-").unwrap();
            let state: String = conn
                .query_row(
                    "SELECT state FROM tool_staging WHERE invocation_id = ?1",
                    [invocation],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "RETAINED", "{name} is a retained record's");
        }
        fsop(
            "staging",
            "staging-S5-repeated-crash-injection",
            "tracked-bounded",
        );
    }

    #[test]
    fn a_directory_is_never_reclaimed_for_its_spelling() {
        let setup = Setup::fsops("S6-spelling");
        with_target(&setup.root);
        // Two directories spelled like the broker's: one naming no
        // invocation, one naming an invocation the authority never minted —
        // holding what would be disposable if they were the broker's.
        let unrelated = setup.root.join(".dwkd-unrelated");
        let lookalike = setup.root.join(".dwkd-inv_01M24BB8G3E0A851TRWE3M8FZZ");
        for dir in [&unrelated, &lookalike] {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join("new"), b"keep me").unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _broker = local_broker(&setup);
        let link = Arc::new(UnixBroker::new(setup.broker_socket(), own_uid()));
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, link.clone());
        let l = live(&mut authority, 1);
        // A completed write, a refusal whose record a reclamation settles,
        // a sweep, and a restart's sweep.
        assert!(
            done(&invoke(
                &mut authority,
                &l,
                &write("/workspace/t", b"a"),
                "k1"
            ))
            .fs_write
            .is_some()
        );
        std::fs::write(setup.root.join("t"), b"changed").unwrap();
        let refused = invoke(
            &mut authority,
            &l,
            &patch("/workspace/t", b"a", b"b", (0, 1, b"b")),
            "k2",
        );
        assert_eq!(failed(&refused), FsFailureReason::Conflict);
        authority
            .reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)
            .unwrap();
        drop(authority);
        let (_again, report) = start(&setup, START_MS + 20_000, None, link);
        assert_eq!(report.staging.pending, 0);
        for dir in [&unrelated, &lookalike] {
            assert_eq!(
                std::fs::read(dir.join("new")).unwrap(),
                b"keep me",
                "{dir:?}"
            );
        }
        assert!(
            staging(&setup.state()).iter().all(|r| r.1 == "CLEARED"),
            "{:?}",
            staging(&setup.state())
        );
        fsop(
            "staging",
            "staging-S6-unrelated-by-spelling",
            "never-touched",
        );
    }

    // ---- a reclamation is root-pinned, never path-trusting (ADR-0044 §10) ------------

    fn with_nested_target(root: &Path) {
        std::fs::create_dir(root.join("d")).unwrap();
        std::fs::write(root.join("d/t"), b"checked").unwrap();
    }

    /// Put, under `root`, a directory spelled like `name` and made as the
    /// broker makes its own — owner, mode `0700`, holding only a `new` file —
    /// so that a reclamation which followed a path there would remove it.
    fn bait(root: &Path, name: &std::ffi::OsStr) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("new"), b"BAIT").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn untouched(bait: &Path) -> bool {
        std::fs::read(bait.join("new")).is_ok_and(|bytes| bytes == b"BAIT")
    }

    /// One sweep: how many records it left pending, removed and retained.
    fn sweep(authority: &mut Authority) -> (u64, u64, u64) {
        let swept = authority
            .reclaim_staging(None, MAX_RECLAIMS_PER_SWEEP)
            .unwrap();
        assert_eq!((swept.absent, swept.foreign), (0, 0));
        (swept.pending, swept.removed, swept.retained)
    }

    #[test]
    fn a_reclamation_re_pins_the_root_and_never_follows_a_replaced_path() {
        // A crash before any effect leaves a disposable staging directory, its
        // record EXPECTED: exactly what a reclamation removes — so exactly
        // what one that followed a path would remove from somewhere else.
        let (setup, reply, mut authority, _l) = broker_crash(
            "staging-R-root",
            with_target,
            "replace.before_record",
            &write("/workspace/t", b"new"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        let staged = the_staging_directory(&setup.root);
        let name = staged.file_name().unwrap().to_owned();
        let broker_new = std::fs::read(staged.join("new")).unwrap();
        let _broker = local_broker(&setup);
        let original = setup.root.with_extension("original");
        let attacker = setup.root.with_extension("attacker");
        let expected = || assert_eq!(staging(&setup.state()), [row("REPLACE", "EXPECTED")]);

        // R1 and R3: the root renamed away and another directory put at its
        // recorded path, holding a lookalike of the staging directory. The
        // binding is reopened by its path and proved by its fingerprint; the
        // replacement is not the root, so nothing is resolved beneath it.
        std::fs::rename(&setup.root, &original).unwrap();
        std::fs::create_dir(&setup.root).unwrap();
        let lookalike = bait(&setup.root, &name);
        assert_eq!(sweep(&mut authority), (1, 0, 0), "pending, nothing touched");
        assert!(untouched(&lookalike), "the replacement root is not touched");
        assert_eq!(
            std::fs::read(original.join(&name).join("new")).unwrap(),
            broker_new
        );
        expected();
        // And the same at a restart's sweep.
        drop(authority);
        let link = Arc::new(UnixBroker::new(setup.broker_socket(), own_uid()));
        let (mut authority, report) = start(&setup, START_MS + 30_000, None, link);
        assert_eq!((report.staging.pending, report.staging.removed), (1, 0));
        assert!(untouched(&lookalike));
        expected();
        fsop(
            "staging",
            "staging-R1-root-renamed-and-replaced",
            "EXPECTED-replacement-untouched",
        );
        fsop(
            "staging",
            "staging-R3-lookalike-in-replacement-root",
            "never-touched",
        );

        // R2: a symlink at the recorded path, to the attacker's directory —
        // the replacement, moved, with its lookalike — and then to the
        // original root itself. The root is never reached through a link,
        // even one that leads to it.
        std::fs::rename(&setup.root, &attacker).unwrap();
        std::os::unix::fs::symlink(&attacker, &setup.root).unwrap();
        assert_eq!(sweep(&mut authority), (1, 0, 0));
        assert!(untouched(&attacker.join(&name)));
        std::fs::remove_file(&setup.root).unwrap();
        std::os::unix::fs::symlink(&original, &setup.root).unwrap();
        assert_eq!(sweep(&mut authority), (1, 0, 0));
        assert_eq!(
            std::fs::read(original.join(&name).join("new")).unwrap(),
            broker_new
        );
        expected();
        fsop(
            "staging",
            "staging-R2-symlink-at-root-path",
            "EXPECTED-never-followed",
        );

        // R4: the original root is still there, under another name. No pinned
        // root outlives a call — each reclamation reopens the binding — so it
        // is out of reach, and the record stays EXPECTED, until the operator
        // puts it back at its recorded path. Then it is the root by its
        // fingerprint, and its staging directory is judged and removed; the
        // lookalikes never are.
        std::fs::remove_file(&setup.root).unwrap();
        std::fs::rename(&original, &setup.root).unwrap();
        assert_eq!(sweep(&mut authority), (0, 1, 0));
        assert!(!setup.root.join(&name).exists());
        assert!(untouched(&attacker.join(&name)), "the lookalike, never");
        assert_eq!(staging(&setup.state()), [row("REPLACE", "REMOVED")]);
        assert_eq!(std::fs::read(setup.root.join("t")).unwrap(), b"checked");
        fsop(
            "staging",
            "staging-R4-original-root-renamed-then-restored",
            "EXPECTED-then-REMOVED-by-fingerprint",
        );

        // R5: the root intact, the parent beneath it replaced. The recorded
        // parent is resolved beneath the pinned root and must be the directory
        // recorded, by identity; another is never handed to the broker.
        let (setup, reply, mut authority, _l) = broker_crash(
            "staging-R5-parent",
            with_nested_target,
            "replace.before_record",
            &write("/workspace/d/t", b"new"),
        );
        assert_eq!(failed(&reply), FsFailureReason::OutcomeUnknown);
        let parent = setup.root.join("d");
        let name = the_staging_directory(&parent)
            .file_name()
            .unwrap()
            .to_owned();
        let _broker = local_broker(&setup);
        std::fs::rename(&parent, setup.root.join("d.original")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let lookalike = bait(&parent, &name);
        assert_eq!(sweep(&mut authority), (1, 0, 0));
        assert!(untouched(&lookalike));
        std::fs::rename(&parent, setup.root.join("d.attacker")).unwrap();
        std::fs::rename(setup.root.join("d.original"), &parent).unwrap();
        assert_eq!(sweep(&mut authority), (0, 1, 0));
        assert!(debris(&parent).is_empty());
        assert!(untouched(&setup.root.join("d.attacker").join(&name)));
        fsop(
            "staging",
            "staging-R5-parent-replaced-beneath-the-root",
            "EXPECTED-then-REMOVED-by-identity",
        );
    }
}
