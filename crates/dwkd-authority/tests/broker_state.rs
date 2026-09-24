//! M4b's phase boundaries, in process (ADR-0043): what is durable at every
//! instant of one `ToolInvoke`, what a hostile broker can and cannot make the
//! authority believe, and which object the broker reads when the tree changes
//! after the authority checked it.
//!
//! Three kinds of broker appear here, and only one is evidence of the real
//! channel:
//!
//! * `Recording` — a fake that never sees a descriptor (nothing outside the
//!   crate can take one out of an order) and returns bytes it made up. It
//!   measures the state layer's phases and nothing else.
//! * `UnixBroker` to a **scripted peer** this test runs — the production
//!   client, the kernel's `SO_PEERCRED` and `SCM_RIGHTS`, and a peer that
//!   misbehaves on purpose. It measures what the authority accepts.
//! * `UnixBroker` to the **real `dwkd-broker`**, with the tree changed between
//!   the check and the read. It measures which object is read.

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

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{IoSliceMut, Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use dwk_proto::brokerp::{
        self, BrokerDone, BrokerHello, BrokerOutcome, BrokerRefusal, ChannelNonce,
        FsReadAuthorisation, FsReadDone, OutcomeResult,
    };
    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::dwkp::messages::FsReadCall;
    use dwk_proto::frame::FrameDecoder;
    use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
    use dwk_proto::wire::scalar::{
        Epoch, FsFailureReason as ToolFailureReason, HexContent, ReadLimit, WorkspacePath,
    };
    use dwkd_authority::broker::{
        BrokerDelivery, BrokerError, BrokerOrder, EffectBroker, FsReadDelivery, Operation,
        UnixBroker,
    };
    use dwkd_authority::state::{
        Authority, CallerContext, CrashHook, CrashPoint, HookAction, ManualClock, Reply,
        StartOptions, StartReport, ToolReply, ToolRequest, verify_audit_against_store,
    };
    use rustix::fs::{FileType, OFlags};
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};

    use super::broker_support::{Broker, POLICY, Setup, evidence};
    use super::state_support::{
        START_MS, admit_simple, audit_records, config, policy, query_msg, raw, session, subject,
        text,
    };
    use super::transport_support::own_uid;

    const SUITE: &str = "broker-state";

    // ---- the in-process authority ------------------------------------------

    fn start(
        setup: &Setup,
        at_ms: u64,
        hook: Option<CrashHook>,
        broker: Option<Arc<dyn EffectBroker>>,
    ) -> (Authority, StartReport) {
        let options = StartOptions {
            clock: Arc::new(ManualClock::new(at_ms)),
            crash_hook: hook,
            broker,
        };
        let _guard = super::state_support::spawn_guard();
        Authority::start(&setup.state(), &config(policy("m4b", POLICY)), options)
            .expect("the authority starts")
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
        let admit = admit_simple(&session, epoch, &format!("k{n}"), &["fs.read:/workspace"]);
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

    fn call(path: &str, max: u32) -> FsReadCall {
        FsReadCall {
            path: WorkspacePath::new(path).unwrap(),
            max_bytes: ReadLimit::new(max).unwrap(),
        }
    }

    fn invoke(
        authority: &mut Authority,
        l: &Live,
        path: &str,
        max: u32,
    ) -> Result<ToolReply, dwkd_authority::state::AuthorityError> {
        let request = ToolRequest::v1(&call(path, max));
        authority.tool_invoke(&l.caller, &l.session, &l.run, l.epoch, &request)
    }

    /// The bytes an `fs.read` invocation returned.
    fn read_bytes(reply: &ToolReply) -> Vec<u8> {
        let ToolReply::Done { output, .. } = reply else {
            panic!("{reply:?}")
        };
        output
            .fs_read
            .as_ref()
            .map(|read| read.content.to_bytes())
            .expect("an fs.read result")
    }

    fn rows(state: &Path) -> Vec<(String, String)> {
        let conn = raw(state);
        let mut statement = conn
            .prepare("SELECT invocation_id, state FROM tool_invocation ORDER BY intent_ms")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// This process's descriptors on `path`: `(readable, O_PATH)`, read from
    /// `/proc/self/fd` and `/proc/self/fdinfo` -- from outside the code under
    /// test. `O_PATH` (`0o10000000`) cannot read; any other descriptor whose
    /// access mode is `O_RDONLY` or `O_RDWR` can.
    fn descriptors_on(path: &Path) -> (usize, usize) {
        let (mut readable, mut o_path) = (0, 0);
        for entry in std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
        {
            if !std::fs::read_link(entry.path()).is_ok_and(|to| to == path) {
                continue;
            }
            let Ok(info) = std::fs::read_to_string(format!(
                "/proc/self/fdinfo/{}",
                entry.file_name().to_string_lossy()
            )) else {
                continue;
            };
            let flags = info
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .map(|v| u32::from_str_radix(v.trim(), 8).unwrap())
                .expect("a flags line");
            if flags & 0o1000_0000 != 0 {
                o_path += 1;
            } else if flags & 0o3 != 0o1 {
                readable += 1;
            }
        }
        (readable, o_path)
    }

    // ---- a fake broker that records what it was asked ----------------------

    #[derive(Debug, Default)]
    struct Recording {
        calls: AtomicUsize,
        orders: Mutex<Vec<(String, u32, u64)>>,
        reply: Mutex<Option<FsReadDelivery>>,
        /// A file whose descriptors in this process are counted when an
        /// order arrives: `(readable, O_PATH)`.
        watch: Mutex<Option<Watch>>,
    }

    /// A watched file, and its descriptor counts at each order.
    type Watch = (PathBuf, Vec<(usize, usize)>);

    impl EffectBroker for Recording {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let Operation::Read { max_bytes, .. } = order.operation() else {
                panic!("only fs.read is ordered here: {order:?}")
            };
            if let Some((path, seen)) = self.watch.lock().unwrap().as_mut() {
                seen.push(descriptors_on(path));
            }
            self.orders.lock().unwrap().push((
                order.invocation().as_str().to_owned(),
                max_bytes.get(),
                order.identity().inode(),
            ));
            Ok(BrokerDelivery::Read(
                self.reply
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(FsReadDelivery {
                        content: b"made up".to_vec(),
                        eof_observed: true,
                    }),
            ))
        }
    }

    /// A hook that records every point and stops at occurrence `stop_at`.
    fn sweeping_hook(
        stop_at: Option<usize>,
    ) -> (CrashHook, Arc<Mutex<Vec<CrashPoint>>>, Arc<AtomicBool>) {
        let seen: Arc<Mutex<Vec<CrashPoint>>> = Arc::new(Mutex::new(Vec::new()));
        let armed = Arc::new(AtomicBool::new(false));
        let (log, on) = (seen.clone(), armed.clone());
        let hook: CrashHook = Arc::new(move |point| {
            if !on.load(Ordering::SeqCst) {
                return HookAction::Continue;
            }
            let mut log = log.lock().unwrap();
            log.push(point);
            if Some(log.len() - 1) == stop_at {
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        });
        (hook, seen, armed)
    }

    #[test]
    fn every_crash_point_of_an_invocation_leaves_an_honest_record() {
        // The sequence of points one allowed invocation crosses.
        let sequence = {
            let setup = Setup::new("m4b-crash-seq");
            let fake = Arc::new(Recording::default());
            let (hook, seen, armed) = sweeping_hook(None);
            let (mut authority, _) = start(&setup, START_MS + 10_000, Some(hook), Some(fake));
            let l = live(&mut authority, 1);
            armed.store(true, Ordering::SeqCst);
            assert!(matches!(
                invoke(&mut authority, &l, "/workspace/a.txt", 64),
                Ok(ToolReply::Done { .. })
            ));
            seen.lock().unwrap().clone()
        };
        let tool_points: Vec<CrashPoint> = sequence
            .iter()
            .copied()
            .filter(|p| CrashPoint::TOOL.contains(p))
            .collect();
        assert_eq!(tool_points, CrashPoint::TOOL, "b, c, e and f, in order");
        println!(
            "an invocation crosses {} points: {sequence:?}",
            sequence.len()
        );

        for (index, point) in sequence.iter().enumerate() {
            let setup = Setup::new("m4b-crash");
            let fake = Arc::new(Recording::default());
            let (hook, _, armed) = sweeping_hook(Some(index));
            let (mut authority, _) =
                start(&setup, START_MS + 10_000, Some(hook), Some(fake.clone()));
            let l = live(&mut authority, 1);
            armed.store(true, Ordering::SeqCst);
            let answer = invoke(&mut authority, &l, "/workspace/a.txt", 64);
            assert!(
                answer.is_err(),
                "#{index} {point}: a stopped invocation answers nothing"
            );
            drop(authority);

            let (_authority, report) = start(&setup, START_MS + 20_000, None, Some(fake.clone()));
            let state = setup.state();
            let rows = rows(&state);
            let intents = audit_records(&state, "tool.intent_recorded").len();
            let completed = audit_records(&state, "tool.completed").len();
            let interrupted = audit_records(&state, "tool.interrupted").len();
            let tainted = audit_records(&state, "run.taint_raised").len();
            let calls = fake.calls.load(Ordering::SeqCst);
            let what = format!("#{index} {point}: rows {rows:?}, calls {calls}");

            // Nothing is left open, and every row has its records.
            assert!(rows.iter().all(|(_, s)| s != "INTENT"), "{what}");
            assert_eq!(rows.len(), intents, "{what}: a row per intent record");
            assert!(rows.len() <= 1, "{what}");
            // No effect without a durable intent.
            if rows.is_empty() {
                assert_eq!(calls, 0, "{what}: the broker was reached without an intent");
            }
            // An effect is never silent: it completed, or it is interrupted.
            if calls == 1 {
                assert_eq!(rows.len(), 1, "{what}");
            }
            match rows.first().map(|(_, s)| s.as_str()) {
                Some("COMPLETED") => {
                    assert_eq!((completed, interrupted, tainted), (1, 0, 1), "{what}");
                }
                Some("INTERRUPTED") => {
                    assert_eq!((completed, interrupted, tainted), (0, 1, 0), "{what}");
                    assert_eq!(report.invocations_interrupted, 1, "{what}");
                }
                None => assert_eq!((completed, interrupted, tainted), (0, 0, 0), "{what}"),
                Some(other) => panic!("{what}: {other}"),
            }
            let comparison = verify_audit_against_store(&state).unwrap();
            assert_eq!(comparison.pending(), 0, "{what}");
        }
        evidence(
            SUITE,
            "crash-sweep",
            &format!("{}-points", sequence.len()),
            0,
        );
    }

    #[test]
    fn no_descriptor_can_read_the_file_until_its_intent_is_durable() {
        // The order ADR-0043 §7 fixes, measured from /proc at every instant
        // the authority exposes: resolution holds O_PATH handles only; the
        // intent row is committed and its audit record written; only then is
        // the one readable descriptor opened -- and it is gone once the broker
        // has answered.
        let setup = Setup::new("m4b-fd-order");
        let target = std::fs::canonicalize(setup.root.join("a.txt")).unwrap();
        let state = setup.state();
        let fake = Arc::new(Recording::default());
        *fake.watch.lock().unwrap() = Some((target.clone(), Vec::new()));
        type Seen = Vec<(CrashPoint, (usize, usize), bool, Vec<(String, String)>)>;
        let seen: Arc<Mutex<Seen>> = Arc::default();
        let armed = Arc::new(AtomicBool::new(false));
        let hook: CrashHook = {
            let (seen, armed, target, state) =
                (seen.clone(), armed.clone(), target.clone(), state.clone());
            Arc::new(move |point| {
                if armed.load(Ordering::SeqCst) && CrashPoint::TOOL.contains(&point) {
                    let fds = descriptors_on(&target);
                    let logged = std::fs::read_to_string(state.join("audit.log"))
                        .is_ok_and(|log| log.contains("tool.intent_recorded"));
                    seen.lock()
                        .unwrap()
                        .push((point, fds, logged, rows(&state)));
                } else if armed.load(Ordering::SeqCst) {
                    // Every transaction point too: nothing readable yet, or
                    // (after the broker) any more.
                    let fds = descriptors_on(&target);
                    seen.lock().unwrap().push((point, fds, false, Vec::new()));
                }
                HookAction::Continue
            })
        };
        let (mut authority, _) = start(&setup, START_MS + 10_000, Some(hook), Some(fake.clone()));
        let l = live(&mut authority, 1);
        armed.store(true, Ordering::SeqCst);
        let answer = invoke(&mut authority, &l, "/workspace/a.txt", 64).unwrap();
        armed.store(false, Ordering::SeqCst);
        assert!(matches!(answer, ToolReply::Done { .. }), "{answer:?}");
        let seen = seen.lock().unwrap().clone();
        let at = |p: CrashPoint| seen.iter().position(|(q, ..)| *q == p).unwrap();
        let (intent, open, broker) = (
            at(CrashPoint::ToolAfterIntent),
            at(CrashPoint::ToolAfterOpen),
            at(CrashPoint::ToolAfterBroker),
        );
        // Up to and including the durable intent: not one readable descriptor.
        for (point, (readable, _), ..) in &seen[..=intent] {
            assert_eq!(
                *readable, 0,
                "{point}: a readable descriptor before the intent"
            );
        }
        // At the intent the checked object is held -- O_PATH -- and the
        // intent is committed and in the audit log.
        let (_, (_, o_path), logged, rows_then) = &seen[intent];
        assert!(*o_path >= 1, "the resolver's O_PATH handle on the object");
        assert!(*logged, "the intent's audit record precedes the open");
        assert_eq!(rows_then.len(), 1);
        assert_eq!(rows_then[0].1, "INTENT");
        // The first readable descriptor: the very next instant, one of it.
        assert_eq!(open, intent + 1);
        assert_eq!(
            seen[open].1,
            (1, 0),
            "one readable descriptor, O_PATH closed"
        );
        let watched = fake.watch.lock().unwrap().clone().unwrap().1;
        assert_eq!(watched, [(1, 0)], "the broker is handed exactly it");
        // After the broker: nothing on the file stays open.
        for (point, fds, ..) in &seen[broker..] {
            assert_eq!(*fds, (0, 0), "{point}");
        }
        evidence(SUITE, "no-readable-fd-before-intent", "intent-then-open", 1);
    }

    #[test]
    fn an_open_that_fails_after_the_intent_ends_the_invocation_failed() {
        // The name is swapped (OBJECT_CHANGED), or the file made unreadable
        // (OBJECT_UNREADABLE), in the window between the durable intent and
        // the open. The invocation ends FAILED, durably, before the runtime
        // is answered; the broker is never reached; nothing is read or
        // tainted.
        #[derive(Clone, Copy, Debug)]
        enum Change {
            Swap,
            Unreadable,
        }
        let root_uid = own_uid() == 0;
        for change in [Change::Swap, Change::Unreadable] {
            if matches!(change, Change::Unreadable) && root_uid {
                // Root reads a mode-000 file; nothing to measure.
                println!("{change:?}: NOT EXERCISED as root");
                continue;
            }
            let setup = Setup::new("m4b-open-fails");
            let root = setup.root.clone();
            let fake = Arc::new(Recording::default());
            let hook: CrashHook = Arc::new(move |point| {
                if point == CrashPoint::ToolAfterIntent {
                    use std::os::unix::fs::PermissionsExt as _;
                    match change {
                        Change::Swap => {
                            std::fs::write(root.join("other"), b"another object").unwrap();
                            std::fs::rename(root.join("other"), root.join("a.txt")).unwrap();
                        }
                        Change::Unreadable => std::fs::set_permissions(
                            root.join("a.txt"),
                            std::fs::Permissions::from_mode(0o000),
                        )
                        .unwrap(),
                    }
                }
                HookAction::Continue
            });
            let (mut authority, _) =
                start(&setup, START_MS + 10_000, Some(hook), Some(fake.clone()));
            let l = live(&mut authority, 1);
            let answer = invoke(&mut authority, &l, "/workspace/a.txt", 64).unwrap();
            let (expected, class) = match change {
                Change::Swap => (ToolFailureReason::ObjectChanged, "OBJECT_CHANGED"),
                Change::Unreadable => (ToolFailureReason::ObjectUnreadable, "OBJECT_UNREADABLE"),
            };
            let ToolReply::Failed { invocation, reason } = answer else {
                panic!("{change:?}: {answer:?}")
            };
            assert_eq!(reason, expected, "{change:?}");
            assert_eq!(
                fake.calls.load(Ordering::SeqCst),
                0,
                "{change:?}: no broker"
            );
            let state = setup.state();
            assert_eq!(
                rows(&state),
                [(invocation.as_str().to_owned(), "FAILED".to_owned())]
            );
            let failure: String = raw(&state)
                .query_row("SELECT failure FROM tool_invocation", [], |row| row.get(0))
                .unwrap();
            assert_eq!(failure, class);
            let failed = audit_records(&state, "tool.failed");
            assert_eq!(failed.len(), 1);
            assert_eq!(text(&failed[0], "failure"), Some(class));
            assert!(audit_records(&state, "tool.completed").is_empty());
            assert!(audit_records(&state, "run.taint_raised").is_empty());
            // The same authority serves the next invocation normally.
            if matches!(change, Change::Unreadable) {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(
                    setup.root.join("a.txt"),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            drop(authority);
            let (mut authority, report) =
                start(&setup, START_MS + 20_000, None, Some(fake.clone()));
            assert_eq!(report.invocations_interrupted, 0, "it ended; nothing open");
            let l = live(&mut authority, 2);
            assert!(matches!(
                invoke(&mut authority, &l, "/workspace/a.txt", 64).unwrap(),
                ToolReply::Done { .. }
            ));
            assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
            let case = match change {
                Change::Swap => "open-fails-after-intent-object-changed",
                Change::Unreadable => "open-fails-after-intent-object-unreadable",
            };
            evidence(SUITE, case, "failed-no-broker", 0);
        }
    }

    #[test]
    fn an_interrupted_invocation_is_recorded_once_across_restarts() {
        let setup = Setup::new("m4b-interrupt-once");
        let fake = Arc::new(Recording::default());
        let stop: CrashHook = Arc::new(|point| {
            if point == CrashPoint::ToolAfterBroker {
                HookAction::Stop
            } else {
                HookAction::Continue
            }
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, Some(stop), Some(fake.clone()));
        let l = live(&mut authority, 1);
        assert!(invoke(&mut authority, &l, "/workspace/a.txt", 64).is_err());
        drop(authority);
        let (authority, first) = start(&setup, START_MS + 20_000, None, None);
        drop(authority);
        let (_authority, second) = start(&setup, START_MS + 30_000, None, None);
        assert_eq!(first.invocations_interrupted, 1);
        assert_eq!(second.invocations_interrupted, 0);
        assert_eq!(audit_records(&setup.state(), "tool.interrupted").len(), 1);
        evidence(SUITE, "interrupted-once", "recorded-once", 1);
    }

    #[test]
    fn a_delivery_longer_than_authorised_is_a_protocol_failure_and_taints_nothing() {
        let setup = Setup::new("m4b-overlong");
        let fake = Arc::new(Recording::default());
        *fake.reply.lock().unwrap() = Some(FsReadDelivery {
            content: vec![b'x'; 100],
            eof_observed: true,
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, Some(fake.clone()));
        let l = live(&mut authority, 1);
        let answer = invoke(&mut authority, &l, "/workspace/a.txt", 4).unwrap();
        assert!(
            matches!(
                answer,
                ToolReply::Failed {
                    reason: ToolFailureReason::BrokerProtocolError,
                    ..
                }
            ),
            "{answer:?}"
        );
        assert_eq!(rows(&setup.state())[0].1, "FAILED");
        assert!(audit_records(&setup.state(), "run.taint_raised").is_empty());
        evidence(SUITE, "overlong-delivery", "protocol-failure", 1);
    }

    #[test]
    fn the_order_carries_the_decided_bound_and_the_checked_object() {
        let setup = Setup::new("m4b-order");
        let fake = Arc::new(Recording::default());
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, Some(fake.clone()));
        let l = live(&mut authority, 1);
        let ToolReply::Done { invocation, .. } =
            invoke(&mut authority, &l, "/workspace/a.txt", 7).unwrap()
        else {
            panic!("done")
        };
        let orders = fake.orders.lock().unwrap().clone();
        let inode = std::fs::metadata(setup.root.join("a.txt")).unwrap().ino();
        assert_eq!(orders, [(invocation.as_str().to_owned(), 7, inode)]);
    }

    #[test]
    fn an_fs_read_admission_replays_without_resolving_or_minting_anything() {
        // The first admission resolves the path beneath the pinned root. A
        // replay under the same key is answered from the record before any
        // path is looked at: it returns the recorded grant even when the
        // workspace directory has gone, resolves nothing, mints nothing, and
        // writes only the replay's audit record -- and a later tenure is told
        // the admission ended rather than handed a re-minted one.
        let setup = Setup::new("m4b-replay");
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, None);
        let caller = authority.connect(subject(1000));
        let session = session(1);
        let Reply::Done(epoch) = authority.acquire_lease(&caller, &session).unwrap() else {
            panic!("a lease")
        };
        let admit = admit_simple(
            &session,
            epoch,
            "k1",
            &[
                "fs.read:/workspace/src?max_bytes=64",
                "process.exec:/usr/bin/git",
            ],
        );
        let Reply::Done(first) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("admitted")
        };
        let granted = |a: &dwkd_authority::state::Admission| -> Vec<String> {
            a.granted()
                .iter()
                .map(|g| g.capability().to_canonical_string())
                .collect()
        };
        assert_eq!(granted(&first), ["fs.read:/workspace/src?max_bytes=64"]);
        assert_eq!(
            first
                .withheld()
                .iter()
                .map(|w| w.requested().as_str().to_owned())
                .collect::<Vec<_>>(),
            ["process.exec:/usr/bin/git"],
            "process capabilities stay unresolved"
        );
        let counts = |state: &Path| {
            let conn = raw(state);
            let one = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
            (
                one("SELECT count(*) FROM run"),
                one("SELECT count(*) FROM run_grant"),
                one("SELECT count(*) FROM admission_idempotency"),
            )
        };
        let before = counts(&setup.state());
        std::fs::rename(&setup.root, setup.root.with_file_name("gone")).unwrap();
        let Reply::Done(second) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("replayed")
        };
        assert_eq!(second.run_id(), first.run_id());
        assert_eq!(granted(&second), granted(&first));
        assert_eq!(
            counts(&setup.state()),
            before,
            "nothing minted, nothing written"
        );
        assert_eq!(audit_records(&setup.state(), "run.admitted").len(), 1);
        assert_eq!(audit_records(&setup.state(), "run.admit_replayed").len(), 1);
        drop(authority);
        let (mut authority, _) = start(&setup, START_MS + 20_000, None, None);
        let caller = authority.connect(subject(1000));
        let Reply::Done(later) = authority.acquire_lease(&caller, &session).unwrap() else {
            panic!("a new tenure")
        };
        let again = admit_simple(
            &session,
            later,
            "k1",
            &[
                "fs.read:/workspace/src?max_bytes=64",
                "process.exec:/usr/bin/git",
            ],
        );
        assert_eq!(
            authority.admit_run(&caller, &again).unwrap(),
            Reply::Refused(dwk_proto::wire::scalar::RefusalReason::AdmissionEnded)
        );
        assert_eq!(counts(&setup.state()), before);
        evidence(SUITE, "admission-replay-no-remint", "recorded-grant", 0);
    }

    #[test]
    fn a_stored_grant_is_frozen_text_and_each_invocation_resolves_its_target_afresh() {
        // Three paths, kept apart (ADR-0043 §8, ADR-0044 §6):
        //
        //   a NEW declaration  -> the production resolver -> canonical authority
        //   a STORED grant     -> its canonical text, re-read: no re-mint
        //   a TOOL TARGET      -> the production resolver again, at invocation,
        //                         compared with the frozen grant
        //
        // That the stored grant and the replay begin no filesystem lookup at
        // all is measured inside the crate, by a counter that exists only in
        // its unit tests (`src/state/lookup_tests.rs`); here, what each path
        // answers when the object behind the grant is gone or replaced.
        use dwkd_authority::state::Admission;

        let setup = Setup::new("m4c-grant-frozen");
        std::fs::write(setup.root.join("a.txt"), b"first").unwrap();
        let fake = Arc::new(Recording::default());
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, Some(fake.clone()));
        let caller = authority.connect(subject(1000));
        let session = session(1);
        let Reply::Done(epoch) = authority.acquire_lease(&caller, &session).unwrap() else {
            panic!("a lease")
        };
        let declared = ["fs.read:/workspace/a.txt?max_bytes=64"];
        let granted = |a: &Admission| -> Vec<String> {
            a.granted()
                .iter()
                .map(|g| g.capability().to_canonical_string())
                .collect()
        };
        let grant_rows = |state: &Path| -> i64 {
            raw(state)
                .query_row("SELECT count(*) FROM run_grant", [], |r| r.get(0))
                .unwrap()
        };

        // A new declaration is resolved.
        let admit = admit_simple(&session, epoch, "k1", &declared);
        let Reply::Done(first) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("admitted")
        };
        assert_eq!(granted(&first), declared);
        let minted = grant_rows(&setup.state());

        // The replay under the same key: the record.
        let Reply::Done(replayed) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("replayed")
        };
        assert_eq!(granted(&replayed), declared);

        // 1. The object deleted: the stored grant rehydrates unchanged —
        //    re-read for a query, and for a replay.
        std::fs::remove_file(setup.root.join("a.txt")).unwrap();
        let query = query_msg(&session, first.run_id(), epoch, None);
        let DwkpBody::EffectiveAuthority(answer) = authority.dispatch(&caller, &query).unwrap()
        else {
            panic!("an answer")
        };
        let texts: Vec<&str> = answer
            .granted
            .iter()
            .map(|g| g.capability.as_str())
            .collect();
        assert_eq!(texts, declared);
        // 2. And the replay after the deletion: the same grant.
        let Reply::Done(after_delete) = authority.admit_run(&caller, &admit).unwrap() else {
            panic!("replayed")
        };
        assert_eq!(granted(&after_delete), declared);

        // 3. A NEW admission of the deleted path: resolved now, and withheld.
        let again = admit_simple(&session, epoch, "k2", &declared);
        let Reply::Done(fresh) = authority.admit_run(&caller, &again).unwrap() else {
            panic!("admitted")
        };
        assert!(granted(&fresh).is_empty());
        assert_eq!(
            fresh
                .withheld()
                .iter()
                .map(|w| (w.requested().as_str().to_owned(), w.cause().code()))
                .collect::<Vec<_>>(),
            // `UNRESOLVED_RESOURCE` on the wire.
            [(declared[0].to_owned(), "NEEDS_CANONICAL_PATH")]
        );

        // 4. A ToolInvoke on the deleted path: its target is resolved at
        //    invocation, and there is nothing there. Nothing recorded, nothing
        //    ordered.
        let l = Live {
            caller,
            session,
            epoch,
            run: first.run_id().clone(),
        };
        let reply = invoke(&mut authority, &l, "/workspace/a.txt", 8).unwrap();
        assert!(
            matches!(
                reply,
                ToolReply::Refused(_, dwk_proto::wire::scalar::FsRefusalReason::NotFound)
            ),
            "{reply:?}"
        );
        assert!(rows(&setup.state()).is_empty());
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);

        // 5. Another object at the same canonical path: the invocation
        //    resolves it afresh — the order names the new inode — and the
        //    frozen grant covers its canonical path. Nothing is re-minted.
        std::fs::write(setup.root.join("a.txt"), b"second").unwrap();
        let inode = std::fs::metadata(setup.root.join("a.txt")).unwrap().ino();
        let reply = invoke(&mut authority, &l, "/workspace/a.txt", 8).unwrap();
        assert!(matches!(reply, ToolReply::Done { .. }), "{reply:?}");
        assert_eq!(fake.orders.lock().unwrap().last().map(|o| o.2), Some(inode));
        assert_eq!(
            grant_rows(&setup.state()),
            minted,
            "the stored grant was not re-minted"
        );
        assert_eq!(audit_records(&setup.state(), "run.admitted").len(), 2);
        for (case, outcome) in [
            ("stored-grant-rehydrated-after-delete", "identical"),
            ("admission-replay", "recorded-grant"),
            ("new-admission-of-deleted-path", "withheld"),
            ("invoke-on-deleted-path", "NOT_FOUND-nothing-recorded"),
            ("replaced-object-same-path", "resolved-afresh-not-reminted"),
        ] {
            println!(
                "FSOP-EVIDENCE {{\"suite\":\"grant-rehydration\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
            );
        }
    }

    // ---- which object is read, when the tree changes after the check -------

    /// The real channel to the real broker, with something done to the tree
    /// after the authority opened the file and before the broker reads it.
    #[derive(Debug)]
    struct ChangeThenReal {
        inner: UnixBroker,
        change: Change,
        root: PathBuf,
    }

    impl EffectBroker for ChangeThenReal {
        fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
            (self.change)(&self.root);
            self.inner.perform(order)
        }
    }

    /// Something done to the workspace between the check and the read.
    type Change = fn(&Path);

    fn replace_by_rename(root: &Path) {
        let staged = root.join(".staged");
        std::fs::write(&staged, b"REPLACEMENT").unwrap();
        std::fs::rename(&staged, root.join("a.txt")).unwrap();
    }

    fn replace_by_symlink(root: &Path) {
        let outside = root.parent().unwrap().join("outside").join("secret");
        std::fs::remove_file(root.join("a.txt")).unwrap();
        std::os::unix::fs::symlink(outside, root.join("a.txt")).unwrap();
    }

    fn rewrite_in_place(root: &Path) {
        std::fs::write(root.join("a.txt"), b"REWRITTEN").unwrap();
    }

    fn read_after(tag: &str, change: Change) -> (Setup, ToolReply, u64) {
        let setup = Setup::new(tag);
        let original = std::fs::metadata(setup.root.join("a.txt")).unwrap().ino();
        let broker = Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        let link = Arc::new(ChangeThenReal {
            inner: UnixBroker::new(setup.broker_socket(), own_uid()),
            change,
            root: setup.root.clone(),
        });
        let (mut authority, _) = start(&setup, START_MS + 10_000, None, Some(link));
        let l = live(&mut authority, 1);
        let answer = invoke(&mut authority, &l, "/workspace/a.txt", 64).unwrap();
        broker.wait_for("executed", 1);
        (setup, answer, original)
    }

    #[test]
    fn a_name_replaced_after_the_check_does_not_redirect_the_read() {
        let changes: [(&str, Change); 2] = [
            ("m4b-swap-rename", replace_by_rename),
            ("m4b-swap-symlink", replace_by_symlink),
        ];
        for (tag, change) in changes {
            let (setup, answer, original) = read_after(tag, change);
            assert!(
                matches!(answer, ToolReply::Done { .. }),
                "{tag}: {answer:?}"
            );
            assert_eq!(
                read_bytes(&answer),
                b"hello, workspace\n",
                "{tag}: the checked object"
            );
            let now = std::fs::read(setup.root.join("a.txt")).unwrap();
            assert_ne!(
                now, b"hello, workspace\n",
                "{tag}: the name does point elsewhere"
            );
            let intent = &audit_records(&setup.state(), "tool.intent_recorded")[0];
            assert_eq!(
                super::state_support::text(intent, "object_inode"),
                Some(original.to_string().as_str())
            );
            evidence(SUITE, tag, "read-the-checked-object", 1);
        }
    }

    #[test]
    fn an_in_place_rewrite_is_read_because_the_authorisation_names_the_object_not_its_bytes() {
        // Stated, not hidden: the authority authorises an OBJECT. Whoever can
        // write that file can change what it holds between the check and the
        // read, and the outcome records the digest of what was actually read.
        let (setup, answer, _) = read_after("m4b-rewrite", rewrite_in_place);
        assert_eq!(read_bytes(&answer), b"REWRITTEN");
        let done = &audit_records(&setup.state(), "tool.completed")[0];
        assert_eq!(super::state_support::int(done, "bytes_returned"), Some(9));
        evidence(SUITE, "in-place-rewrite", "object-not-content", 1);
    }

    // ---- a scripted peer on the real channel -------------------------------

    /// How the scripted peer misbehaves.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Script {
        Honest,
        WrongChannel,
        WrongInvocation,
        TooManyBytes,
        BothResults,
        Garbage,
        OversizedHeader,
        CloseAfterAuthorisation,
        Stall,
        NoHello,
        Refuse,
    }

    /// What the scripted peer observed.
    #[derive(Debug, Default)]
    struct Observed {
        authorisation: Option<String>,
        descriptors: usize,
        read_only: bool,
        o_path: bool,
        regular: bool,
        identity: (u64, u64),
        bytes_before_hello: usize,
    }

    fn channel() -> ChannelNonce {
        ChannelNonce::new("00112233445566778899aabbccddeeff").unwrap()
    }

    fn receive(stream: &UnixStream) -> (Vec<u8>, Vec<OwnedFd>) {
        let mut decoder = FrameDecoder::new();
        let mut fds = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        loop {
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let got = rustix::net::recvmsg(
                stream.as_fd(),
                &mut [IoSliceMut::new(&mut buffer)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            for message in control.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            assert!(got.bytes > 0, "the authority closed before authorising");
            let (_, frame) = decoder.feed(&buffer[..got.bytes]).unwrap();
            if let Some(frame) = frame {
                return (frame.body, fds);
            }
        }
    }

    fn scripted_peer(path: PathBuf, script: Script) -> JoinHandle<Observed> {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Observed::default();
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut early = [0u8; 64];
            if let Ok(n) = stream.read(&mut early) {
                seen.bytes_before_hello = n;
            }
            if script == Script::NoHello {
                std::thread::sleep(Duration::from_millis(1200));
                return seen;
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .write_all(&brokerp::encode_frame(&BrokerHello::new(channel())).unwrap())
                .unwrap();
            let (body, fds) = receive(&stream);
            seen.authorisation = Some(String::from_utf8(body.clone()).unwrap());
            seen.descriptors = fds.len();
            if let Some(fd) = fds.first() {
                let flags = rustix::fs::fcntl_getfl(fd).unwrap();
                seen.read_only = flags & OFlags::RWMODE == OFlags::RDONLY;
                seen.o_path = flags.contains(OFlags::PATH);
                let st = rustix::fs::fstat(fd).unwrap();
                seen.regular = FileType::from_raw_mode(st.st_mode) == FileType::RegularFile;
                seen.identity = (st.st_dev, st.st_ino);
            }
            let authorisation = FsReadAuthorisation::decode_frame_body(&body).unwrap();
            let done = |bytes: &[u8]| {
                OutcomeResult::Done(BrokerDone::read(FsReadDone {
                    content: HexContent::from_bytes(bytes).unwrap(),
                    eof_observed: true,
                }))
            };
            let outcome = |ch: ChannelNonce, inv: InvocationId, result| {
                brokerp::encode_frame(&BrokerOutcome::new(ch, inv, result)).unwrap()
            };
            let other = InvocationId::parse("inv_01M24BB8G3E0A851TRWE3M8FZF").unwrap();
            let inv = authorisation.invocation_id.clone();
            let reply: Vec<u8> = match script {
                Script::Honest => outcome(channel(), inv, done(b"honest")),
                Script::WrongChannel => outcome(
                    ChannelNonce::new("ffeeddccbbaa99887766554433221100").unwrap(),
                    inv,
                    done(b"honest"),
                ),
                Script::WrongInvocation => outcome(channel(), other, done(b"honest")),
                Script::TooManyBytes => outcome(channel(), inv, done(&[b'x'; 64])),
                Script::BothResults => {
                    let text = format!(
                        r#"{{"channel":"{}","done":{{"content":"6869","eof_observed":true}},"invocation_id":"{}","kind":"broker.outcome","protocol":1,"refused":"READ_FAILED"}}"#,
                        channel().as_str(),
                        inv.as_str()
                    );
                    dwk_proto::frame::encode(dwk_proto::frame::ContentType::Json, text.as_bytes())
                        .unwrap()
                }
                Script::Garbage => {
                    dwk_proto::frame::encode(dwk_proto::frame::ContentType::Json, b"{not json")
                        .unwrap()
                }
                Script::OversizedHeader => vec![0x7f, 0xff, 0xff, 0xff, 0x01],
                Script::CloseAfterAuthorisation => Vec::new(),
                Script::Stall => {
                    std::thread::sleep(Duration::from_millis(1200));
                    Vec::new()
                }
                Script::Refuse => outcome(
                    channel(),
                    inv,
                    OutcomeResult::Refused(BrokerRefusal::IdentityMismatch),
                ),
                Script::NoHello => unreachable!(),
            };
            let _ = stream.write_all(&reply);
            seen
        })
    }

    #[test]
    fn the_authority_believes_only_an_exact_answer_from_the_broker_uid() {
        let cases = [
            (Script::Honest, None),
            (
                Script::WrongChannel,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::WrongInvocation,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::TooManyBytes,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::BothResults,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::Garbage,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::OversizedHeader,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (
                Script::CloseAfterAuthorisation,
                Some(ToolFailureReason::BrokerProtocolError),
            ),
            (Script::Stall, Some(ToolFailureReason::BrokerUnavailable)),
            (Script::NoHello, Some(ToolFailureReason::BrokerUnavailable)),
            (
                Script::Refuse,
                Some(ToolFailureReason::BrokerExecutionError),
            ),
        ];
        for (script, expected) in cases {
            let setup = Setup::new("m4b-peer");
            let peer = scripted_peer(setup.broker_socket(), script);
            let link = Arc::new(
                UnixBroker::new(setup.broker_socket(), own_uid())
                    .with_deadline(Duration::from_millis(800)),
            );
            let (mut authority, _) = start(&setup, START_MS + 10_000, None, Some(link));
            let l = live(&mut authority, 1);
            let answer = invoke(&mut authority, &l, "/workspace/a.txt", 8).unwrap();
            let seen = peer.join().unwrap();
            let state = setup.state();
            match expected {
                None => {
                    assert_eq!(read_bytes(&answer), b"honest", "{script:?}");
                    assert_eq!(rows(&state)[0].1, "COMPLETED");
                }
                Some(reason) => {
                    assert!(
                        matches!(answer, ToolReply::Failed { reason: r, .. } if r == reason),
                        "{script:?}: {answer:?}"
                    );
                    assert_eq!(rows(&state)[0].1, "FAILED", "{script:?}");
                    assert!(
                        audit_records(&state, "run.taint_raised").is_empty(),
                        "{script:?}: nothing was delivered, nothing is tainted"
                    );
                }
            }
            // What the authority sent, whatever the peer did afterwards.
            assert_eq!(
                seen.bytes_before_hello, 0,
                "{script:?}: nothing before the hello"
            );
            if script == Script::NoHello {
                assert!(seen.authorisation.is_none());
            } else {
                let text = seen.authorisation.as_deref().unwrap();
                assert!(
                    !text.contains("a.txt") && !text.contains("/workspace"),
                    "{text}"
                );
                assert_eq!(seen.descriptors, 1, "{script:?}");
                assert!(
                    seen.read_only && !seen.o_path && seen.regular,
                    "{script:?}: {seen:?}"
                );
                let meta = std::fs::metadata(setup.root.join("a.txt")).unwrap();
                assert_eq!(seen.identity, (meta.dev(), meta.ino()));
            }
            evidence(
                SUITE,
                &format!("hostile-broker-{script:?}").to_lowercase(),
                expected.map_or("DONE", |r| r.as_str()),
                1,
            );
        }
    }
}
