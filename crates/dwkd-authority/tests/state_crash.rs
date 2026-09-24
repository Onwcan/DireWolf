//! Crash windows A–G around an authority mutation and its audit record,
//! recovered from real files.
//!
//! Two ways to crash:
//!
//! * **In-process**: a crash hook stops the operation at the window. The
//!   authority poisons itself (as a dead process would be gone), the test
//!   drops it, and a new incarnation starts on the same files.
//! * **A real process**: this test binary re-executes itself as a child which
//!   starts the authority and calls `std::process::abort()` at the window —
//!   no destructors, no rollback, no flush, no clean close. The parent then
//!   starts on what the child left.
//!
//! What neither can simulate is **power loss**: a process crash leaves the
//! page cache intact, so a written-but-unsynced audit line survives it. The
//! power-loss form of window E — the line is gone, or partly gone — is the
//! same on-disk state as window C or D, and those are exercised directly.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dwk_proto::wire::scalar::RefusalReason;
use dwkd_authority::state::{
    AuditEvent, AuthorityError, CrashHook, CrashPoint, HookAction, ManualClock, PoisonReason,
    Reply, StartReport, verify_audit_against_store, verify_audit_log,
};
use state_support::{
    Harness, START_MS, TempDir, admit_simple, audit_records, balanced, count, install_fixtures,
    raw, session, start, subject,
};

/// A hook that stops at one armed point.
fn armed_hook() -> (CrashHook, Arc<Mutex<Option<CrashPoint>>>) {
    let target: Arc<Mutex<Option<CrashPoint>>> = Arc::new(Mutex::new(None));
    let seen = target.clone();
    let hook: CrashHook = Arc::new(move |point| {
        if *seen.lock().unwrap() == Some(point) {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    (hook, target)
}

const fn committed(point: CrashPoint) -> bool {
    !matches!(
        point,
        CrashPoint::BeforeTransaction | CrashPoint::BeforeCommit
    )
}

/// What every recovery must satisfy, whatever the window was.
fn assert_recovered(state: &Path, point: CrashPoint, report: &StartReport) {
    let conn = raw(state);
    let runs = count(&conn, "SELECT count(*) FROM run");
    let records = count(&conn, "SELECT count(*) FROM admission_idempotency");
    let expected = i64::from(committed(point));
    assert_eq!(
        runs, expected,
        "{point}: no lost and no fabricated admission"
    );
    assert_eq!(
        records, expected,
        "{point}: the idempotency record commits with it"
    );
    if committed(point) {
        let state: String = conn
            .query_row("SELECT state FROM run", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            state, "REAPED",
            "{point}: the dead process's run ended with it"
        );
    }
    // The admission is audited exactly once: never lost, never appended twice.
    assert_eq!(
        audit_records(state, AuditEvent::RunAdmitted.as_str()).len(),
        usize::try_from(expected).unwrap(),
        "{point}: audit record count"
    );
    let comparison = verify_audit_against_store(state).unwrap();
    assert_eq!(comparison.pending(), 0, "{point}: nothing left pending");
    assert_eq!(comparison.log_records, comparison.store_head);
    assert_eq!(comparison.store_flushed, comparison.store_head);
    assert!(verify_audit_log(&state.join("audit.log")).is_ok());

    match point {
        CrashPoint::AfterCommitBeforeAudit => {
            assert_eq!(report.audit_appended, 1, "the pending record was appended");
            assert_eq!(report.audit_reconciled, 0);
        }
        CrashPoint::MidAuditRecord => {
            assert!(
                report.audit_torn_tail_bytes > 0,
                "the torn half was removed"
            );
            assert_eq!(report.audit_appended, 1, "and the record replayed whole");
        }
        CrashPoint::AfterAuditWriteBeforeSync | CrashPoint::AfterAuditSyncBeforeMark => {
            assert_eq!(report.audit_reconciled, 1, "found in the log: reconciled");
            assert_eq!(report.audit_appended, 0, "and not appended a second time");
        }
        CrashPoint::BeforeTransaction | CrashPoint::BeforeCommit | CrashPoint::AfterAuditMark => {
            assert_eq!(report.audit_appended, 0);
            assert_eq!(report.audit_reconciled, 0);
            assert_eq!(report.audit_torn_tail_bytes, 0);
        }
        // Crossed only between the phases of a tool invocation (M4b), never by
        // an admission: `CrashPoint::ALL` does not contain them.
        CrashPoint::ToolAfterIntent
        | CrashPoint::ToolAfterOpen
        | CrashPoint::ToolAfterBroker
        | CrashPoint::ToolAfterOutcome => {
            unreachable!("{point} is not a transaction crash point")
        }
    }
}

#[test]
fn every_window_of_an_admission_recovers_without_ambiguity() {
    for point in CrashPoint::ALL {
        let (hook, target) = armed_hook();
        let mut h = Harness::with_hook("window", balanced(), Some(hook));
        let (a, s) = (h.connect(1000), session(1));
        let e = h.lease(&a, &s);
        let message = admit_simple(&s, e, "k1", &["model.call:*"]);
        *target.lock().unwrap() = Some(point);
        assert_eq!(
            h.authority().admit_run(&a, &message),
            Err(AuthorityError::Poisoned(PoisonReason::Interrupted(point))),
            "{point}: the caller receives no authority"
        );
        // The crashed authority is gone for every purpose.
        assert!(matches!(
            h.authority().acquire_lease(&a, &session(2)),
            Err(AuthorityError::Poisoned(_))
        ));
        let report = h.restart().clone();
        assert_recovered(&h.state(), point, &report);

        // The pre-crash caller's retry meets the fence, whatever it holds.
        assert_eq!(
            h.authority().admit_run(&a, &message).unwrap(),
            Reply::Refused(RefusalReason::StaleEpoch),
            "{point}"
        );
        // A new holder with the same key and request: a committed admission
        // spent the key -- its run was reaped by the restart, so it is
        // ADMISSION_ENDED, never a replay of dead authority and never a second
        // run (ADR-0040); an uncommitted one never happened, so the key is
        // free.
        let b = h.connect(1000);
        let fresh = h.lease(&b, &s);
        assert!(fresh > e, "{point}: epochs only move forward");
        let again = h
            .authority()
            .admit_run(&b, &admit_simple(&s, fresh, "k1", &["model.call:*"]))
            .unwrap();
        if committed(point) {
            assert_eq!(
                again,
                Reply::Refused(RefusalReason::AdmissionEnded),
                "{point}"
            );
        } else {
            assert!(matches!(again, Reply::Done(_)), "{point}: {again:?}");
        }
    }
}

#[test]
fn a_crash_after_a_lease_commits_never_lets_its_epoch_be_reused() {
    let (hook, target) = armed_hook();
    let mut h = Harness::with_hook("lease-window", balanced(), Some(hook));
    let (a, s) = (h.connect(1000), session(1));
    *target.lock().unwrap() = Some(CrashPoint::AfterCommitBeforeAudit);
    assert!(
        h.authority().acquire_lease(&a, &s).is_err(),
        "the caller never saw its epoch"
    );
    let report = h.restart().clone();
    assert_eq!(
        report.leases_invalidated, 1,
        "the committed lease is invalidated, not lost"
    );
    let b = h.connect(1000);
    assert_eq!(
        h.lease(&b, &s).get(),
        2,
        "epoch 1 was issued, so it is never issued again"
    );
}

#[test]
fn a_tail_that_is_not_the_pending_record_is_never_treated_as_a_torn_write() {
    // A record is genuinely pending (window C), and the log ends in bytes that
    // are NOT a prefix of it. That is not a crash artefact, whatever its
    // length, and recovery must refuse rather than truncate it away.
    for garbage in [
        b"{\"v\":1,\"seq\":999".to_vec(),
        b"x".to_vec(),
        vec![b'{'; 4096],
    ] {
        let (hook, target) = armed_hook();
        let mut h = Harness::with_hook("foreign-tail", balanced(), Some(hook));
        let (a, s) = (h.connect(1000), session(1));
        let e = h.lease(&a, &s);
        *target.lock().unwrap() = Some(CrashPoint::AfterCommitBeforeAudit);
        let _ = h
            .authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]));
        h.stop();
        let path = h.state().join("audit.log");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(&garbage);
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            matches!(
                h.try_restart(),
                Err(dwkd_authority::state::StartError::Audit(_))
            ),
            "garbage of {} bytes was accepted as a torn tail",
            garbage.len()
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "and nothing was truncated"
        );
    }
}

// ---------------------------------------------------------------------------
// Real processes.
// ---------------------------------------------------------------------------

static ARMED: AtomicBool = AtomicBool::new(false);

/// The child half. Runs only when the parent sets `DW_CRASH_DIR`; as an
/// ordinary test it is ignored, and if run without the variable it does
/// nothing.
#[test]
#[ignore = "executed as a child process by the crash tests"]
fn crash_child() {
    let (Ok(dir), Ok(letter)) = (
        std::env::var("DW_CRASH_DIR"),
        std::env::var("DW_CRASH_POINT"),
    ) else {
        return;
    };
    let point = CrashPoint::ALL
        .into_iter()
        .find(|p| p.letter().to_string() == letter)
        .expect("a crash point letter");
    let hook: CrashHook = Arc::new(move |at| {
        if at == point && ARMED.load(Ordering::SeqCst) {
            // A real crash: no unwinding, no destructors, no rollback, no
            // close. Whatever is on disk now is what the parent recovers.
            std::process::abort();
        }
        HookAction::Continue
    });
    let clock = Arc::new(ManualClock::new(START_MS));
    let (mut authority, _) =
        start(Path::new(&dir), &balanced(), &clock, Some(hook)).expect("the child starts");
    install_fixtures(&mut authority);
    let caller = authority.connect(subject(1000));
    let s = session(1);
    let Reply::Done(e) = authority.acquire_lease(&caller, &s).unwrap() else {
        panic!("leased")
    };
    ARMED.store(true, Ordering::SeqCst);
    let _ = authority.admit_run(&caller, &admit_simple(&s, e, "k1", &["model.call:*"]));
    // Reaching here means the window was never crossed: the parent treats a
    // clean exit as a failed test.
}

fn crash_in_child(state: &Path, point: CrashPoint) -> std::process::ExitStatus {
    state_support::status(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "crash_child", "--test-threads=1"])
            .env("DW_CRASH_DIR", state)
            .env("DW_CRASH_POINT", point.letter().to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("the child runs")
}

#[test]
fn a_real_process_killed_in_each_audit_window_recovers() {
    for point in [
        CrashPoint::BeforeCommit,
        CrashPoint::AfterCommitBeforeAudit,
        CrashPoint::MidAuditRecord,
        CrashPoint::AfterAuditWriteBeforeSync,
        CrashPoint::AfterAuditSyncBeforeMark,
    ] {
        let dir = TempDir::new("child");
        let status = crash_in_child(&dir.state(), point);
        assert!(
            !status.success(),
            "{point}: the child must have died at the window ({status})"
        );
        let clock = Arc::new(ManualClock::new(START_MS));
        let (mut authority, report) =
            start(&dir.state(), &balanced(), &clock, None).expect("the parent recovers the store");
        assert_recovered(&dir.state(), point, &report);
        assert_eq!(
            report.leases_invalidated, 1,
            "{point}: the dead process's lease"
        );
        // The recovered authority works.
        let b = authority.connect(subject(1000));
        let Reply::Done(fresh) = authority.acquire_lease(&b, &session(1)).unwrap() else {
            panic!("{point}: leased after recovery")
        };
        assert!(fresh.get() >= 2, "{point}");
        drop(authority);
        // And a second recovery finds nothing left to do.
        let (_, again) = start(&dir.state(), &balanced(), &clock, None).expect("a clean restart");
        assert_eq!(
            again.audit_appended + again.audit_reconciled + again.audit_torn_tail_bytes,
            0
        );
    }
}
