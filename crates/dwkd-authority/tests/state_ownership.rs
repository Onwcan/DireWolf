//! F-18 (ADR-0063, Proposed): who may hold a session, use a workspace and run
//! under an agent profile -- against real `kernel.db` files.
//!
//! The subject is the uid a caller connected as (`Authority::connect`), the
//! value the DWKP server takes from the kernel. Every test here is in
//! process; `transport_foreign.rs` proves the same refusals for a real second
//! uid through the real server, and the agent evidence for the runtime's
//! kernel-reported uid with three identities.
//!
//! What is proved:
//!
//! * a session is held only by its owner or an operator's delegate, whatever
//!   happened to its lease -- expiry, release, a restart -- and a refused
//!   subject takes over and reaps nothing;
//! * a legacy session, or a bound one, without a declared owner is held by
//!   nobody; a new one is its first acquirer's;
//! * a profile is named only by a subject granted it, refused exactly as a
//!   profile the kernel does not hold;
//! * a workspace is reached only by its principals, and shared only as the
//!   operator acknowledged;
//! * a revocation ends the subject's leases and runs in its own transaction
//!   -- a stale epoch, a replayed key, a re-acquisition, a restart give
//!   nothing back -- and the fence would refuse even had it not;
//! * a migration grants nothing from history, and the single-principal
//!   adoption refuses whatever history shows of another subject;
//! * nothing a runtime sends names a subject.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

#[cfg(target_os = "linux")]
use nix as _;
use proptest as _;
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

mod state_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dwk_proto::dwkp;
use dwk_proto::wire::scalar::{AgentProfileName, RefusalReason};
use dwkd_authority::state::{
    Admission, AuditEvent, ConfigError, CrashPoint, HookAction, KERNEL_SCHEMA_VERSION, Reply,
    RevocationStatus, WorkspaceId, WorkspaceSensitivity,
};
use state_support::{
    Harness, admit_msg, admit_simple, audit_records, count, epoch, heartbeat_msg, raw, session,
    subject, text,
};

fn admitted(reply: Reply<Admission>) -> Admission {
    match reply {
        Reply::Done(admission) => admission,
        Reply::Refused(reason) => panic!("refused: {reason:?}"),
    }
}

fn profile(name: &str) -> AgentProfileName {
    AgentProfileName::new(name).unwrap()
}

/// The reason the last refusal of `event` recorded for ownership.
fn last_ownership(h: &Harness, event: AuditEvent) -> Option<String> {
    audit_records(&h.state(), event.as_str())
        .last()
        .and_then(|record| text(record, "ownership").map(str::to_owned))
}

fn run_state(h: &Harness, run: &str) -> String {
    raw(&h.state())
        .query_row("SELECT state FROM run WHERE run_id = ?1", [run], |row| {
            row.get(0)
        })
        .unwrap()
}

fn lease_epoch(h: &Harness, n: u64) -> i64 {
    raw(&h.state())
        .query_row(
            "SELECT epoch FROM session_lease WHERE session_id = ?1",
            [session(n).as_str()],
            |row| row.get(0),
        )
        .unwrap()
}

fn invalid(result: Result<impl std::fmt::Debug, ConfigError>, needle: &str) {
    match result {
        Err(ConfigError::Invalid(why)) => assert!(why.contains(needle), "{why}"),
        other => panic!("expected an invalid declaration ({needle}): {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Taking a session over.
// ---------------------------------------------------------------------------

#[test]
fn another_subject_cannot_take_a_session_after_its_lease_expires_and_nothing_is_reaped() {
    let mut h = Harness::new("own-expiry");
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, ea, "k1", &["model.call:*"]))
            .unwrap(),
    );
    h.clock
        .advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
    // The lease has expired: before F-18 any allowed uid took the session,
    // its binding and its epoch, and reaped A's run.
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    assert_eq!(
        last_ownership(&h, AuditEvent::LeaseRefused).as_deref(),
        Some("SESSION_NOT_PERMITTED")
    );
    assert_eq!(run_state(&h, run.run_id().as_str()), "ACTIVE", "not reaped");
    assert_eq!(lease_epoch(&h, 1), 1, "no new tenure");
    assert!(
        audit_records(&h.state(), AuditEvent::RunReaped.as_str()).is_empty(),
        "nothing was reaped"
    );
    // The owner takes it back; its own old run ends with its old tenure.
    let a2 = h.connect(1000);
    let next = h.lease(&a2, &s);
    assert!(next.get() > ea.get());
    assert_eq!(run_state(&h, run.run_id().as_str()), "REAPED");
}

#[test]
fn another_subject_cannot_take_a_released_session_before_or_after_a_restart() {
    let mut h = Harness::new("own-release");
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    h.authority().release_lease(&a, &s, ea).unwrap();
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "released"
    );
    h.restart();
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "a restart erases no ownership"
    );
    // The same uid after a restart is the owner, on a new connection.
    let a = h.connect(1000);
    assert!(h.lease(&a, &s).get() > ea.get());
    // And B's own new session is B's.
    let s2 = session(2);
    assert_eq!(h.lease(&b, &s2).get(), 1);
    let a = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&a, &s2).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
}

#[test]
fn the_same_uid_on_a_new_connection_holds_its_session_once_the_old_lease_ends() {
    let mut h = Harness::new("own-reconnect");
    let s = session(1);
    let first = h.connect(1000);
    let e1 = h.lease(&first, &s);
    let second = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&second, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "a live lease is still its holder's"
    );
    assert_eq!(
        last_ownership(&h, AuditEvent::LeaseRefused),
        None,
        "refused by the lease, not by ownership"
    );
    h.authority().release_lease(&first, &s, e1).unwrap();
    let e2 = h.lease(&second, &s);
    assert!(e2.get() > e1.get());
    assert_eq!(
        h.authority().heartbeat(&first, &s, e1).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
}

#[test]
fn a_new_session_is_its_first_acquirers_and_the_record_says_so() {
    let mut h = Harness::new("own-first");
    let s = session(5);
    let a = h.connect(1000);
    h.lease(&a, &s);
    let conn = raw(&h.state());
    let (owner, basis): (String, String) = conn
        .query_row(
            "SELECT subject, basis FROM session_owner WHERE session_id = ?1",
            [s.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (owner.as_str(), basis.as_str()),
        ("uid:1000", "FIRST_ACQUIRER")
    );
    let declared = audit_records(&h.state(), AuditEvent::OwnershipDeclared.as_str());
    assert!(
        declared
            .iter()
            .any(|r| text(r, "resource") == Some(s.as_str())
                && text(r, "basis") == Some("FIRST_ACQUIRER")
                && text(r, "subject") == Some("uid:1000"))
    );
    // The owner is fixed: the operator cannot hand the session to another.
    invalid(
        h.authority()
            .operator()
            .declare_session_owner(&s, subject(2000)),
        "already has an owner",
    );
    // An operator-declared session is not anyone's to claim first.
    let t = session(6);
    h.authority()
        .operator()
        .declare_session_owner(&t, subject(3000))
        .unwrap();
    let a = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&a, &t).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    let c = h.connect(3000);
    assert_eq!(h.lease(&c, &t).get(), 1);
}

// ---------------------------------------------------------------------------
// Workspaces.
// ---------------------------------------------------------------------------

#[test]
fn a_session_is_bound_only_with_an_owner_who_is_a_principal_of_the_workspace() {
    let mut h = Harness::new("own-bind");
    let ws = WorkspaceId::new("proj").unwrap();
    let s = session(1);
    h.authority()
        .operator()
        .install_workspace(&ws, WorkspaceSensitivity::Private)
        .unwrap();
    invalid(
        h.authority().operator().bind_session_workspace(&s, &ws),
        "has no owner",
    );
    h.authority()
        .operator()
        .declare_session_owner(&s, subject(1000))
        .unwrap();
    invalid(
        h.authority().operator().bind_session_workspace(&s, &ws),
        "is not a principal",
    );
    // A delegate outside the workspace blocks the binding too.
    h.authority()
        .operator()
        .add_session_delegate(&s, subject(2000))
        .unwrap();
    h.authority()
        .operator()
        .grant_workspace_principal(&ws, subject(1000))
        .unwrap();
    invalid(
        h.authority().operator().bind_session_workspace(&s, &ws),
        "a delegate",
    );
    // A second principal of a workspace needs the share acknowledged.
    invalid(
        h.authority()
            .operator()
            .grant_workspace_principal(&ws, subject(2000)),
        "acknowledge",
    );
    h.authority()
        .operator()
        .acknowledge_root_share(&ws)
        .unwrap();
    h.authority()
        .operator()
        .grant_workspace_principal(&ws, subject(2000))
        .unwrap();
    h.authority()
        .operator()
        .bind_session_workspace(&s, &ws)
        .unwrap();
    // Bound: a delegate outside it is refused, and so is the binding's own
    // undoing.
    invalid(
        h.authority()
            .operator()
            .add_session_delegate(&s, subject(3000)),
        "not a principal",
    );
    let shares = audit_records(&h.state(), AuditEvent::OwnershipDeclared.as_str())
        .iter()
        .filter(|r| text(r, "kind") == Some("ROOT_SHARE"))
        .count();
    assert_eq!(shares, 1, "the acknowledgement is audited");
}

#[test]
fn a_bound_session_is_held_only_while_its_holder_is_a_principal_of_the_workspace() {
    let mut h = Harness::new("own-ws-standing");
    let ws = WorkspaceId::new("proj").unwrap();
    let s = session(1);
    h.authority()
        .operator()
        .install_workspace(&ws, WorkspaceSensitivity::Private)
        .unwrap();
    state_support::own_and_bind(h.authority(), 1000, &s, &ws);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    let report = h
        .authority()
        .operator()
        .revoke_workspace_principal(&ws, subject(1000))
        .unwrap();
    assert_eq!(
        (report.leases_invalidated, report.runs_reaped, report.status),
        (1, 1, RevocationStatus::Complete),
        "no environment: complete at once"
    );
    assert_eq!(run_state(&h, run.run_id().as_str()), "REAPED");
    assert_eq!(
        h.authority().heartbeat(&a, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    let a = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&a, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    assert_eq!(
        last_ownership(&h, AuditEvent::LeaseRefused).as_deref(),
        Some("WORKSPACE_NOT_PERMITTED")
    );
    // A new grant is a new row; the owner holds its session again.
    h.authority()
        .operator()
        .grant_workspace_principal(&ws, subject(1000))
        .unwrap();
    assert!(h.lease(&a, &s).get() > e.get());
}

#[test]
fn an_acknowledged_shared_workspace_lets_each_principal_hold_only_its_own_session() {
    let mut h = Harness::new("own-shared");
    let ws = WorkspaceId::new("shared").unwrap();
    let (s1, s2) = (session(1), session(2));
    {
        let mut operator = h.authority().operator();
        operator
            .install_workspace(&ws, WorkspaceSensitivity::Private)
            .unwrap();
        operator.acknowledge_root_share(&ws).unwrap();
    }
    state_support::own_and_bind(h.authority(), 1000, &s1, &ws);
    state_support::own_and_bind(h.authority(), 2000, &s2, &ws);
    state_support::grant_fixture_profiles(h.authority(), 2000);
    let a = h.connect(1000);
    let b = h.connect(2000);
    let ea = h.lease(&a, &s1);
    let eb = h.lease(&b, &s2);
    admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s1, ea, "k", &["model.call:*"]))
            .unwrap(),
    );
    admitted(
        h.authority()
            .admit_run(&b, &admit_simple(&s2, eb, "k", &["model.call:*"]))
            .unwrap(),
    );
    // Sharing a workspace is not sharing a session.
    let a2 = h.connect(1000);
    h.clock
        .advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
    assert_eq!(
        h.authority().acquire_lease(&a2, &s2).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
}

// ---------------------------------------------------------------------------
// Profiles.
// ---------------------------------------------------------------------------

#[test]
fn a_profile_not_granted_to_the_subject_is_refused_as_one_the_kernel_does_not_hold() {
    let mut h = Harness::new("own-profile");
    let s = session(1);
    let c = h.connect(3000);
    let e = h.lease(&c, &s);
    // `researcher` exists, and is uid:1000's: to uid:3000 it is unknown, the
    // same answer as a profile that never existed.
    let refused = h
        .authority()
        .admit_run(&c, &admit_simple(&s, e, "k1", &["model.call:*"]))
        .unwrap();
    assert_eq!(refused, Reply::Refused(RefusalReason::UnknownAgentProfile));
    assert_eq!(
        last_ownership(&h, AuditEvent::RunAdmitRefused).as_deref(),
        Some("PROFILE_NOT_PERMITTED")
    );
    let unknown = h
        .authority()
        .admit_run(
            &c,
            &admit_msg(&s, e, "k2", "nobody-installed", &[], &["model.call:*"], 2),
        )
        .unwrap();
    assert_eq!(unknown, refused, "indistinguishable on the wire");
    assert_eq!(
        count(&raw(&h.state()), "SELECT count(*) FROM run"),
        0,
        "no run was admitted"
    );
    // Granted, under a new key, it is admitted.
    h.authority()
        .operator()
        .grant_profile_principal(&profile("researcher"), subject(3000))
        .unwrap();
    admitted(
        h.authority()
            .admit_run(&c, &admit_simple(&s, e, "k3", &["model.call:*"]))
            .unwrap(),
    );
    // A grant names an installed profile only.
    invalid(
        h.authority()
            .operator()
            .grant_profile_principal(&profile("nobody-installed"), subject(3000)),
        "no agent profile",
    );
}

#[test]
fn revoking_a_profile_reaps_only_that_subjects_runs_under_it() {
    let mut h = Harness::new("own-profile-revoke");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    let researcher = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    let coder = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(&s, e, "k2", "coder", &[], &["model.call:*"], 2),
            )
            .unwrap(),
    );
    let report = h
        .authority()
        .operator()
        .revoke_profile_principal(&profile("researcher"), subject(1000))
        .unwrap();
    assert_eq!((report.leases_invalidated, report.runs_reaped), (0, 1));
    assert_eq!(run_state(&h, researcher.run_id().as_str()), "REAPED");
    assert_eq!(run_state(&h, coder.run_id().as_str()), "ACTIVE");
    // The lease is untouched; the profile is not the subject's any more.
    assert_eq!(h.authority().heartbeat(&a, &s, e).unwrap(), Reply::Done(()));
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k3", &["model.call:*"]))
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownAgentProfile)
    );
    let reaped = audit_records(&h.state(), AuditEvent::RunReaped.as_str());
    assert_eq!(text(&reaped[0], "cause"), Some("principal_revoked"));
}

// ---------------------------------------------------------------------------
// Delegation and revocation.
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_delegate_keeps_nothing_and_gets_nothing_back() {
    let mut h = Harness::new("own-delegate");
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    h.authority().release_lease(&a, &s, ea).unwrap();
    state_support::delegate(h.authority(), &s, 2000);
    let b = h.connect(2000);
    let eb = h.lease(&b, &s);
    let message = admit_simple(&s, eb, "kb", &["model.call:*"]);
    let run = admitted(h.authority().admit_run(&b, &message).unwrap());

    let report = h
        .authority()
        .operator()
        .revoke_session_delegate(&s, subject(2000))
        .unwrap();
    assert_eq!(
        (report.leases_invalidated, report.runs_reaped, report.status),
        (1, 1, RevocationStatus::Complete)
    );
    assert_eq!(run_state(&h, run.run_id().as_str()), "REAPED");
    let revoked = audit_records(&h.state(), AuditEvent::LeaseRevoked.as_str());
    assert_eq!(text(&revoked[0], "subject"), Some("uid:2000"));
    // CW6: its old epoch is fenced before anything else -- a heartbeat, a
    // replay of its admission key.
    assert_eq!(
        h.authority().heartbeat(&b, &s, eb).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    assert_eq!(
        h.authority().admit_run(&b, &message).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // CW7: re-acquiring, before and after a restart, is refused.
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    h.restart();
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    // The owner's next tenure is strictly newer than the revoked one's.
    let a = h.connect(1000);
    assert!(h.lease(&a, &s).get() > eb.get());
    // Nothing to revoke twice; the revocation is recorded once.
    invalid(
        h.authority()
            .operator()
            .revoke_session_delegate(&s, subject(2000)),
        "not a delegate",
    );
    assert_eq!(
        audit_records(&h.state(), AuditEvent::OwnershipRevoked.as_str()).len(),
        1
    );
    assert_eq!(
        h.authority()
            .revocation_status(report.revocation)
            .unwrap()
            .map(|r| r.status),
        Some(RevocationStatus::Complete)
    );
}

#[test]
fn the_fence_refuses_a_holder_whose_standing_ended_even_without_the_revocations_fence() {
    // The revocation invalidates the lease in its transaction; the fence's
    // own check of the holder's standing is the second, independent
    // statement. A grant revoked behind the authority's back -- the row
    // alone -- still fences the holder.
    let mut h = Harness::new("own-fence");
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    h.authority().release_lease(&a, &s, ea).unwrap();
    state_support::delegate(h.authority(), &s, 2000);
    let b = h.connect(2000);
    let eb = h.lease(&b, &s);
    assert_eq!(
        h.authority().heartbeat(&b, &s, eb).unwrap(),
        Reply::Done(())
    );
    raw(&h.state())
        .execute(
            "UPDATE session_delegate SET revoked_ms = 9999999999999 WHERE subject = 'uid:2000'",
            [],
        )
        .unwrap();
    assert_eq!(
        h.authority().heartbeat(&b, &s, eb).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    assert_eq!(
        h.authority()
            .admit_run(&b, &admit_simple(&s, eb, "k", &["model.call:*"]))
            .unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
}

#[test]
fn a_retired_session_is_held_by_nobody_again() {
    let mut h = Harness::new("own-retire");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    state_support::delegate(h.authority(), &s, 2000);
    let report = h.authority().operator().revoke_session_owner(&s).unwrap();
    assert_eq!(report.leases_invalidated, 1);
    for uid in [1000, 2000] {
        let caller = h.connect(uid);
        assert_eq!(
            h.authority().acquire_lease(&caller, &s).unwrap(),
            Reply::Refused(RefusalReason::LeaseHeld),
            "uid {uid}"
        );
    }
    assert_eq!(
        last_ownership(&h, AuditEvent::LeaseRefused).as_deref(),
        Some("SESSION_RETIRED")
    );
    assert_eq!(
        h.authority().heartbeat(&a, &s, e).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    invalid(
        h.authority()
            .operator()
            .declare_session_owner(&s, subject(1000)),
        "retired",
    );
    let delegates: i64 = count(
        &raw(&h.state()),
        "SELECT count(*) FROM session_delegate WHERE revoked_ms IS NULL",
    );
    assert_eq!(delegates, 0, "its delegates went with it");
}

// ---------------------------------------------------------------------------
// Migration and the operator's bootstrap.
// ---------------------------------------------------------------------------

/// Turn the harness's store into a version-13 one -- its ownership records
/// gone, as no version-13 store ever had them -- and start it, migrating.
fn as_version_thirteen(h: &mut Harness) {
    h.stop();
    raw(&h.state())
        .execute_batch(
            "DROP TABLE ownership_revocation_run; DROP TABLE ownership_revocation; \
             DROP TABLE session_delegate; \
             DROP TRIGGER session_workspace_bound_with_its_owner; \
             DROP TABLE session_owner; DROP TABLE profile_principal; \
             DROP TABLE workspace_principal; DROP TABLE workspace_root_share; \
             DROP TABLE ownership_observation; DROP TABLE legacy_session; \
             PRAGMA user_version = 13;",
        )
        .unwrap();
    h.try_restart().expect("a version-13 store migrates");
    assert_eq!(h.report.schema_version, KERNEL_SCHEMA_VERSION);
}

/// A store whose history has two subjects on one session: uid:1000 owned
/// it and admitted a run; uid:2000, delegated, admitted another. A third
/// session is bound to a workspace.
fn conflicting_history(tag: &str) -> Harness {
    let mut h = Harness::new(tag);
    let ws = WorkspaceId::new("proj").unwrap();
    h.authority()
        .operator()
        .install_workspace(&ws, WorkspaceSensitivity::Private)
        .unwrap();
    state_support::own_and_bind(h.authority(), 1000, &session(3), &ws);
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, ea, "k1", &["model.call:*"]))
            .unwrap(),
    );
    h.authority().release_lease(&a, &s, ea).unwrap();
    state_support::delegate(h.authority(), &s, 2000);
    let b = h.connect(2000);
    let eb = h.lease(&b, &s);
    admitted(
        h.authority()
            .admit_run(&b, &admit_simple(&s, eb, "k2", &["model.call:*"]))
            .unwrap(),
    );
    h
}

#[test]
fn a_migrated_store_grants_nothing_its_history_shows_and_refuses_until_declared() {
    let mut h = conflicting_history("own-migrate");
    let lease_holder: String = raw(&h.state())
        .query_row(
            "SELECT holder_subject FROM session_lease WHERE session_id = ?1",
            [session(1).as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        lease_holder, "uid:2000",
        "uid:2000 held the lease when it stopped"
    );
    as_version_thirteen(&mut h);
    // OD-11: it started, and said what is missing.
    let gaps = h.report.ownership;
    assert_eq!(gaps.legacy_sessions_undeclared, 2);
    assert_eq!(gaps.bound_sessions_unowned, 1);
    assert_eq!(gaps.workspaces_without_principal, 1);
    assert_eq!(gaps.profiles_without_principal, 2);
    assert!(!gaps.is_complete());
    let incomplete = audit_records(&h.state(), AuditEvent::OwnershipIncomplete.as_str());
    assert_eq!(incomplete.len(), 1, "recorded once, at the start");
    // History made nobody an owner: not the last lease holder, not the
    // first, not a run's subject -- and nobody claims a legacy session first.
    for uid in [1000, 2000, 4000] {
        let caller = h.connect(uid);
        assert_eq!(
            h.authority().acquire_lease(&caller, &session(1)).unwrap(),
            Reply::Refused(RefusalReason::LeaseHeld),
            "uid {uid}"
        );
        assert_eq!(
            last_ownership(&h, AuditEvent::LeaseRefused).as_deref(),
            Some("SESSION_UNOWNED")
        );
    }
    let a = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&a, &session(3)).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "a bound legacy session with no declared owner"
    );
    // The observation says what history showed, conflict included.
    let ambiguous = count(
        &raw(&h.state()),
        "SELECT count(*) FROM ownership_observation WHERE resource_kind = 'SESSION' \
         AND ambiguous = 1",
    );
    assert_eq!(
        ambiguous, 3,
        "session 1: uid:1000's run, uid:2000's run and uid:2000's lease"
    );
    // The adoption refuses it: history shows another subject.
    invalid(
        h.authority()
            .operator()
            .adopt_single_principal(subject(1000)),
        "history shows",
    );
    // A declared owner holds its legacy session -- and still runs under no
    // profile its history shows it used: only a grant makes one its own.
    h.authority()
        .operator()
        .declare_session_owner(&session(1), subject(1000))
        .unwrap();
    let a = h.connect(1000);
    let e = h.lease(&a, &session(1));
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&session(1), e, "k8", &["model.call:*"]))
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownAgentProfile),
        "uid:1000 ran `researcher` before the migration; that is not a grant"
    );
    // The operator's bootstrap, in order: workspace, profiles, owners, delegates.
    // A bound session's owner is a principal of its workspace first.
    let ws = WorkspaceId::new("proj").unwrap();
    invalid(
        h.authority()
            .operator()
            .declare_session_owner(&session(3), subject(1000)),
        "not a principal",
    );
    {
        let mut operator = h.authority().operator();
        operator
            .grant_workspace_principal(&ws, subject(1000))
            .unwrap();
        operator
            .grant_profile_principal(&profile("researcher"), subject(1000))
            .unwrap();
        operator
            .declare_session_owner(&session(3), subject(1000))
            .unwrap();
    }
    admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&session(1), e, "k9", &["model.call:*"]))
            .unwrap(),
    );
    assert!(h.lease(&a, &session(3)).get() >= 1);
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &session(1)).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld),
        "the delegation before the migration was not carried over"
    );
}

#[test]
fn the_single_principal_adoption_declares_a_consistent_history_and_nothing_else() {
    let mut h = Harness::new("own-adopt");
    let ws = WorkspaceId::new("proj").unwrap();
    h.authority()
        .operator()
        .install_workspace(&ws, WorkspaceSensitivity::Private)
        .unwrap();
    state_support::own_and_bind(h.authority(), 1000, &session(2), &ws);
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    as_version_thirteen(&mut h);
    // Another subject is refused adoption of a store that shows only uid:1000.
    invalid(
        h.authority()
            .operator()
            .adopt_single_principal(subject(2000)),
        "history shows",
    );
    let adopted = h
        .authority()
        .operator()
        .adopt_single_principal(subject(1000))
        .unwrap();
    assert_eq!(
        (adopted.sessions, adopted.workspaces, adopted.profiles),
        (2, 1, 2)
    );
    assert!(h.authority().ownership_gaps().unwrap().is_complete());
    let record = audit_records(&h.state(), AuditEvent::OwnershipAdopted.as_str());
    assert_eq!(text(&record[0], "subject"), Some("uid:1000"));
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k2", &["model.call:*"]))
            .unwrap(),
    );
    assert!(h.lease(&a, &session(2)).get() >= 1);
    let b = h.connect(2000);
    assert_eq!(
        h.authority().acquire_lease(&b, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
    // Adopted twice: nothing more to declare.
    let again = h
        .authority()
        .operator()
        .adopt_single_principal(subject(1000))
        .unwrap();
    assert_eq!(
        (again.sessions, again.workspaces, again.profiles),
        (0, 0, 0)
    );
}

#[test]
fn an_adoption_interrupted_before_its_commit_grants_nothing() {
    // CW5: the adoption is one transaction; a crash before its commit leaves
    // the store as it was.
    let armed = Arc::new(AtomicBool::new(false));
    let hook_armed = Arc::clone(&armed);
    let hook: dwkd_authority::state::CrashHook = Arc::new(move |point| {
        if hook_armed.load(Ordering::SeqCst) && point == CrashPoint::BeforeCommit {
            HookAction::Stop
        } else {
            HookAction::Continue
        }
    });
    let mut h = Harness::new("own-adopt-crash");
    let s = session(1);
    let a = h.connect(1000);
    h.lease(&a, &s);
    as_version_thirteen(&mut h);
    h.restart_with(Some(hook));
    armed.store(true, Ordering::SeqCst);
    let result = h
        .authority()
        .operator()
        .adopt_single_principal(subject(1000));
    assert!(
        matches!(result, Err(ConfigError::Authority(_))),
        "{result:?}"
    );
    armed.store(false, Ordering::SeqCst);
    h.restart();
    let conn = raw(&h.state());
    for table in ["session_owner", "workspace_principal", "profile_principal"] {
        assert_eq!(
            count(&conn, &format!("SELECT count(*) FROM {table}")),
            0,
            "{table}"
        );
    }
    let a = h.connect(1000);
    assert_eq!(
        h.authority().acquire_lease(&a, &s).unwrap(),
        Reply::Refused(RefusalReason::LeaseHeld)
    );
}

// ---------------------------------------------------------------------------
// Nothing a runtime sends names a subject.
// ---------------------------------------------------------------------------

#[test]
fn a_forged_subject_or_principal_in_a_message_is_not_a_message() {
    // The subject is the kernel's (the caller's context); a request that
    // tries to say who it is, anywhere, does not decode at all.
    let honest = admit_simple(&session(1), epoch(1), "k1", &["model.call:*"]);
    let mut text = String::from_utf8(honest.to_canonical_bytes().unwrap()).unwrap();
    for (field, value) in [
        ("subject", "\"uid:0\""),
        ("principal", "\"uid:0\""),
        ("uid", "0"),
        ("owner", "\"uid:0\""),
        ("delegate", "\"uid:0\""),
    ] {
        let envelope = text.replacen('{', &format!("{{\"{field}\":{value},"), 1);
        assert!(
            dwkp::decode_body(envelope.as_bytes()).is_err(),
            "an envelope naming `{field}`"
        );
        let payload = text.replacen(
            "\"payload\":{",
            &format!("\"payload\":{{\"{field}\":{value},"),
            1,
        );
        assert!(
            dwkp::decode_body(payload.as_bytes()).is_err(),
            "a payload naming `{field}`"
        );
    }
    // And a heartbeat, the shortest request there is.
    text = String::from_utf8(
        heartbeat_msg(&session(1), epoch(1))
            .to_canonical_bytes()
            .unwrap(),
    )
    .unwrap();
    let forged = text.replacen('{', "{\"subject\":\"uid:0\",", 1);
    assert!(dwkp::decode_body(forged.as_bytes()).is_err());
}

#[test]
fn an_adoption_is_refused_when_a_declaration_names_another_subject() {
    // A store with no history at all, whose operator already granted a
    // workspace to uid:2000: it has two principals, and adopting one would
    // be false.
    let mut h = Harness::new("own-adopt-records");
    let ws = WorkspaceId::new("proj").unwrap();
    h.authority()
        .operator()
        .install_workspace(&ws, WorkspaceSensitivity::Private)
        .unwrap();
    h.authority()
        .operator()
        .grant_workspace_principal(&ws, subject(2000))
        .unwrap();
    invalid(
        h.authority()
            .operator()
            .adopt_single_principal(subject(1000)),
        "ownership records already name",
    );
    assert!(audit_records(&h.state(), AuditEvent::OwnershipAdopted.as_str()).is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn a_root_two_workspaces_share_is_shared_by_their_principals_only_as_acknowledged() {
    // Two workspaces bound to one directory are one root (F-17, F-01): its
    // exposure and its taint are the root's. Their principals together reach
    // it, so a second principal across them needs every one acknowledged.
    let mut h = Harness::new("own-root-share");
    let root = h.dir.path().join("shared-root");
    std::fs::create_dir_all(&root).unwrap();
    let (first, second) = (
        WorkspaceId::new("first").unwrap(),
        WorkspaceId::new("second").unwrap(),
    );
    {
        let mut operator = h.authority().operator();
        for ws in [&first, &second] {
            operator
                .install_workspace(ws, WorkspaceSensitivity::Private)
                .unwrap();
            operator
                .install_workspace_root(ws, root.to_str().unwrap())
                .unwrap();
        }
        operator
            .grant_workspace_principal(&first, subject(1000))
            .unwrap();
    }
    invalid(
        h.authority()
            .operator()
            .grant_workspace_principal(&second, subject(2000)),
        "more than one principal",
    );
    h.authority()
        .operator()
        .acknowledge_root_share(&second)
        .unwrap();
    invalid(
        h.authority()
            .operator()
            .grant_workspace_principal(&second, subject(2000)),
        "every workspace bound to it",
    );
    h.authority()
        .operator()
        .acknowledge_root_share(&first)
        .unwrap();
    h.authority()
        .operator()
        .grant_workspace_principal(&second, subject(2000))
        .unwrap();
    // A third workspace bound to the root later is refused until it too is
    // acknowledged.
    let third = WorkspaceId::new("third").unwrap();
    h.authority()
        .operator()
        .install_workspace(&third, WorkspaceSensitivity::Private)
        .unwrap();
    invalid(
        h.authority()
            .operator()
            .install_workspace_root(&third, root.to_str().unwrap()),
        "more than one principal",
    );
}
