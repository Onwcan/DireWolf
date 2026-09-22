//! `AdmitRun` and `ReleaseRun` against real `kernel.db` files.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
use sha2 as _;
use toml as _;

mod state_support;

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::wire::scalar::{RefusalReason, RefusedOperation, WithheldReason};
use dwkd_authority::capability::{PrivacyClass, UnresolvedScope};
use dwkd_authority::policy::{Origin, TaintLevel};
use dwkd_authority::state::{
    Admission, AuditEvent, AuthorityError, Clock as _, Reply, TaintCause, WithheldCause,
    WorkspaceId, WorkspaceSensitivity, request_digest,
};
use state_support::{
    Harness, admit_msg, admit_simple, audit_records, count, decode, epoch, id, query_msg, raw,
    release_run_msg, session, text,
};

fn admitted(reply: Reply<Admission>) -> Admission {
    match reply {
        Reply::Done(admission) => admission,
        Reply::Refused(reason) => panic!("refused: {reason:?}"),
    }
}

fn granted_texts(admission: &Admission) -> Vec<String> {
    admission
        .granted()
        .iter()
        .map(|g| g.capability().to_canonical_string())
        .collect()
}

fn withheld(admission: &Admission) -> Vec<(String, WithheldCause)> {
    admission
        .withheld()
        .iter()
        .map(|w| (w.requested().as_str().to_owned(), w.cause()))
        .collect()
}

#[test]
fn a_first_admission_grants_exactly_what_was_asked_and_covered() {
    let mut h = Harness::new("first");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let msg = admit_simple(
        &s,
        e,
        "k1",
        &[
            "model.call:*",
            "network.https:api.example.com",
            "network.https:evil.test",
            "secret.use:github",
        ],
    );
    let admission = admitted(h.authority().admit_run(&a, &msg).unwrap());
    assert_eq!(
        granted_texts(&admission),
        ["model.call:*", "network.https:api.example.com"]
    );
    assert_eq!(
        withheld(&admission),
        [
            (
                "network.https:evil.test".to_owned(),
                WithheldCause::NotInAgentProfile
            ),
            (
                "secret.use:github".to_owned(),
                WithheldCause::NotInAgentProfile
            ),
        ]
    );
    assert_eq!(admission.epoch(), e);
    assert_eq!(admission.session_id(), &s);
    assert_eq!(
        Some(*admission.policy_revision()),
        h.authority().policy_revision()
    );
    // The profile also declares memory.read, scheduler.create and more; none of
    // it was asked for, so none of it was granted.
    assert!(
        !granted_texts(&admission)
            .iter()
            .any(|c| c.starts_with("memory"))
    );

    // The same admission as a wire `RunGrant` (`state_wire.rs` sends every
    // such body through the real encoder and decoder).
    let DwkpBody::RunGrant(grant) = h
        .authority()
        .dispatch(
            &a,
            &admit_simple(
                &s,
                e,
                "k1",
                &[
                    "model.call:*",
                    "network.https:api.example.com",
                    "network.https:evil.test",
                    "secret.use:github",
                ],
            ),
        )
        .unwrap()
    else {
        panic!("a RunGrant")
    };
    assert_eq!(&grant.run_id, admission.run_id());
    assert_eq!(grant.granted.len(), 2);
    assert_eq!(grant.withheld.len(), 2);
    assert_eq!(
        grant.withheld.iter().map(|w| w.reason).collect::<Vec<_>>(),
        [
            WithheldReason::NotInAgentProfile,
            WithheldReason::NotInAgentProfile
        ]
    );
}

#[test]
fn an_identical_retry_returns_the_same_grant_and_writes_no_authority() {
    let mut h = Harness::new("replay");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let caps = ["model.call:*", "memory.read:*", "teleport.now:*"];
    let first = admitted(
        h.authority()
            .admit_run(&a, &admit_msg(&s, e, "k1", "researcher", &[], &caps, 1))
            .unwrap(),
    );
    let conn = raw(&h.state());
    let rows_before = (
        count(&conn, "SELECT count(*) FROM run"),
        count(&conn, "SELECT count(*) FROM run_grant"),
        count(&conn, "SELECT count(*) FROM admission_idempotency"),
    );
    // A different message id, timestamp and correlation id: those four fields
    // legitimately differ between a request and its own retry.
    let retry = admit_msg(&s, e, "k1", "researcher", &[], &caps, 2);
    assert_ne!(
        retry.header.id,
        admit_msg(&s, e, "k1", "researcher", &[], &caps, 1)
            .header
            .id
    );
    assert_eq!(
        request_digest(&retry).unwrap(),
        request_digest(&admit_msg(&s, e, "k1", "researcher", &[], &caps, 1)).unwrap()
    );
    let second = admitted(h.authority().admit_run(&a, &retry).unwrap());
    assert_eq!(
        first, second,
        "the same run id, epoch, revision, cap ids and withheld list"
    );
    // Through an independent connection too -- read back from disk.
    let mut other = h.authority().handle().unwrap();
    let third = admitted(other.admit_run(&a, &retry).unwrap());
    assert_eq!(first, third);
    assert_eq!(
        rows_before,
        (
            count(&conn, "SELECT count(*) FROM run"),
            count(&conn, "SELECT count(*) FROM run_grant"),
            count(&conn, "SELECT count(*) FROM admission_idempotency"),
        ),
        "no second admission, no new grant, no new record"
    );
    assert_eq!(
        audit_records(&h.state(), AuditEvent::RunAdmitted.as_str()).len(),
        1
    );
    assert_eq!(
        audit_records(&h.state(), AuditEvent::RunAdmitReplayed.as_str()).len(),
        2
    );
}

#[test]
fn a_changed_request_under_the_same_key_conflicts_and_changes_nothing() {
    let mut h = Harness::new("conflict");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let original = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(&s, e, "k1", "researcher", &[], &["model.call:*"], 1),
            )
            .unwrap(),
    );
    for changed in [
        admit_msg(&s, e, "k1", "coder", &[], &["model.call:*"], 3),
        admit_msg(&s, e, "k1", "researcher", &["web"], &["model.call:*"], 4),
        admit_msg(
            &s,
            e,
            "k1",
            "researcher",
            &[],
            &["model.call:*", "memory.read:*"],
            5,
        ),
        admit_msg(&s, e, "k1", "researcher", &[], &["memory.read:*"], 6),
    ] {
        assert_eq!(
            h.authority().admit_run(&a, &changed).unwrap(),
            Reply::Refused(RefusalReason::IdempotencyConflict)
        );
    }
    // The original is exactly as it was: its replay still returns it.
    let replay = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(&s, e, "k1", "researcher", &[], &["model.call:*"], 7),
            )
            .unwrap(),
    );
    assert_eq!(replay, original);
    let conn = raw(&h.state());
    assert_eq!(count(&conn, "SELECT count(*) FROM run"), 1);
    let refusals = audit_records(&h.state(), AuditEvent::RunAdmitRefused.as_str());
    assert_eq!(refusals.len(), 4);
    assert!(
        refusals
            .iter()
            .all(|r| text(r, "original_run_id") == Some(original.run_id().as_str()))
    );
}

#[test]
fn a_different_key_is_a_different_admission() {
    let mut h = Harness::new("two-keys");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let one = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    let two = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k2", &["model.call:*"]))
            .unwrap(),
    );
    assert_ne!(
        one.run_id(),
        two.run_id(),
        "the key distinguishes again from still"
    );
}

#[test]
fn another_subject_with_the_same_key_neither_replays_nor_collides() {
    let mut h = Harness::new("subjects");
    let s = session(1);
    let a = h.connect(1000);
    let ea = h.lease(&a, &s);
    let theirs = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, ea, "shared", &["model.call:*"]))
            .unwrap(),
    );
    h.authority().release_lease(&a, &s, ea).unwrap();

    let b = h.connect(2000);
    let eb = h.lease(&b, &s);
    let mine = admitted(
        h.authority()
            .admit_run(&b, &admit_simple(&s, eb, "shared", &["model.call:*"]))
            .unwrap(),
    );
    assert_ne!(mine.run_id(), theirs.run_id(), "not their grant");
    // And their run is not visible under this subject.
    assert_eq!(
        h.authority()
            .query_authority(&b, &s, theirs.run_id(), eb, None)
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
}

#[test]
fn the_fence_is_checked_before_the_key_even_for_a_valid_old_key() {
    let mut h = Harness::new("zombie");
    let s = session(1);
    let zombie = h.connect(1000);
    let old = h.lease(&zombie, &s);
    let msg = admit_simple(&s, old, "k1", &["model.call:*"]);
    let original = admitted(h.authority().admit_run(&zombie, &msg).unwrap());

    // The zombie's lease expires and a new connection -- the same subject --
    // takes the session.
    h.clock
        .advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
    let fresh = h.connect(1000);
    let new = h.lease(&fresh, &s);
    assert!(new > old);

    // The zombie retries with its valid old key and old epoch. It gets the
    // fence, not the grant.
    assert_eq!(
        h.authority().admit_run(&zombie, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // So does the new holder presenting the old epoch.
    assert_eq!(
        h.authority().admit_run(&fresh, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // And the zombie's run was reaped when the lease moved: explicitly, in the
    // store, not merely unreachable because its epoch is old.
    let state: String = raw(&h.state())
        .query_row(
            "SELECT state FROM run WHERE run_id = ?1",
            [original.run_id().as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "REAPED");
    assert_eq!(
        h.authority()
            .query_authority(&fresh, &s, original.run_id(), new, None)
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
}

#[test]
fn after_a_restart_the_old_key_meets_the_fence_and_then_is_spent() {
    let mut h = Harness::new("zombie-restart");
    let s = session(1);
    let before = h.connect(1000);
    let old = h.lease(&before, &s);
    let msg = admit_simple(&s, old, "k1", &["model.call:*"]);
    let original = admitted(h.authority().admit_run(&before, &msg).unwrap());
    let report = h.restart().clone();
    assert_eq!(
        report.runs_reaped, 1,
        "the previous process's run ended with it"
    );

    // The pre-restart connection and its key: the fence.
    assert_eq!(
        h.authority().admit_run(&before, &msg).unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    // A new connection re-leases and presents the same key and request. The
    // epoch is not part of the bound request (ADR-0040), so this is the same
    // admission -- and its run was reaped by the restart, so it is spent:
    // never a replay of dead authority, never a second run.
    let after = h.connect(1000);
    let new = h.lease(&after, &s);
    let again = admit_simple(&s, new, "k1", &["model.call:*"]);
    assert_eq!(
        h.authority().admit_run(&after, &again).unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    // The same key with a changed request is still a conflict.
    assert_eq!(
        h.authority()
            .admit_run(&after, &admit_simple(&s, new, "k1", &["memory.read:*"]))
            .unwrap(),
        Reply::Refused(RefusalReason::IdempotencyConflict)
    );
    let conn = raw(&h.state());
    assert_eq!(count(&conn, "SELECT count(*) FROM run"), 1);
    let state: String = conn
        .query_row(
            "SELECT state FROM run WHERE run_id = ?1",
            [original.run_id().as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "REAPED");
}

#[test]
fn a_released_run_replayed_is_spent_and_authorises_nothing() {
    let mut h = Harness::new("released-replay");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let msg = admit_simple(&s, e, "k1", &["model.call:*"]);
    let first = admitted(h.authority().admit_run(&a, &msg).unwrap());
    assert_eq!(
        h.authority()
            .release_run(&a, &s, first.run_id(), e)
            .unwrap(),
        Reply::Done(())
    );
    // ADR-0040: a grant is replayed only while its run is usable. This one
    // is not, so the key is spent -- in the same tenure, with the same epoch.
    assert_eq!(
        h.authority().admit_run(&a, &msg).unwrap(),
        Reply::Refused(RefusalReason::AdmissionEnded)
    );
    let refused = audit_records(&h.state(), AuditEvent::RunAdmitRefused.as_str());
    let last = refused.last().unwrap();
    assert_eq!(text(last, "reason"), Some("ADMISSION_ENDED"));
    assert_eq!(text(last, "original_run_id"), Some(first.run_id().as_str()));
    assert_eq!(text(last, "original_run_state"), Some("RELEASED"));
    // The run stays released, and nothing new exists.
    assert_eq!(
        h.authority()
            .query_authority(
                &a,
                &s,
                first.run_id(),
                e,
                Some(dwkd_authority::state::Proposal::Text(
                    &dwk_proto::wire::scalar::CapabilityText::new("model.call:x/y").unwrap()
                ))
            )
            .unwrap(),
        Reply::Refused(RefusalReason::UnknownRun)
    );
    let conn = raw(&h.state());
    let state: String = conn
        .query_row("SELECT state FROM run", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "RELEASED");
    assert_eq!(count(&conn, "SELECT count(*) FROM run"), 1);
}

#[test]
fn release_is_idempotent_by_shape_and_fenced() {
    let mut h = Harness::new("release");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    for _ in 0..3 {
        assert_eq!(
            h.authority().release_run(&a, &s, run.run_id(), e).unwrap(),
            Reply::Done(())
        );
    }
    assert_eq!(
        h.authority()
            .release_run(&a, &s, &state_support::run_id(424_242), e)
            .unwrap(),
        Reply::Done(()),
        "an unknown run is acknowledged, never UNKNOWN_RUN"
    );
    let stranger = h.connect(2000);
    assert_eq!(
        h.authority()
            .release_run(&stranger, &s, run.run_id(), e)
            .unwrap(),
        Reply::Refused(RefusalReason::StaleEpoch)
    );
    assert_eq!(
        audit_records(&h.state(), AuditEvent::RunReleased.as_str()).len(),
        1,
        "released once"
    );
    let DwkpBody::Ack(_) = h
        .authority()
        .dispatch(&a, &release_run_msg(&s, run.run_id(), e))
        .unwrap()
    else {
        panic!("Ack")
    };
}

#[test]
fn an_unknown_profile_is_refused_and_mints_nothing() {
    let mut h = Harness::new("unknown-profile");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let msg = admit_msg(&s, e, "k1", "nobody", &[], &["model.call:*"], 1);
    assert_eq!(
        h.authority().admit_run(&a, &msg).unwrap(),
        Reply::Refused(RefusalReason::UnknownAgentProfile)
    );
    let conn = raw(&h.state());
    assert_eq!(count(&conn, "SELECT count(*) FROM run"), 0);
    assert_eq!(
        count(&conn, "SELECT count(*) FROM admission_idempotency"),
        0
    );
    let DwkpBody::AuthorityRefused(refusal) = h.authority().dispatch(&a, &msg).unwrap() else {
        panic!("a refusal")
    };
    assert_eq!(
        (refusal.operation, refusal.reason),
        (
            RefusedOperation::AdmitRun,
            RefusalReason::UnknownAgentProfile
        )
    );
}

#[test]
fn omitting_skills_cannot_remove_a_baseline_constraint() {
    // `coder` declares network.https:* but mandates `house-rules`, which does
    // not. An empty skill list must not widen past it.
    let mut h = Harness::new("empty-skills");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let admission = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(
                    &s,
                    e,
                    "k1",
                    "coder",
                    &[],
                    &["network.https:api.example.com", "model.call:*"],
                    1,
                ),
            )
            .unwrap(),
    );
    assert_eq!(granted_texts(&admission), ["model.call:*"]);
    assert_eq!(
        withheld(&admission),
        [(
            "network.https:api.example.com".to_owned(),
            WithheldCause::NotInSkillSet
        )]
    );
    // Naming another skill only adds a term.
    let more = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(
                    &s,
                    e,
                    "k2",
                    "coder",
                    &["web"],
                    &["network.https:api.example.com", "memory.read:*"],
                    2,
                ),
            )
            .unwrap(),
    );
    assert!(
        granted_texts(&more).is_empty(),
        "house-rules ∩ web covers neither"
    );
    let conn = raw(&h.state());
    let baseline: String = conn
        .query_row(
            "SELECT origin FROM run_skill WHERE run_id = ?1 AND skill = 'house-rules'",
            [admission.run_id().as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        baseline, "BASELINE",
        "the kernel added it; the runtime did not name it"
    );
}

#[test]
fn naming_a_skill_only_narrows() {
    let mut h = Harness::new("narrow");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let without = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(&s, e, "k1", "researcher", &[], &["memory.read:*"], 1),
            )
            .unwrap(),
    );
    let with = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_msg(
                    &s,
                    e,
                    "k2",
                    "researcher",
                    &["models-only"],
                    &["memory.read:*"],
                    2,
                ),
            )
            .unwrap(),
    );
    assert_eq!(granted_texts(&without), ["memory.read:*"]);
    assert!(granted_texts(&with).is_empty());
    assert_eq!(
        withheld(&with),
        [("memory.read:*".to_owned(), WithheldCause::NotInSkillSet)]
    );
}

#[test]
fn an_unknown_or_quarantined_skill_is_the_empty_set_not_the_absence_of_one() {
    let mut h = Harness::new("unknown-skill");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    for (key, named) in [("k1", "no-such-skill"), ("k2", "broken")] {
        let admission = admitted(
            h.authority()
                .admit_run(
                    &a,
                    &admit_msg(&s, e, key, "researcher", &[named], &["model.call:*"], 1),
                )
                .unwrap(),
        );
        assert!(
            granted_texts(&admission).is_empty(),
            "{named} widened nothing"
        );
        assert_eq!(
            withheld(&admission),
            [("model.call:*".to_owned(), WithheldCause::NotInSkillSet)]
        );
    }
}

#[test]
fn a_capability_above_the_mode_ceiling_is_withheld() {
    let mut config = state_support::balanced();
    config.ceiling = vec!["model.call:*".to_owned()];
    let mut h = Harness::with_config("ceiling", config);
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let admission = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_simple(&s, e, "k1", &["model.call:*", "memory.read:*"]),
            )
            .unwrap(),
    );
    assert_eq!(granted_texts(&admission), ["model.call:*"]);
    assert_eq!(
        withheld(&admission),
        [(
            "memory.read:*".to_owned(),
            WithheldCause::AboveProfileCeiling
        )]
    );
}

#[test]
fn a_filesystem_request_is_withheld_honestly_as_an_unresolved_resource() {
    let mut h = Harness::new("fs");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let msg = admit_simple(&s, e, "k1", &["fs.read:/workspace", "model.call:*"]);
    let admission = admitted(h.authority().admit_run(&a, &msg).unwrap());
    assert_eq!(
        withheld(&admission),
        [(
            "fs.read:/workspace".to_owned(),
            WithheldCause::NeedsCanonicalization(UnresolvedScope::CanonicalPath)
        )],
        "not NOT_IN_AGENT_PROFILE: the profile declares exactly this"
    );
    // On the wire it is UNRESOLVED_RESOURCE (ADR-0040), a reason that claims
    // nothing about any declaration.
    let DwkpBody::RunGrant(grant) = h.authority().dispatch(&a, &msg).unwrap() else {
        panic!("a RunGrant")
    };
    let reasons: Vec<WithheldReason> = grant.withheld.iter().map(|w| w.reason).collect();
    assert_eq!(reasons, [WithheldReason::UnresolvedResource]);
    // A universal fs scope needs no canonicalisation and is decided normally.
    let universal = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k2", &["fs.read:*"]))
            .unwrap(),
    );
    assert_eq!(granted_texts(&universal), ["fs.read:*"]);
}

#[test]
fn the_kernel_derives_every_policy_input_itself() {
    let mut h = Harness::new("inputs");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    let context = h.authority().policy_context_of(run.run_id()).unwrap();
    assert_eq!(
        context.origin(),
        Origin::Api,
        "the only admission path is programmatic"
    );
    assert_eq!(
        context.taint(),
        TaintLevel::None,
        "nothing has been delivered yet"
    );
    assert_eq!(
        context.privacy(),
        PrivacyClass::LocalOnly,
        "no workspace is recorded for the session, so its sensitivity is unknown: strictest"
    );
    assert!(!context.standing_grant().is_held());

    // With a kernel-recorded workspace binding, sensitivity narrows the
    // profile's default -- never widens it.
    let (b, s2) = (h.connect(1000), session(2));
    let public = WorkspaceId::new("public-ws").unwrap();
    let secret = WorkspaceId::new("secret-ws").unwrap();
    {
        let mut operator = h.authority().operator();
        operator
            .install_workspace(&public, WorkspaceSensitivity::Public)
            .unwrap();
        operator
            .install_workspace(&secret, WorkspaceSensitivity::Secret)
            .unwrap();
        operator.bind_session_workspace(&s2, &public).unwrap();
        operator
            .bind_session_workspace(&session(3), &secret)
            .unwrap();
    }
    let e2 = h.lease(&b, &s2);
    let researcher = admitted(
        h.authority()
            .admit_run(&b, &admit_simple(&s2, e2, "k1", &["model.call:*"]))
            .unwrap(),
    );
    assert_eq!(
        h.authority()
            .policy_context_of(researcher.run_id())
            .unwrap()
            .privacy(),
        PrivacyClass::Any
    );
    let coder = admitted(
        h.authority()
            .admit_run(
                &b,
                &admit_msg(&s2, e2, "k2", "coder", &[], &["model.call:*"], 2),
            )
            .unwrap(),
    );
    assert_eq!(
        h.authority()
            .policy_context_of(coder.run_id())
            .unwrap()
            .privacy(),
        PrivacyClass::VendorOk,
        "the profile's default is the ceiling; a public workspace does not lift it"
    );
    let (c, s3) = (h.connect(1000), session(3));
    let e3 = h.lease(&c, &s3);
    let in_secret = admitted(
        h.authority()
            .admit_run(&c, &admit_simple(&s3, e3, "k1", &["model.call:*"]))
            .unwrap(),
    );
    assert_eq!(
        h.authority()
            .policy_context_of(in_secret.run_id())
            .unwrap()
            .privacy(),
        PrivacyClass::LocalOnly
    );
    // A workspace can be made stricter and never looser; a binding is for life.
    let mut operator = h.authority().operator();
    assert!(
        operator
            .install_workspace(&secret, WorkspaceSensitivity::Public)
            .is_err()
    );
    assert!(
        operator
            .install_workspace(&public, WorkspaceSensitivity::Private)
            .is_ok()
    );
    assert!(operator.bind_session_workspace(&s2, &secret).is_err());
}

#[test]
fn taint_only_ever_rises() {
    let mut h = Harness::new("taint");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]))
            .unwrap(),
    );
    let id = run.run_id();
    let expected = [
        (TaintLevel::LocalUnverified, TaintLevel::LocalUnverified),
        (TaintLevel::None, TaintLevel::LocalUnverified),
        (TaintLevel::ExternalUntrusted, TaintLevel::ExternalUntrusted),
        (TaintLevel::LocalUnverified, TaintLevel::ExternalUntrusted),
        (TaintLevel::None, TaintLevel::ExternalUntrusted),
    ];
    for (observed, result) in expected {
        assert_eq!(
            h.authority()
                .raise_taint(id, observed, TaintCause::ToolResult)
                .unwrap(),
            result
        );
        assert_eq!(h.authority().policy_context_of(id).unwrap().taint(), result);
    }
    assert_eq!(
        audit_records(&h.state(), AuditEvent::TaintRaised.as_str()).len(),
        2,
        "only the two real rises are recorded"
    );
    // The database refuses a decrease even from a raw write.
    assert!(
        raw(&h.state())
            .execute("UPDATE run_policy_input SET taint = 0", [])
            .is_err()
    );
    // And origin and privacy are fixed at admission.
    assert!(
        raw(&h.state())
            .execute("UPDATE run_policy_input SET origin = 'interactive'", [])
            .is_err()
    );
    assert!(
        raw(&h.state())
            .execute("UPDATE run_policy_input SET privacy = 'ANY'", [])
            .is_err()
    );
}

#[test]
fn every_exhaustive_taint_transition_is_monotonic() {
    // All 3 x 3 (from, observed) pairs, each on a fresh run.
    let mut h = Harness::new("taint-all");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let mut key = 0u64;
    for from in TaintLevel::ALL {
        for observed in TaintLevel::ALL {
            key += 1;
            let run = admitted(
                h.authority()
                    .admit_run(
                        &a,
                        &admit_simple(&s, e, &format!("t{key}"), &["model.call:*"]),
                    )
                    .unwrap(),
            );
            h.authority()
                .raise_taint(run.run_id(), from, TaintCause::ArtifactRead)
                .unwrap();
            let after = h
                .authority()
                .raise_taint(run.run_id(), observed, TaintCause::MemoryRetrieval)
                .unwrap();
            assert_eq!(after, from.max(observed), "{from:?} then {observed:?}");
            assert!(after >= from, "never lowered");
        }
    }
}

#[test]
fn the_runtime_has_no_field_in_which_to_state_a_policy_input() {
    let s = session(1);
    let base = |extra: &str, envelope: &str| {
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{s}","epoch":1,"idempotency_key":"k"{envelope},"payload":{{"agent_profile":"researcher","skills":[],"requested_capabilities":[]{extra}}}}}"#,
            id = id("msg", 1),
            s = s.as_str(),
        )
    };
    for field in [
        r#","origin":"interactive""#,
        r#","taint":"NONE""#,
        r#","taint_level":"NONE""#,
        r#","privacy_class":"ANY""#,
        r#","workspace_sensitivity":"PUBLIC""#,
        r#","standing_grant":true"#,
        r#","mode":"POWER""#,
        r#","profile":"POWER""#,
        r#","policy_revision":"00""#,
        r#","trusted_skills":["x"]"#,
        r#","metadata":{}"#,
    ] {
        let json = base(field, "");
        assert!(
            dwk_proto::dwkp::decode_body(json.as_bytes()).is_err(),
            "the decoder accepted {field}"
        );
    }
    let with_run = base(
        "",
        &format!(r#","run_id":"{}""#, state_support::run_id(9).as_str()),
    );
    assert!(
        dwk_proto::dwkp::decode_body(with_run.as_bytes()).is_err(),
        "the runtime cannot name the run the kernel will mint"
    );
    // The base request itself decodes: the refusals above are about the field.
    let _ = decode(&base("", ""));
}

#[test]
fn ids_are_the_wire_types_distinct_and_kernel_minted() {
    let mut h = Harness::new("ids");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let mut seen = std::collections::BTreeSet::new();
    for n in 0..20 {
        let run = admitted(
            h.authority()
                .admit_run(
                    &a,
                    &admit_simple(&s, e, &format!("k{n}"), &["model.call:*", "memory.read:*"]),
                )
                .unwrap(),
        );
        assert!(seen.insert(run.run_id().as_str().to_owned()));
        for grant in run.granted() {
            assert!(seen.insert(grant.cap_id().as_str().to_owned()));
        }
    }
    assert_eq!(seen.len(), 60);
}

#[test]
fn a_cap_id_collision_fails_the_whole_admission_closed() {
    // Plant a row holding the id the store will mint next -- an attacker with
    // file access, or a corrupt counter -- and show the admission refuses
    // rather than overwriting or sharing it.
    let mut h = Harness::new("collision");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let conn = raw(&h.state());
    let (store_id, counter): (String, i64) = conn
        .query_row("SELECT store_id, id_counter FROM store_meta", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    let instance = u32::from_str_radix(&store_id[..8], 16).unwrap();
    // The run id takes counter + 1; the first cap id counter + 2. The layout is
    // ids.rs's, restated here: the test knows what the store will do.
    let next = u128::from(u64::try_from(counter + 2).unwrap());
    let ts = u128::from(h.clock.now_ms());
    let value = (ts << 80)
        | (0x7 << 76)
        | (((next >> 30) & 0x0fff) << 64)
        | (0b10 << 62)
        | ((next & 0x3fff_ffff) << 32)
        | u128::from(instance);
    let planted = dwk_proto::wire::id::CapId::from_uuid(value).unwrap();
    // The bundled SQLite enforces foreign keys by default; an attacker with the
    // file simply turns them off for their own connection.
    conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
    conn.execute(
        "INSERT INTO run_grant (cap_id, run_id, ordinal, capability) VALUES (?1, 'x', 0, 'x')",
        [planted.as_str()],
    )
    .unwrap();
    let result = h
        .authority()
        .admit_run(&a, &admit_simple(&s, e, "k1", &["model.call:*"]));
    assert!(
        matches!(result, Err(AuthorityError::Rejected(_))),
        "{result:?}"
    );
    assert_eq!(
        count(&conn, "SELECT count(*) FROM run"),
        0,
        "nothing committed"
    );
    assert_eq!(
        count(&conn, "SELECT count(*) FROM admission_idempotency"),
        0
    );
}

#[test]
fn the_admission_record_binds_what_an_investigator_needs() {
    let mut h = Harness::new("audit");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let run = admitted(
        h.authority()
            .admit_run(
                &a,
                &admit_simple(&s, e, "k1", &["model.call:*", "secret.use:x"]),
            )
            .unwrap(),
    );
    let records = audit_records(&h.state(), AuditEvent::RunAdmitted.as_str());
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(text(record, "run_id"), Some(run.run_id().as_str()));
    assert_eq!(text(record, "subject"), Some("uid:1000"));
    assert_eq!(
        text(record, "policy_revision"),
        Some(run.policy_revision().to_hex().as_str())
    );
    assert_eq!(text(record, "origin"), Some("api"));
    assert_eq!(text(record, "taint"), Some("NONE"));
    assert!(text(record, "request_digest").is_some());
    let line = state_support::audit_lines(&h.state()).join("\n");
    assert!(line.contains(run.granted()[0].cap_id().as_str()));
    assert!(line.contains("NOT_IN_AGENT_PROFILE"));
    let _ = query_msg(&s, run.run_id(), epoch(e.get()), None);
}
