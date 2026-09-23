//! A hostile runtime, in process.
//!
//! M3e puts a real socket and a real peer in front of these operations; the
//! real-process versions of these attacks are `transport_hostile.rs`.
//! Until then the adversary is a caller of `dispatch` with decoded DWKP
//! messages — the same objects the socket will produce — and the question is
//! always the same: **can any of this become broader authority?**
//!
//! Many single cases live in the per-area suites. This file holds the ones
//! that are about the combination, and the property that ties them together.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

use std::collections::BTreeSet;

use dwk_proto::dwkp::DwkpBody;
use dwk_proto::wire::scalar::{CapabilityText, RefusalReason};
use dwkd_authority::capability::CapabilitySet;
use dwkd_authority::state::{AuthorityError, CallerContext, Proposal, Reply};
use proptest::prelude::*;
use state_support::{
    Harness, admit_msg, admit_simple, count, query_msg, raw, release_run_msg, session,
};

/// Every capability some active run of `session` holds, as the store records it.
fn effective(h: &Harness) -> BTreeSet<String> {
    let conn = raw(&h.state());
    let mut statement = conn
        .prepare(
            "SELECT g.capability FROM run_grant g JOIN run r ON r.run_id = g.run_id \
             WHERE r.state = 'ACTIVE'",
        )
        .unwrap();
    statement
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn no_hostile_request_in_the_list_widens_anything() {
    let mut h = Harness::new("hostile");
    let s = session(1);
    let owner = h.connect(1000);
    let e = h.lease(&owner, &s);
    let honest = admit_simple(&s, e, "k1", &["model.call:*"]);
    let DwkpBody::RunGrant(grant) = h.authority().dispatch(&owner, &honest).unwrap() else {
        panic!("admitted")
    };
    let baseline = effective(&h);

    let intruder = h.connect(1000); // same uid, different connection
    let stranger = h.connect(6666);
    let hostile: Vec<(&str, CallerContext, dwk_proto::dwkp::DwkpMessage)> = vec![
        (
            "same uid, new connection, valid key",
            intruder,
            honest.clone(),
        ),
        ("another uid, valid key", stranger, honest.clone()),
        (
            "changed profile under the key",
            owner,
            admit_msg(&s, e, "k1", "coder", &[], &["model.call:*"], 9),
        ),
        (
            "changed skills under the key",
            owner,
            admit_msg(&s, e, "k1", "researcher", &["web"], &["model.call:*"], 9),
        ),
        (
            "changed capabilities under the key",
            owner,
            admit_msg(&s, e, "k1", "researcher", &[], &["network.https:*"], 9),
        ),
        (
            "empty skills on a baseline profile",
            owner,
            admit_msg(&s, e, "k2", "coder", &[], &["network.https:*"], 9),
        ),
        (
            "an unknown skill",
            owner,
            admit_msg(
                &s,
                e,
                "k3",
                "researcher",
                &["mystery"],
                &["network.https:*"],
                9,
            ),
        ),
        (
            "a quarantined skill",
            owner,
            admit_msg(&s, e, "k4", "researcher", &["broken"], &["model.call:*"], 9),
        ),
        (
            "an unknown profile",
            owner,
            admit_msg(&s, e, "k5", "root", &[], &["model.call:*"], 9),
        ),
        (
            "a wildcard beyond the profile",
            owner,
            admit_msg(&s, e, "k6", "researcher", &[], &["network.https:*"], 9),
        ),
        (
            "the other connection querying",
            intruder,
            query_msg(&s, &grant.run_id, e, Some("model.call:*")),
        ),
        (
            "the other connection releasing",
            stranger,
            release_run_msg(&s, &grant.run_id, e),
        ),
    ];
    for (case, caller, message) in hostile {
        let answer = h.authority().dispatch(&caller, &message).unwrap();
        // Nothing in the list is entitled to anything: the requests that are
        // admissions at all are admissions of nothing, and every other one is
        // refused. Effective authority is exactly what it was.
        assert_eq!(effective(&h), baseline, "{case}: {answer:?}");
    }
    // The owner's original run still holds exactly what it was granted.
    let DwkpBody::EffectiveAuthority(answer) = h
        .authority()
        .dispatch(&owner, &query_msg(&s, &grant.run_id, e, None))
        .unwrap()
    else {
        panic!("still answered")
    };
    assert_eq!(answer.granted, grant.granted);
}

#[test]
fn id_space_exhaustion_fails_closed() {
    let mut h = Harness::new("ids");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    raw(&h.state())
        .execute("UPDATE store_meta SET id_counter = 4398046511103", [])
        .unwrap();
    assert_eq!(
        h.authority()
            .admit_run(&a, &admit_simple(&s, e, "k", &["model.call:*"])),
        Err(AuthorityError::IdSpaceExhausted)
    );
    assert_eq!(count(&raw(&h.state()), "SELECT count(*) FROM run"), 0);
}

#[test]
fn hostile_looking_values_are_data_not_sql() {
    // Every value reaches SQLite as a bound parameter. The grammar of each
    // field is narrow already; these are the most SQL-flavoured spellings the
    // decoder still accepts, and they are stored and compared as text.
    let mut h = Harness::new("sql");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let key = "k1:--.drop_table.run";
    let Reply::Done(first) = h
        .authority()
        .admit_run(
            &a,
            &admit_msg(
                &s,
                e,
                key,
                "researcher",
                &["x-or-1-1"],
                &["model.call:*"],
                1,
            ),
        )
        .unwrap()
    else {
        panic!("admitted")
    };
    let Reply::Done(again) = h
        .authority()
        .admit_run(
            &a,
            &admit_msg(
                &s,
                e,
                key,
                "researcher",
                &["x-or-1-1"],
                &["model.call:*"],
                2,
            ),
        )
        .unwrap()
    else {
        panic!("replayed")
    };
    assert_eq!(first, again);
    let conn = raw(&h.state());
    assert_eq!(
        count(&conn, "SELECT count(*) FROM run"),
        1,
        "the table is still there"
    );
    let stored: String = conn
        .query_row(
            "SELECT idempotency_key FROM admission_idempotency",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, key);
    // A proposal with the SQL wildcard characters the capability grammar allows.
    let proposal = CapabilityText::new("model.call:x_y/*").unwrap();
    let _ = h
        .authority()
        .query_authority(&a, &s, first.run_id(), e, Some(Proposal::Text(&proposal)))
        .unwrap();
    assert_eq!(count(&conn, "SELECT count(*) FROM run"), 1);
}

#[test]
fn a_stale_caller_with_a_valid_key_learns_nothing_it_did_not_have() {
    let mut h = Harness::new("oracle");
    let (a, s) = (h.connect(1000), session(1));
    let e = h.lease(&a, &s);
    let message = admit_simple(&s, e, "k1", &["model.call:*"]);
    let _ = h.authority().admit_run(&a, &message).unwrap();
    let b = h.connect(1000);
    for probe in [
        admit_simple(&s, e, "k1", &["model.call:*"]),
        admit_simple(&s, e, "unused", &["model.call:*"]),
        admit_simple(&session(99), e, "k1", &["model.call:*"]),
    ] {
        let DwkpBody::AuthorityRefused(refusal) = h.authority().dispatch(&b, &probe).unwrap()
        else {
            panic!("refused")
        };
        assert_eq!(
            refusal.reason,
            RefusalReason::StaleEpoch,
            "a known key, an unknown key and an unknown session all read alike"
        );
    }
}

// ---------------------------------------------------------------------------
// Release, replay, staleness, expiry and restart only ever remove authority.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Act {
    Admit(u8),
    Release(u8),
    Replay(u8),
    StaleAdmit(u8),
    Expire,
    Restart,
}

fn act() -> impl Strategy<Value = Act> {
    prop_oneof![
        3 => (0u8..4).prop_map(Act::Admit),
        3 => (0u8..4).prop_map(Act::Release),
        2 => (0u8..4).prop_map(Act::Replay),
        1 => (0u8..4).prop_map(Act::StaleAdmit),
        1 => Just(Act::Expire),
        1 => Just(Act::Restart),
    ]
}

/// The `researcher` fixture's declared set (state_support::install_fixtures).
const RESEARCHER: [&str; 9] = [
    "model.call:*",
    "memory.read:*",
    "memory.promote:*",
    "network.https:*.example.com",
    "network.https:github.com",
    "network.http:*",
    "scheduler.create:*",
    "fs.read:/workspace",
    "fs.read:*",
];

fn caps(n: u8) -> &'static [&'static str] {
    match n % 4 {
        0 => &["model.call:*"],
        1 => &["memory.read:*"],
        2 => &["model.call:*", "memory.read:*"],
        _ => &["network.https:api.example.com"],
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    #[test]
    fn only_an_admission_ever_adds_authority(acts in proptest::collection::vec(act(), 1..30)) {
        let mut h = Harness::new("prop-narrow");
        let s = session(1);
        let mut caller = h.connect(1000);
        let mut e = h.lease(&caller, &s);
        let mut runs: Vec<(u8, dwk_proto::wire::id::RunId, dwk_proto::wire::scalar::Epoch)> = Vec::new();
        for act in acts {
            let before = effective(&h);
            let mut admitted = false;
            match act {
                Act::Admit(n) => {
                    let message = admit_simple(&s, e, &format!("k{n}-{}", e.get()), caps(n));
                    if let Ok(Reply::Done(admission)) = h.authority().admit_run(&caller, &message) {
                        admitted = true;
                        runs.push((n, admission.run_id().clone(), e));
                    }
                }
                Act::Release(n) => {
                    if let Some((_, run, at)) = runs.get(usize::from(n)).cloned() {
                        let _ = h.authority().release_run(&caller, &s, &run, at).unwrap();
                    }
                }
                Act::Replay(n) => {
                    if let Some((m, _, at)) = runs.get(usize::from(n)).cloned() {
                        let message = admit_simple(&s, at, &format!("k{m}-{}", at.get()), caps(m));
                        let _ = h.authority().admit_run(&caller, &message);
                    }
                }
                Act::StaleAdmit(n) => {
                    let zombie = h.connect(1000);
                    let message = admit_simple(&s, e, &format!("z{n}"), caps(n));
                    let reply = h.authority().admit_run(&zombie, &message).unwrap();
                    prop_assert_eq!(reply, Reply::Refused(RefusalReason::StaleEpoch));
                }
                Act::Expire => {
                    h.clock.advance(dwkd_authority::state::DEFAULT_LEASE_TTL_MS + 1);
                    caller = h.connect(1000);
                    e = h.lease(&caller, &s);
                }
                Act::Restart => {
                    h.restart();
                    caller = h.connect(1000);
                    e = h.lease(&caller, &s);
                }
            }
            let after = effective(&h);
            if !admitted {
                prop_assert!(after.is_subset(&before), "{act:?} added authority: {before:?} -> {after:?}");
            }
            // Whatever happened, everything effective is inside the profile's
            // declared ceiling: one declared member covers each whole.
            let ceiling: CapabilitySet = RESEARCHER
                .iter()
                .filter_map(|c| dwkd_authority::capability::parse(c).ok()?.resolve().ok())
                .collect();
            for cap in &after {
                let capability = dwkd_authority::capability::parse(cap).unwrap().resolve().unwrap();
                prop_assert!(ceiling.covers(&capability), "{cap} escaped the profile");
            }
        }
    }
}
