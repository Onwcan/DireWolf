//! Every response the state layer produces survives the real wire.
//!
//! Each answer from `Authority::dispatch` is wrapped in the response envelope
//! the M3e server sends, encoded to canonical bytes, and decoded again by
//! `dwk_proto`'s own decoder — which closes the pairing of refusal operation
//! and reason, and which `DwkpMessage::to_value` already re-runs before it
//! returns. A body the decoder would reject cannot pass.
//!
//! The scenario is built to reach **every** pair in the decoder's refusal
//! table and every withheld reason M3d produces, and the test asserts that it
//! did: a mapping this file does not exercise is a mapping nobody has shown the
//! wire accepts. Decisions are made only about complete canonical actions
//! (ADR-0040), which in M3d come from the in-process path tests stand in for;
//! their `EffectiveAuthority` bodies go through the same encoder and decoder,
//! and every decision reason is reached.

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

use std::collections::BTreeSet;

use dwk_proto::dwkp::messages::REFUSALS;
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::envelope::Header;
use dwk_proto::wire::id::AnyId;
use dwk_proto::wire::scalar::{SchemaName, Timestamp, Version};
use dwkd_authority::capability::parse;
use dwkd_authority::policy::{CanonicalAction, Environment};
use dwkd_authority::state::{CallerContext, Proposal, Reply, wire};
use state_support::{
    Harness, acquire_msg, admit_msg, heartbeat_msg, id, query_msg, release_lease_msg,
    release_run_msg, session,
};

/// What the scenario has put on the wire so far.
#[derive(Default)]
struct Seen {
    schemas: BTreeSet<&'static str>,
    refusals: BTreeSet<(String, String)>,
    decisions: BTreeSet<String>,
    withheld: BTreeSet<String>,
    sent: u64,
}

impl Seen {
    /// Dispatch `request`, send the answer through the encoder and decoder,
    /// and return the body as the peer would receive it.
    fn send(&mut self, h: &mut Harness, caller: &CallerContext, request: &DwkpMessage) -> DwkpBody {
        let body = h.authority().dispatch(caller, request).unwrap();
        self.transmit(body, request)
    }

    /// Wrap `body` in the response envelope answering `request`, encode it,
    /// decode it, and record what crossed.
    fn transmit(&mut self, body: DwkpBody, request: &DwkpMessage) -> DwkpBody {
        self.sent += 1;
        let (message_type, schema) = body.identity();
        let version = dwk_proto::dwkp::registry::MESSAGES
            .iter()
            .find(|m| m.schema == schema)
            .map(|m| m.versions.max)
            .unwrap();
        let response = DwkpMessage {
            header: Header {
                v: Version::new(1).unwrap(),
                id: AnyId::parse(&id("msg", 900_000 + self.sent)).unwrap(),
                message_type,
                schema: SchemaName::new(schema).unwrap(),
                schema_version: Version::new(version).unwrap(),
                ts: Timestamp::new("2026-09-21T10:00:00.000Z").unwrap(),
                correlation_id: request.header.correlation_id.clone(),
                causation_id: Some(request.header.id.clone()),
                session_id: None,
                run_id: None,
                epoch: None,
                idempotency_key: None,
            },
            body,
        };
        let bytes = response
            .to_canonical_bytes()
            .unwrap_or_else(|e| panic!("{schema} encodes: {e}"));
        let decoded = dwkp::decode_body(&bytes).unwrap_or_else(|e| panic!("{schema} decodes: {e}"));
        assert_eq!(decoded, response, "{schema} survives its round trip");

        self.schemas.insert(schema);
        match &decoded.body {
            DwkpBody::AuthorityRefused(refusal) => {
                self.refusals.insert((
                    refusal.operation.as_str().to_owned(),
                    refusal.reason.as_str().to_owned(),
                ));
            }
            DwkpBody::RunGrant(grant) => {
                for entry in grant.withheld.iter() {
                    self.withheld.insert(entry.reason.as_str().to_owned());
                }
            }
            DwkpBody::EffectiveAuthority(answer) => {
                for entry in answer.withheld.iter() {
                    self.withheld.insert(entry.reason.as_str().to_owned());
                }
                if let Some(decision) = &answer.decision {
                    self.decisions.insert(decision.reason.as_str().to_owned());
                }
            }
            _ => {}
        }
        decoded.body
    }
}

#[test]
fn every_state_response_round_trips_and_every_refusal_pair_is_reached() {
    let mut config = state_support::balanced();
    // A ceiling below what the profile and skill both declare, so one request
    // is withheld by each of the three terms M3d can apply.
    config.ceiling = vec!["model.call:*".to_owned()];
    let mut h = Harness::with_config("wire", config);
    let mut seen = Seen::default();
    let a = h.connect(1000);
    let b = h.connect(1000); // same subject, another connection: another holder
    let s = session(1);

    let DwkpBody::LeaseGrant(lease) = seen.send(&mut h, &a, &acquire_msg(&s)) else {
        panic!("a LeaseGrant")
    };
    let e = lease.epoch;
    let DwkpBody::AuthorityRefused(_) = seen.send(&mut h, &b, &acquire_msg(&s)) else {
        panic!("LEASE_HELD")
    };
    let DwkpBody::Ack(_) = seen.send(&mut h, &a, &heartbeat_msg(&s, e)) else {
        panic!("a heartbeat Ack")
    };
    seen.send(&mut h, &b, &heartbeat_msg(&s, e));
    seen.send(&mut h, &b, &release_lease_msg(&s, e));

    let requested = [
        "model.call:anthropic/*",        // granted
        "secret.use:github",             // NOT_IN_AGENT_PROFILE
        "memory.read:*",                 // NOT_IN_SKILL_SET (web does not declare it)
        "network.https:api.example.com", // ABOVE_PROFILE_CEILING
        "fs.read:/workspace",            // UNRESOLVED_RESOURCE
    ];
    let admit = admit_msg(&s, e, "k1", "researcher", &["web"], &requested, 1);
    let DwkpBody::RunGrant(grant) = seen.send(&mut h, &a, &admit) else {
        panic!("a RunGrant")
    };
    let DwkpBody::RunGrant(replayed) = seen.send(&mut h, &a, &admit) else {
        panic!("the recorded RunGrant")
    };
    assert_eq!(replayed, grant, "a replay answers with the recorded grant");
    let conflicting = admit_msg(&s, e, "k1", "researcher", &["web"], &["model.call:*"], 2);
    seen.send(&mut h, &a, &conflicting);
    seen.send(
        &mut h,
        &a,
        &admit_msg(
            &s,
            e,
            "k2",
            "nobody-installed-this",
            &[],
            &["model.call:*"],
            3,
        ),
    );
    seen.send(&mut h, &b, &admit);

    let run = &grant.run_id;
    let DwkpBody::EffectiveAuthority(answer) = seen.send(&mut h, &a, &query_msg(&s, run, e, None))
    else {
        panic!("EffectiveAuthority")
    };
    assert!(answer.decision.is_none(), "no proposal, no decision");
    // Every wire proposal is refused before any rule runs (ADR-0040).
    for proposed in [
        "model.call:anthropic/claude",
        "fs.read:/etc/hosts",
        "teleport.now:*",
    ] {
        let DwkpBody::AuthorityRefused(refusal) =
            seen.send(&mut h, &a, &query_msg(&s, run, e, Some(proposed)))
        else {
            panic!("a refusal for {proposed}")
        };
        assert_eq!(refusal.reason.as_str(), "NO_CANONICAL_ACTION", "{proposed}");
    }
    // Decisions about complete canonical actions: the in-process path, the
    // same encoder and decoder.
    let carrier = query_msg(&s, run, e, None);
    let caller = &a;
    for capability in [
        "model.call:anthropic/claude", // ALLOWED_BY_RULE
        "model.call:openai/gpt",       // NO_CAPABILITY
        "network.http:example.com",    // DENIED_BY_RULE
        "scheduler.create:*",          // DEFAULT_DENY
    ] {
        let action = CanonicalAction::new(
            parse(capability).unwrap().resolve().unwrap(),
            Environment::Sandbox,
        );
        let Reply::Done(answer) = h
            .authority()
            .query_authority(caller, &s, run, e, Some(Proposal::Action(&action)))
            .unwrap()
        else {
            panic!("answered")
        };
        let body = DwkpBody::EffectiveAuthority(wire::effective_authority(&answer).unwrap());
        let DwkpBody::EffectiveAuthority(sent) = seen.transmit(body, &carrier) else {
            panic!("EffectiveAuthority")
        };
        assert!(sent.decision.is_some(), "a decision for {capability}");
    }
    seen.send(&mut h, &b, &query_msg(&s, run, e, None));
    seen.send(&mut h, &b, &release_run_msg(&s, run, e));

    let DwkpBody::Ack(_) = seen.send(&mut h, &a, &release_run_msg(&s, run, e)) else {
        panic!("a ReleaseRun Ack")
    };
    let DwkpBody::Ack(_) = seen.send(&mut h, &a, &release_run_msg(&s, run, e)) else {
        panic!("releasing twice is acknowledged")
    };
    seen.send(&mut h, &a, &query_msg(&s, run, e, None));
    // The key's run has ended: the same admission again is spent, not replayed.
    let DwkpBody::AuthorityRefused(ended) = seen.send(&mut h, &a, &admit) else {
        panic!("ADMISSION_ENDED")
    };
    assert_eq!(ended.reason.as_str(), "ADMISSION_ENDED");
    let DwkpBody::Ack(_) = seen.send(&mut h, &a, &release_lease_msg(&s, e)) else {
        panic!("a ReleaseLease Ack")
    };
    let DwkpBody::AuthorityRefused(_) = seen.send(&mut h, &a, &heartbeat_msg(&s, e)) else {
        panic!("a released lease cannot be renewed")
    };

    let table: BTreeSet<(String, String)> = REFUSALS
        .iter()
        .flat_map(|(operation, reasons)| {
            reasons
                .iter()
                .map(move |reason| ((*operation).to_owned(), (*reason).to_owned()))
        })
        .collect();
    assert_eq!(
        seen.refusals, table,
        "every refusal pair the decoder accepts is produced, and nothing else"
    );
    assert_eq!(table.len(), 11);
    assert_eq!(
        seen.decisions,
        [
            "ALLOWED_BY_RULE",
            "DEFAULT_DENY",
            "DENIED_BY_RULE",
            "NO_CAPABILITY",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect::<BTreeSet<_>>(),
        "every decision reason, and no CAPABILITY_MALFORMED (ADR-0040)"
    );
    assert_eq!(
        seen.withheld,
        [
            "ABOVE_PROFILE_CEILING",
            "NOT_IN_AGENT_PROFILE",
            "NOT_IN_SKILL_SET",
            "UNRESOLVED_RESOURCE",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect::<BTreeSet<_>>(),
        "NOT_IN_PARENT_GRANT and DENIED_BY_POLICY are never produced in M3d"
    );
    assert_eq!(
        seen.schemas,
        [
            "direwolf.ack",
            "direwolf.authority.effective",
            "direwolf.authority.refused",
            "direwolf.lease.grant",
            "direwolf.run.grant",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
}
