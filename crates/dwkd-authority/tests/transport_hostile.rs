//! The hostile DWKP client (EVALS.md §3), against the real authority process.
//!
//! This process plays a completely compromised runtime: it sends whatever
//! bytes it likes to `dwkd-authority serve`. Every case asserts that the
//! attack was **contained** — and where — and, where it is security-
//! significant, that `audit.log` (read through the verifier) **recorded** it.
//! Each passing case prints one `DWKP-EVIDENCE` line; the M3 evaluation
//! (`authority-security/hostile-dwkp-client`) runs this file and reads them.
//!
//! Where a case is contained, from strongest to weakest:
//!
//! * `peer-gate` — refused on the kernel-reported uid, before a byte was read;
//! * `framing` / `decoder` — `dwk-proto`'s production framing and decoder;
//! * `connection-protocol` — the handshake-first state machine;
//! * `state-fence` — the M3d state layer: epoch, holder, idempotency, runs;
//! * `capability-policy` — no canonical action, so nothing decided.
//!
//! "Nothing reached `Authority::dispatch`" is proven, not asserted: every
//! dispatched `AdmitRun`, lease operation and fenced request writes a state
//! record, and the cases that must stop at the decoder or the connection
//! protocol assert that no state record appeared.

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

mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::net::Shutdown;
    use std::time::Duration;

    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::error::{ErrorCode, Violation};
    use dwk_proto::wire::id::SessionId;
    use dwk_proto::wire::scalar::{Epoch, RefusalReason, RefusedOperation};

    use super::state_support::{
        acquire_msg, admit_simple, epoch, heartbeat_msg, id, query_msg, release_run_msg, run_id,
        session,
    };
    use super::transport_support::{
        Client, Fixture, PROMPT, Server, evidence, handshake, handshake_json,
    };

    /// Tracks `transport.protocol_violation` records and the state records
    /// around them.
    struct Audit<'a> {
        fx: &'a Fixture,
        violations: usize,
    }

    impl<'a> Audit<'a> {
        fn new(fx: &'a Fixture) -> Self {
            Self {
                fx,
                violations: fx.events("transport.protocol_violation").len(),
            }
        }

        /// Wait for the next violation record and check it says `violation`
        /// with `code`.
        fn expect(&mut self, violation: &str, code: Option<&str>) {
            let deadline = std::time::Instant::now() + PROMPT;
            loop {
                let records = self.fx.events("transport.protocol_violation");
                if records.len() > self.violations {
                    let record = &records[self.violations];
                    assert_eq!(record.text("violation"), Some(violation));
                    assert_eq!(record.text("code"), code);
                    assert!(record.text("holder").is_some(), "the connection's holder");
                    self.violations += 1;
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "no {violation} record was written"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// How many records the state layer (not the transport) has written.
        fn state_records(&self) -> usize {
            self.fx
                .audit()
                .iter()
                .filter(|record| !record.event().starts_with("transport."))
                .count()
        }
    }

    fn connected(fx: &Fixture) -> Client {
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        client
    }

    /// The server answers with a protocol error and closes.
    fn protocol_error(client: &mut Client) -> (ErrorCode, Option<Violation>, String) {
        let message = client.recv(PROMPT).message();
        let DwkpBody::ProtocolError(payload) = message.body else {
            panic!("expected a protocol error, got {:?}", message.body)
        };
        assert!(
            client.recv(PROMPT).is_closed(),
            "a protocol error closes the connection"
        );
        (
            payload.code,
            payload.violation,
            payload
                .path
                .map(|path| path.as_str().to_owned())
                .unwrap_or_default(),
        )
    }

    /// The server closes without answering.
    fn closed_unanswered(client: &mut Client) {
        assert!(
            client.recv(PROMPT).is_closed(),
            "closed, and nothing was sent"
        );
    }

    fn refusal(message: &DwkpMessage) -> (RefusedOperation, RefusalReason) {
        match &message.body {
            DwkpBody::AuthorityRefused(refusal) => (refusal.operation, refusal.reason),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn lease(client: &mut Client, s: &SessionId) -> Epoch {
        match client.call(&acquire_msg(s)).body {
            DwkpBody::LeaseGrant(grant) => grant.epoch,
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    fn envelope(schema: &str, extra: &str, payload: &str) -> String {
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"{schema}","schema_version":1,"ts":"2026-09-22T10:00:00.000Z"{extra},"payload":{{{payload}}}}}"#,
            id = id("msg", 70_000),
        )
    }

    fn admit_json(
        s: &SessionId,
        epoch: u64,
        key: &str,
        envelope_extra: &str,
        payload_extra: &str,
    ) -> String {
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}"{envelope_extra},"payload":{{"agent_profile":"researcher","skills":[],"requested_capabilities":["model.call:*"]{payload_extra}}}}}"#,
            id = id("msg", 70_001),
            session = s.as_str(),
        )
    }

    #[test]
    fn framing_attacks_are_answered_once_and_close_the_stream() {
        let fx = Fixture::new("h-framing");
        let _server = Server::start(&fx.args(&[]));
        let mut audit = Audit::new(&fx);
        let before = audit.state_records();

        // A header declaring 2 MiB: refused from the header alone, without the
        // server waiting for (or buffering) the body.
        let mut client = connected(&fx);
        client.raw(&[0x00, 0x20, 0x00, 0x00, 0x01]).unwrap();
        assert_eq!(protocol_error(&mut client).0, ErrorCode::FrameTooLarge);
        audit.expect("framing", Some("PROTOCOL_FRAME_TOO_LARGE"));
        evidence("hostile", "oversized-frame", "framing", true, true);

        let mut client = connected(&fx);
        client.raw(&[0, 0, 0, 0, 1]).unwrap();
        assert_eq!(protocol_error(&mut client).0, ErrorCode::FrameEmpty);
        audit.expect("framing", Some("PROTOCOL_FRAME_EMPTY"));
        evidence("hostile", "invalid-frame-length", "framing", true, true);

        let mut client = connected(&fx);
        client.raw(&[0, 0, 0, 2, 0x02, b'{', b'}']).unwrap();
        assert_eq!(
            protocol_error(&mut client).0,
            ErrorCode::ContentTypeUnsupported
        );
        audit.expect("framing", Some("PROTOCOL_CONTENT_TYPE_UNSUPPORTED"));
        evidence("hostile", "reserved-content-type", "framing", true, true);

        // A frame that ends early: the partial request is never decoded.
        let mut client = connected(&fx);
        client.raw(&[0, 0, 0, 100, 0x01]).unwrap();
        client.raw(b"{\"v\":1,\"id\"").unwrap();
        client.stream().shutdown(Shutdown::Write).unwrap();
        assert_eq!(protocol_error(&mut client).0, ErrorCode::FrameTruncated);
        audit.expect("truncated", Some("PROTOCOL_FRAME_TRUNCATED"));
        evidence("hostile", "truncated-frame", "framing", true, true);

        // Before the handshake too.
        let mut client = Client::connect(&fx.socket());
        client.raw(&[0xff, 0xff, 0xff, 0xff, 0x01]).unwrap();
        assert_eq!(protocol_error(&mut client).0, ErrorCode::FrameTooLarge);
        audit.expect("framing", Some("PROTOCOL_FRAME_TOO_LARGE"));

        assert_eq!(
            audit.state_records(),
            before,
            "nothing reached the state layer"
        );
    }

    #[test]
    fn malformed_messages_are_refused_by_the_production_decoder() {
        let fx = Fixture::new("h-decoder");
        let _server = Server::start(&fx.args(&[]));
        let mut audit = Audit::new(&fx);
        let before = audit.state_records();
        let s = session(1);
        let sid = s.as_str().to_owned();

        let cases: Vec<(&str, Vec<u8>, ErrorCode, Option<Violation>)> = vec![
            (
                "duplicate-json-key",
                format!(
                    r#"{{"v":1,"v":1,"id":"{}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","payload":{{}}}}"#,
                    id("msg", 1)
                )
                .into_bytes(),
                ErrorCode::DuplicateKey,
                None,
            ),
            ("malformed-json", b"{\"v\":1,".to_vec(), ErrorCode::InvalidJson, None),
            ("non-utf8", b"{\"v\":\"\xff\xfe\"}".to_vec(), ErrorCode::InvalidUtf8, None),
            (
                "depth-bomb",
                envelope(
                    "direwolf.heartbeat",
                    "",
                    &format!("\"x\":{}{}", "[".repeat(40), "]".repeat(40)),
                )
                .into_bytes(),
                ErrorCode::MaxDepthExceeded,
                None,
            ),
            (
                "malformed-id",
                br#"{"v":1,"id":"msg_NOT-A-UUIDv7","type":"request","schema":"direwolf.lease.acquire","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","session_id":"ses_0","payload":{}}"#.to_vec(),
                ErrorCode::SchemaViolation,
                Some(Violation::InvalidFormat),
            ),
            (
                "missing-envelope-field",
                format!(
                    r#"{{"v":1,"id":"{}","type":"request","schema":"direwolf.lease.acquire","schema_version":1,"session_id":"{sid}","payload":{{}}}}"#,
                    id("msg", 2)
                )
                .into_bytes(),
                ErrorCode::SchemaViolation,
                Some(Violation::MissingField),
            ),
            (
                "number-out-of-domain",
                envelope(
                    "direwolf.heartbeat",
                    &format!(r#","session_id":"{sid}","epoch":1.5"#),
                    "",
                )
                .into_bytes(),
                ErrorCode::NumberOutOfDomain,
                None,
            ),
            (
                "unknown-field",
                envelope(
                    "direwolf.heartbeat",
                    &format!(r#","session_id":"{sid}","epoch":1"#),
                    r#""extra":1"#,
                )
                .into_bytes(),
                ErrorCode::SchemaViolation,
                Some(Violation::UnknownField),
            ),
            (
                "forbidden-envelope-field",
                envelope(
                    "direwolf.heartbeat",
                    &format!(r#","session_id":"{sid}","epoch":1,"idempotency_key":"k""#),
                    "",
                )
                .into_bytes(),
                ErrorCode::SchemaViolation,
                Some(Violation::ForbiddenField),
            ),
            (
                "unknown-operation",
                envelope("direwolf.frobnicate", "", "").into_bytes(),
                ErrorCode::UnknownOperation,
                None,
            ),
            (
                "reserved-tool-invoke",
                envelope("direwolf.tool.invoke", &format!(r#","session_id":"{sid}","epoch":1"#), r#""tool":"fs.write""#).into_bytes(),
                ErrorCode::UnknownOperation,
                None,
            ),
            (
                "reserved-canonical-preview",
                envelope("direwolf.canonical.preview", "", r#""tool":"fs.read""#).into_bytes(),
                ErrorCode::UnknownOperation,
                None,
            ),
            (
                "reserved-model-call",
                envelope("direwolf.model.call", "", "").into_bytes(),
                ErrorCode::UnknownOperation,
                None,
            ),
            (
                "unsupported-envelope-version",
                br#"{"v":2,"id":"x","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"x","payload":{}}"#.to_vec(),
                ErrorCode::VersionUnsupported,
                Some(Violation::OutOfRange),
            ),
            (
                "unsupported-schema-version",
                envelope("direwolf.lease.acquire", &format!(r#","session_id":"{sid}""#), "")
                    .replace("\"schema_version\":1", "\"schema_version\":2")
                    .into_bytes(),
                ErrorCode::VersionUnsupported,
                Some(Violation::OutOfRange),
            ),
            (
                "schema-downgrade-v1-refusal",
                format!(
                    r#"{{"v":1,"id":"{}","type":"response","schema":"direwolf.authority.refused","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","causation_id":"{}","payload":{{"operation":"HEARTBEAT","reason":"STALE_EPOCH"}}}}"#,
                    id("msg", 3),
                    id("msg", 4)
                )
                .into_bytes(),
                ErrorCode::VersionUnsupported,
                Some(Violation::OutOfRange),
            ),
            (
                "event-type-message",
                envelope("direwolf.heartbeat", "", "")
                    .replace("\"type\":\"request\"", "\"type\":\"event\"")
                    .into_bytes(),
                ErrorCode::SchemaViolation,
                None,
            ),
        ];
        for (case, body, code, violation) in cases {
            let mut client = connected(&fx);
            client.body(&body).unwrap();
            let (got, got_violation, path) = protocol_error(&mut client);
            if case == "event-type-message" {
                // An event carries an `evt_` id; this one carries `msg_`, and
                // the decoder refuses it before any registry lookup.
                assert!(
                    matches!(
                        got,
                        ErrorCode::SchemaViolation | ErrorCode::UnknownOperation
                    ),
                    "{case}: {got:?} at {path}"
                );
                audit.expect("malformed", Some(got.as_str()));
            } else {
                assert_eq!(got, code, "{case} at {path}");
                if violation.is_some() {
                    assert_eq!(got_violation, violation, "{case}");
                }
                audit.expect("malformed", Some(code.as_str()));
            }
            evidence("hostile", case, "decoder", true, true);
        }
        assert_eq!(
            audit.state_records(),
            before,
            "nothing reached the state layer"
        );
    }

    #[test]
    fn policy_inputs_cannot_be_asserted_on_the_wire() {
        let fx = Fixture::new("h-inject");
        let _server = Server::start(&fx.args(&[]));
        let mut audit = Audit::new(&fx);
        let s = session(2);
        let mut owner = connected(&fx);
        let e = lease(&mut owner, &s).get();
        let before = audit.state_records();

        let lies = [
            ("taint_level", "\"none\""),
            ("origin", "\"USER\""),
            ("privacy_class", "\"ANY\""),
            ("workspace_sensitivity", "\"PUBLIC\""),
            ("active_skills", "[\"house-rules\"]"),
            ("skill_trust", "\"SYSTEM_TRUSTED\""),
            ("standing_grant", "\"fs.write:*\""),
            ("policy_mode", "\"POWER\""),
            ("subject", "\"uid:0\""),
            ("uid", "0"),
            ("lease_holder", "\"1:1\""),
        ];
        for (field, value) in lies {
            for placement in ["envelope", "payload"] {
                let member = format!(r#","{field}":{value}"#);
                let text = if placement == "envelope" {
                    admit_json(&s, e, "inject-key", &member, "")
                } else {
                    admit_json(&s, e, "inject-key", "", &member)
                };
                let mut client = connected(&fx);
                client.body(text.as_bytes()).unwrap();
                let (code, violation, path) = protocol_error(&mut client);
                assert_eq!(
                    code,
                    ErrorCode::SchemaViolation,
                    "{field} in the {placement}"
                );
                assert_eq!(violation, Some(Violation::UnknownField), "{field}");
                assert!(path.ends_with(field), "{path}");
                audit.expect("malformed", Some("PROTOCOL_SCHEMA_VIOLATION"));
                evidence(
                    "hostile",
                    &format!("policy-input-{field}-in-{placement}"),
                    "decoder",
                    true,
                    true,
                );
            }
        }
        // None of the twenty-two reached the state layer: no admission, no
        // refusal, no replay was recorded for them.
        assert_eq!(audit.state_records(), before);
        // And the key was never consumed: the honest request admits afresh.
        let admitted = owner.call(&admit_simple(
            &s,
            Epoch::new(e).unwrap(),
            "inject-key",
            &["model.call:*"],
        ));
        assert!(matches!(admitted.body, DwkpBody::RunGrant(_)));
        assert_eq!(fx.events("run.admitted").len(), 1);
        assert!(fx.events("run.admit_replayed").is_empty());
    }

    #[test]
    fn the_connection_protocol_is_handshake_first_and_once() {
        let fx = Fixture::new("h-order");
        let _server = Server::start(&fx.args(&[]));
        let mut audit = Audit::new(&fx);
        let before = audit.state_records();
        let s = session(3);

        // An authority request before the handshake: closed, unanswered, and
        // never dispatched.
        let mut client = Client::connect(&fx.socket());
        client.send(&acquire_msg(&s));
        closed_unanswered(&mut client);
        audit.expect("handshake_required", None);
        evidence(
            "hostile",
            "non-handshake-first",
            "connection-protocol",
            true,
            true,
        );

        // A second handshake.
        let mut client = connected(&fx);
        client.send(&handshake(1, 1, 2));
        closed_unanswered(&mut client);
        audit.expect("duplicate_handshake", None);
        evidence(
            "hostile",
            "duplicate-handshake",
            "connection-protocol",
            true,
            true,
        );

        // No common version: a typed answer naming the supported range.
        let mut client = Client::connect(&fx.socket());
        client.send(&handshake(2, 9, 3));
        let message = client.recv(PROMPT).message();
        let DwkpBody::ProtocolError(error) = message.body else {
            panic!("a version error")
        };
        assert_eq!(error.code, ErrorCode::VersionUnsupported);
        let supported = error.supported.expect("the supported range");
        assert_eq!((supported.min.get(), supported.max.get()), (1, 1));
        assert!(client.recv(PROMPT).is_closed());
        audit.expect("version_unsupported", Some("PROTOCOL_VERSION_UNSUPPORTED"));
        evidence(
            "hostile",
            "version-downgrade-or-mismatch",
            "connection-protocol",
            true,
            true,
        );

        // The wrong direction: a response sent to the authority.
        let mut client = connected(&fx);
        client
            .body(
                format!(
                    r#"{{"v":1,"id":"{}","type":"response","schema":"direwolf.ack","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","causation_id":"{}","payload":{{}}}}"#,
                    id("msg", 5),
                    id("msg", 6)
                )
                .as_bytes(),
            )
            .unwrap();
        closed_unanswered(&mut client);
        audit.expect("not_a_request", None);
        evidence(
            "hostile",
            "wrong-direction-response",
            "connection-protocol",
            true,
            true,
        );

        // A handshake sent before the first one completes is the first one;
        // one offering nothing at all is refused by the decoder.
        let mut client = Client::connect(&fx.socket());
        client
            .body(
                handshake_json(1, 1, 4)
                    .replace("\"min_version\":1", "\"min_version\":0")
                    .as_bytes(),
            )
            .unwrap();
        let (code, _, _) = protocol_error(&mut client);
        assert_eq!(code, ErrorCode::SchemaViolation);
        audit.expect("malformed", Some("PROTOCOL_SCHEMA_VIOLATION"));

        assert_eq!(audit.state_records(), before, "nothing was dispatched");
        // The session the pre-handshake request named was never touched.
        let mut client = connected(&fx);
        assert_eq!(lease(&mut client, &s).get(), 1);
    }

    #[test]
    fn state_attacks_are_fenced_by_the_state_layer_not_the_transport() {
        let fx = Fixture::new("h-state");
        let _server = Server::start(&fx.args(&[]));
        let s = session(4);
        let mut a = connected(&fx);
        let e1 = lease(&mut a, &s);

        // A stale epoch.
        assert_eq!(
            refusal(&a.call(&heartbeat_msg(&s, epoch(7)))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        evidence("hostile", "stale-epoch", "state-fence", true, true);

        // Replayed and conflicting admissions.
        let admit = admit_simple(&s, e1, "state-key", &["model.call:*"]);
        let first = a.call(&admit);
        let DwkpBody::RunGrant(grant) = &first.body else {
            panic!("admitted")
        };
        let run = grant.run_id.clone();
        for _ in 0..3 {
            let DwkpBody::RunGrant(again) = a.call(&admit).body else {
                panic!("replayed")
            };
            assert_eq!(again.run_id, run, "a replay is the recorded grant");
        }
        evidence("hostile", "replayed-admit-run", "state-fence", true, true);
        let conflicting = admit_simple(&s, e1, "state-key", &["memory.read:*"]);
        assert_eq!(
            refusal(&a.call(&conflicting)),
            (
                RefusedOperation::AdmitRun,
                RefusalReason::IdempotencyConflict
            )
        );
        evidence(
            "hostile",
            "conflicting-admit-run",
            "state-fence",
            true,
            true,
        );

        // A key presented at a stale epoch is fenced before it is looked at.
        let stale_key = admit_simple(&s, epoch(99), "state-key", &["model.call:*"]);
        assert_eq!(
            refusal(&a.call(&stale_key)),
            (RefusedOperation::AdmitRun, RefusalReason::StaleEpoch)
        );
        evidence("hostile", "old-key-stale-epoch", "state-fence", true, true);

        // QueryAuthority cannot be made to decide an action.
        for proposed in [
            "fs.write:/etc/passwd",
            "process.exec:/bin/sh",
            "network.https:evil.example",
        ] {
            assert_eq!(
                refusal(&a.call(&query_msg(&s, &run, e1, Some(proposed)))),
                (
                    RefusedOperation::QueryAuthority,
                    RefusalReason::NoCanonicalAction
                ),
                "{proposed}"
            );
        }
        assert!(
            fx.events("authority.decision").is_empty(),
            "no decision was fabricated"
        );
        evidence(
            "hostile",
            "query-proposal-forces-no-decision",
            "capability-policy",
            true,
            true,
        );

        // Ended admission.
        assert!(matches!(
            a.call(&release_run_msg(&s, &run, e1)).body,
            DwkpBody::Ack(_)
        ));
        assert_eq!(
            refusal(&a.call(&admit)),
            (RefusedOperation::AdmitRun, RefusalReason::AdmissionEnded)
        );
        evidence(
            "hostile",
            "ended-admission-replay",
            "state-fence",
            true,
            true,
        );

        // Ordering abuse: releasing what was never admitted is idempotent;
        // asking about it is UNKNOWN_RUN; renewing without a lease is fenced.
        let never = run_id(424_242);
        assert!(matches!(
            a.call(&release_run_msg(&s, &never, e1)).body,
            DwkpBody::Ack(_)
        ));
        assert_eq!(
            refusal(&a.call(&query_msg(&s, &never, e1, None))),
            (RefusedOperation::QueryAuthority, RefusalReason::UnknownRun)
        );
        let unleased = session(5);
        assert_eq!(
            refusal(&a.call(&heartbeat_msg(&unleased, epoch(1)))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        evidence(
            "hostile",
            "operation-ordering-abuse",
            "state-fence",
            true,
            true,
        );

        // Another connection guessing the session and reusing A's own message
        // ids as its correlation and causation: identifiers are not identity.
        let mut b = connected(&fx);
        let a_id = admit.header.id.as_str().to_owned();
        let borrowed = super::state_support::decode(&format!(
            r#"{{"v":1,"id":"{b_id}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","correlation_id":"{a_id}","causation_id":"{a_id}","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
            b_id = id("msg", 8),
            session = s.as_str(),
            epoch = e1.get(),
        ));
        let answer = b.call(&borrowed);
        assert_eq!(
            refusal(&answer),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        assert_eq!(
            answer.header.causation_id.as_ref().map(|c| c.as_str()),
            Some(borrowed.header.id.as_str()),
            "the answer names B's request, whatever B claimed"
        );
        assert_eq!(
            refusal(&b.call(&acquire_msg(&s))),
            (RefusedOperation::AcquireLease, RefusalReason::LeaseHeld)
        );
        evidence("hostile", "session-guessing", "state-fence", true, true);
        evidence(
            "hostile",
            "correlation-causation-reuse",
            "state-fence",
            true,
            true,
        );
        evidence(
            "hostile",
            "same-uid-inherit-lease",
            "state-fence",
            true,
            true,
        );

        // Every refusal above is on the record.
        assert!(fx.events("lease.refused").len() >= 3);
        assert!(fx.events("run.admit_refused").len() >= 3);
        assert!(fx.events("authority.query_refused").len() >= 4);
        assert_eq!(fx.events("run.admitted").len(), 1);
        assert_eq!(fx.events("run.admit_replayed").len(), 3);
    }

    #[test]
    fn a_clean_disconnect_is_not_a_violation_and_a_reconnect_is_a_stranger() {
        let fx = Fixture::new("h-eof");
        let _server = Server::start(&fx.args(&[]));
        let audit = Audit::new(&fx);
        let s = session(6);
        let mut a = connected(&fx);
        let e = lease(&mut a, &s);
        a.stream().shutdown(Shutdown::Write).unwrap();
        assert!(a.recv(PROMPT).is_closed());
        let mut b = connected(&fx);
        assert_eq!(
            refusal(&b.call(&heartbeat_msg(&s, e))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            fx.events("transport.protocol_violation").len(),
            audit.violations,
            "a clean end of stream is a disconnect, not a violation"
        );
        evidence(
            "hostile",
            "connection-close-reconnect",
            "state-fence",
            true,
            true,
        );
        let _ = a.stream().flush();
    }
}
