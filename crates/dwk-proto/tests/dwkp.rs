//! DWKP message construction, negotiation and the operation inventory.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::messages::REFUSALS;
use dwk_proto::dwkp::messages::{Handshake, HandshakeAccepted, LeaseGrant, ProtocolErrorPayload};
use dwk_proto::dwkp::registry::{MESSAGES, OPERATIONS, WireStatus};
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::envelope::{Header, MessageType, Presence};
use dwk_proto::version::{SUPPORTED_ENVELOPE, VersionRange, negotiate};
use dwk_proto::wire::id::{AnyId, SessionId};
use dwk_proto::wire::scalar::{Epoch, SchemaName, Timestamp, Version};
use dwk_proto::{ErrorCode, ProtocolError, Violation, frame};

fn header(message_type: MessageType, schema: &str) -> Header {
    Header {
        v: Version::new(1).unwrap(),
        id: AnyId::parse("msg_01M24BB8G0E87TVJX9GX248ADD").unwrap(),
        message_type,
        schema: SchemaName::new(schema).unwrap(),
        schema_version: Version::new(1).unwrap(),
        ts: Timestamp::new("2026-09-12T09:14:22.481Z").unwrap(),
        correlation_id: None,
        causation_id: None,
        session_id: None,
        run_id: None,
        epoch: None,
        idempotency_key: None,
    }
}

fn session() -> SessionId {
    SessionId::parse("ses_01M24BB8G2E87V1ZPZXQ7DSCVW").unwrap()
}

#[test]
fn a_constructed_message_frames_and_decodes_back_to_itself() {
    let mut h = header(MessageType::Response, "direwolf.lease.grant");
    h.causation_id = AnyId::parse("msg_01M24BB8G1FQR94D2PF2XVQDV4");
    let message = DwkpMessage {
        header: h,
        body: DwkpBody::LeaseGrant(LeaseGrant {
            session_id: session(),
            epoch: Epoch::new(48).unwrap(),
        }),
    };
    let bytes = message.to_frame().unwrap();
    let frames = frame::decode_all(&bytes).unwrap();
    assert_eq!(dwkp::decode_frame(&frames[0]).unwrap(), message);
}

#[test]
fn the_encoder_refuses_to_emit_what_the_decoder_would_reject() {
    // A heartbeat without the session and epoch its rules require.
    let message = DwkpMessage {
        header: header(MessageType::Request, "direwolf.heartbeat"),
        body: DwkpBody::Heartbeat(dwk_proto::dwkp::messages::HeartbeatPayload {}),
    };
    let err = message.to_frame().unwrap_err();
    assert_eq!(err.violation, Some(Violation::MissingField));

    // A body that does not match the header's schema.
    let mismatched = DwkpMessage {
        header: header(MessageType::Request, "direwolf.lease.acquire"),
        body: DwkpBody::Heartbeat(dwk_proto::dwkp::messages::HeartbeatPayload {}),
    };
    assert_eq!(
        mismatched.to_frame().unwrap_err().violation,
        Some(Violation::Inconsistent)
    );
}

#[test]
fn a_handshake_negotiates_the_highest_mutual_version_and_nothing_else() {
    let offer = Handshake {
        min_version: Version::new(1).unwrap(),
        max_version: Version::new(9).unwrap(),
    };
    let offered = VersionRange::new(offer.min_version.get(), offer.max_version.get()).unwrap();
    let chosen = negotiate(offered, SUPPORTED_ENVELOPE, 1).unwrap();
    assert_eq!(chosen, 1);
    let mut h = header(MessageType::Response, "direwolf.handshake.accepted");
    h.causation_id = AnyId::parse("msg_01M24BB8G1FQR94D2PF2XVQDV4");
    let accepted = DwkpMessage {
        header: h,
        body: DwkpBody::HandshakeAccepted(HandshakeAccepted {
            version: Version::new(chosen).unwrap(),
        }),
    };
    assert!(accepted.to_frame().is_ok());
}

#[test]
fn an_unsatisfiable_handshake_produces_an_actionable_protocol_error() {
    let err = negotiate(VersionRange::new(4, 6).unwrap(), SUPPORTED_ENVELOPE, 1).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionUnsupported);
    let payload = ProtocolErrorPayload::from(&err);
    let supported = payload
        .supported
        .clone()
        .expect("the supported range travels with the error");
    assert_eq!((supported.min.get(), supported.max.get()), (1, 1));
    let message = DwkpMessage {
        header: header(MessageType::Response, "direwolf.protocol.error"),
        body: DwkpBody::ProtocolError(payload),
    };
    assert!(
        message.to_frame().is_ok(),
        "a protocol error needs no causation: it may answer bytes that were never a request"
    );
}

#[test]
fn every_decode_failure_can_be_reported_on_the_wire() {
    // Whatever went wrong, the error must itself be a valid message, with the
    // detail and path bounded — a malformed error response would leave the peer
    // with nothing actionable.
    let long_detail = "x".repeat(10_000);
    let long_path = format!("/{}", "k".repeat(10_000));
    for code in ErrorCode::ALL {
        let err = ProtocolError::new(code, long_detail.clone())
            .with_path(&long_path)
            .with_violation(Violation::TooLong);
        let message = DwkpMessage {
            header: header(MessageType::Response, "direwolf.protocol.error"),
            body: DwkpBody::ProtocolError(ProtocolErrorPayload::from(&err)),
        };
        assert!(message.to_frame().is_ok(), "{code:?}");
    }
}

#[test]
fn every_reserved_operation_is_rejected_on_the_wire() {
    // A reserved operation is not a half-implemented one. Whatever schema name
    // its owning milestone picks, today it decodes as UNKNOWN_OPERATION.
    let candidates = [
        "direwolf.tool.cancel",
        "direwolf.model.call",
        "direwolf.canonical.preview",
        "direwolf.tools.list_visible",
        "direwolf.subagent.spawn",
        "direwolf.artifact.create",
        "direwolf.artifact.read",
        "direwolf.mcp.open",
        "direwolf.mcp.close",
        "direwolf.channel.send",
        "direwolf.budget.query",
        "direwolf.invocation.status",
    ];
    for schema in candidates {
        let doc = format!(
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"{schema}","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","payload":{{}}}}"#
        );
        assert_eq!(
            dwkp::decode_body(doc.as_bytes()).unwrap_err().code,
            ErrorCode::UnknownOperation,
            "{schema}"
        );
    }
    // M3 defined three of them (AdmitRun, ReleaseRun, QueryAuthority) and M4b
    // two more (ToolInvoke, CanonicalPreview), so the floor drops by five. It
    // is a floor, not an equality: the point is that reserving remains the
    // normal state of an operation nobody can police yet.
    assert!(
        OPERATIONS
            .iter()
            .filter(|o| o.status == WireStatus::Reserved)
            .count()
            >= 11
    );
}

#[test]
fn tool_invoke_is_defined_with_exactly_one_tool_and_no_opaque_arguments() {
    // M4b gives ToolInvoke its first wire form together with the first tool
    // (ADR-0043), which is what ADR-0036 waited for: a request whose every
    // argument the authority can canonicalise. It is not a name plus an
    // argument map -- the only member is `fs_read`, a typed call -- so another
    // tool is an undeclared member and a protocol error, never a dispatch.
    let tool_invoke = OPERATIONS
        .iter()
        .find(|o| o.name == "ToolInvoke")
        .expect("ToolInvoke is in the inventory");
    assert_eq!(tool_invoke.status, WireStatus::Defined);
    assert_eq!(tool_invoke.request, Some("direwolf.tool.invoke"));
    assert!(tool_invoke.effect_bearing && tool_invoke.authority_bearing);
    let invoke = |payload: &str| {
        format!(
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"direwolf.tool.invoke","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","session_id":"ses_01M24BB8G1FQR94D2PF2XVQDV4","run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":3,"payload":{payload}}}"#
        )
    };
    let good = invoke(r#"{"fs_read":{"path":"/workspace/src/main.rs","max_bytes":4096}}"#);
    assert!(matches!(
        dwkp::decode_body(good.as_bytes())
            .expect("fs.read decodes")
            .body,
        DwkpBody::ToolInvoke(_)
    ));
    for bad in [
        // Another tool: an undeclared member.
        r#"{"fs_write":{"path":"/workspace/a","max_bytes":1}}"#,
        // A name-plus-arguments shape.
        r#"{"tool":"fs.read","args":{"path":"/workspace/a"}}"#,
        // A capability or grant asserted by the runtime.
        r#"{"fs_read":{"path":"/workspace/a","max_bytes":1},"cap_id":"cap_01M24BB8G3E0A851TRWE3M8FZF"}"#,
        r#"{"fs_read":{"path":"/workspace/a","max_bytes":1,"environment":"HOST"}}"#,
        // An unbounded or out-of-range read.
        r#"{"fs_read":{"path":"/workspace/a"}}"#,
        r#"{"fs_read":{"path":"/workspace/a","max_bytes":0}}"#,
        r#"{"fs_read":{"path":"/workspace/a","max_bytes":262145}}"#,
        // A relative path.
        r#"{"fs_read":{"path":"workspace/a","max_bytes":1}}"#,
    ] {
        assert!(
            dwkp::decode_body(invoke(bad).as_bytes()).is_err(),
            "{bad} decoded"
        );
    }
}

#[test]
fn the_largest_tool_result_every_field_allows_fits_one_frame() {
    // The bound on `fs.read` is derived from the frame (limits.rs); this is
    // the proof. Every field at its worst: a canonical path of 384
    // characters that each canonicalise to the most bytes (a control
    // character escapes to six), a rule id and source at their maxima, and
    // the content at MAX_FS_READ_BYTES.
    let path = format!("/{}", "\\u0001".repeat(383));
    let rule_id = format!("a{}", "-".repeat(63));
    let rule_source = format!("{}:{}", "a".repeat(240), "9".repeat(8));
    let result = |content: &str| {
        format!(
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.tool.result","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","correlation_id":"run_01M24BB8G3E0A851TRWE3M8FZF","payload":{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","action":{{"tool":"fs.read","canonical_path":"{path}","byte_count":262144,"environment":"SANDBOX"}},"decision":{{"effect":"DENY","reason":"UNRESOLVED_POLICY_INPUT","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"{rule_id}","rule_source":"{rule_source}"}},"fs_read":{{"content":"{content}","eof_observed":false}}}}}}"#
        )
    };
    let largest = result(&"ff".repeat(dwk_proto::limits::MAX_FS_READ_BYTES));
    let message = dwkp::decode_body(largest.as_bytes()).expect("the largest result decodes");
    let frame = message.to_frame().expect("and frames");
    assert!(frame.len() <= frame::HEADER_LEN + dwk_proto::limits::MAX_FRAME_BODY);
    let overhead = frame.len() - frame::HEADER_LEN - 2 * dwk_proto::limits::MAX_FS_READ_BYTES;
    assert!(
        overhead < 8 * 1024,
        "everything but the content is {overhead} bytes"
    );
    // One byte more is not a result at all.
    let over = result(&"ff".repeat(dwk_proto::limits::MAX_FS_READ_BYTES + 1));
    let refused = dwkp::decode_body(over.as_bytes()).expect_err("above the bound");
    assert_eq!(refused.violation, Some(Violation::TooLong));
}

fn refusal(operation: &str, reason: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.refused","schema_version":2,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","payload":{{"operation":"{operation}","reason":"{reason}"}}}}"#
    )
}

#[test]
fn an_authority_refusal_is_not_a_protocol_error() {
    // Three answers, three remedies, and a caller has to be able to tell them
    // apart: fix the message, re-acquire the lease, or ask for less. A refusal
    // travelling as a protocol error would claim nothing well-formed arrived,
    // which is false and sends the caller to repair a message that was correct.
    let refused = dwkp::decode_body(refusal("ADMIT_RUN", "STALE_EPOCH").as_bytes())
        .expect("a well-formed refusal decodes");
    assert_eq!(refused.header.schema.as_str(), "direwolf.authority.refused");
    assert!(matches!(refused.body, DwkpBody::AuthorityRefused(_)));

    // And the two are different schemas, so no decoder path can confuse them.
    let error = dwkp::decode_body(
        br#"{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.protocol.error","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","payload":{"code":"PROTOCOL_SCHEMA_VIOLATION","detail":"x"}}"#,
    )
    .expect("a protocol error decodes");
    assert!(matches!(error.body, DwkpBody::ProtocolError(_)));
}

#[test]
fn a_refusal_reason_its_operation_cannot_produce_is_refused() {
    // The pairing is closed, not just each enum. A kernel that answers
    // ReleaseLease with IDEMPOTENCY_CONFLICT has a bug, and the wire is where
    // it stops -- not three components later, where the reason gets believed.
    for (operation, reason) in [
        ("RELEASE_LEASE", "IDEMPOTENCY_CONFLICT"),
        ("ACQUIRE_LEASE", "STALE_EPOCH"),
        ("RELEASE_RUN", "UNKNOWN_RUN"),
        ("HEARTBEAT", "UNKNOWN_AGENT_PROFILE"),
        ("QUERY_AUTHORITY", "LEASE_HELD"),
        // ADR-0040's two reasons are as closed as the rest: an ended admission
        // is only ever an AdmitRun answer, and an undecidable proposal only a
        // QueryAuthority one.
        ("RELEASE_RUN", "ADMISSION_ENDED"),
        ("QUERY_AUTHORITY", "ADMISSION_ENDED"),
        ("ADMIT_RUN", "NO_CANONICAL_ACTION"),
        ("HEARTBEAT", "NO_CANONICAL_ACTION"),
    ] {
        let err = dwkp::decode_body(refusal(operation, reason).as_bytes()).unwrap_err();
        assert_eq!(err.code, ErrorCode::SchemaViolation, "{operation}/{reason}");
        assert_eq!(
            err.violation,
            Some(Violation::Inconsistent),
            "{operation}/{reason}"
        );
        assert_eq!(err.path, "/payload/reason", "{operation}/{reason}");
    }
}

#[test]
fn every_pair_the_table_permits_decodes() {
    // The negative test above is only meaningful if the positive side is
    // complete: every pair the kernel is allowed to send must survive the wire.
    let mut pairs = 0;
    for (operation, reasons) in REFUSALS {
        for reason in *reasons {
            assert!(
                dwkp::decode_body(refusal(operation, reason).as_bytes()).is_ok(),
                "{operation}/{reason}"
            );
            pairs += 1;
        }
    }
    assert_eq!(
        pairs, 11,
        "the M3 refusal matrix has eleven pairs (ADR-0040)"
    );
}

#[test]
fn the_refusal_carries_nothing_but_the_operation_and_the_reason() {
    // A refusal tells a caller about state it cannot otherwise see, so every
    // extra field is an oracle. STALE_EPOCH in particular must not carry the
    // kernel's current epoch: that is the one value a fenced runtime needs to
    // un-fence itself.
    let with_epoch = refusal("ADMIT_RUN", "STALE_EPOCH").replace(
        r#""reason":"STALE_EPOCH""#,
        r#""reason":"STALE_EPOCH","current_epoch":48"#,
    );
    let err = dwkp::decode_body(with_epoch.as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::UnknownField));
    assert_eq!(err.path, "/payload/current_epoch");

    let schemas = dwk_proto::schema::emit::all();
    let (_, schema) = schemas
        .iter()
        .find(|(path, _)| path.ends_with("direwolf.authority.refused.v2.schema.json"))
        .expect("the refusal schema is emitted");
    let text = dwk_proto::json::to_canonical_string(schema);
    assert!(text.contains(r#""required":["operation","reason"]"#));
    assert!(text.contains(r#""additionalProperties":false"#));
    for absent in ["detail", "message", "hint", "metadata", "current_epoch"] {
        assert!(
            !text.contains(&format!("\"{absent}\":")),
            "the refusal schema declares {absent}"
        );
    }
}

#[test]
fn a_run_that_holds_no_admission_is_a_refusal_and_not_a_denial() {
    // RUN_NOT_ADMITTED used to be a DecisionReason, which claimed an evaluation
    // that cannot have happened: with no admission there is no grant, no
    // profile and no policy revision, so EffectiveAuthority cannot be filled
    // in at all. It is a refusal now, and the decision enum must not take it
    // back.
    let decision = format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.effective","schema_version":2,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","payload":{{"run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1,"policy_revision":"{rev}","profile":"SAFE","granted":[],"withheld":[],"decision":{{"effect":"DENY","reason":"RUN_NOT_ADMITTED","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"default","rule_source":"policy/balanced.toml:1","required_capability":"model.call:*"}}}}}}"#,
        rev = "9f".repeat(32)
    );
    let err = dwkp::decode_body(decision.as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::UnknownVariant));
    assert_eq!(err.path, "/payload/decision/reason");

    assert!(dwkp::decode_body(refusal("QUERY_AUTHORITY", "UNKNOWN_RUN").as_bytes()).is_ok());
}

#[test]
fn every_operation_that_can_be_refused_lists_the_refusal_as_a_response() {
    // The inventory is what a reader consults to know what an operation can
    // answer with. An operation whose kernel can refuse it but whose inventory
    // does not say so is a documented protocol that does not match the wire.
    let refusable: Vec<&str> = REFUSALS.iter().map(|(op, _)| *op).collect();
    for op in OPERATIONS
        .iter()
        .filter(|o| o.status == WireStatus::Defined)
    {
        // OperationSpec names are CamelCase; the wire enum is SCREAMING_SNAKE.
        let screaming: String = op
            .name
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let mut out = Vec::new();
                if c.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_uppercase());
                out
            })
            .collect();
        let can_be_refused = refusable.contains(&screaming.as_str());
        assert_eq!(
            op.responses.contains(&"direwolf.authority.refused"),
            can_be_refused,
            "{} lists the refusal response but the matrix disagrees",
            op.name
        );
    }
}

#[test]
fn only_admission_and_a_version_two_or_three_invocation_carry_an_idempotency_key() {
    // Admission mints authority, so a retry that is not deduplicated mints a
    // second grant. The key is Required rather than Optional because an
    // optional one leaves the kernel two paths and a retry takes the
    // unprotected one (ADR-0036 section 8).
    //
    // A version-2 ToolInvoke carries one for the same reason (ADR-0044):
    // fs.move and fs.delete are not retry-safe, so a key names one invocation,
    // is never performed twice, and is what a lost response is later asked
    // about by. Version 1 carries fs.read only, which is retry-safe, and keeps
    // M4b's rule exactly.
    //
    // Everything else stays Forbidden, and for reasons rather than by default:
    // ReleaseRun is idempotent by shape -- releasing twice is acknowledged
    // twice and resurrects nothing -- QueryAuthority and CanonicalPreview are
    // pure, so a replay has nothing to duplicate. A key on any of them would
    // be a field with no meaning, which is a field that can acquire one.
    for spec in MESSAGES {
        // Version 3 (ADR-0045) keeps version 2's rule: process.exec and
        // process.kill are not retry-safe either.
        let keyed = spec.schema == "direwolf.run.admit"
            || (spec.schema == "direwolf.tool.invoke" && spec.versions.min >= 2);
        let expected = if keyed {
            Presence::Required
        } else {
            Presence::Forbidden
        };
        assert_eq!(
            spec.rules.idempotency_key, expected,
            "{} idempotency_key presence",
            spec.schema
        );
    }
}

#[test]
fn an_admission_without_its_idempotency_key_is_refused_by_location() {
    // A missing key must be a refusal a caller can act on, not a silent
    // fallback to the unprotected path.
    let without = r#"{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","session_id":"ses_01M24BB8G2E87V1ZPZXQ7DSCVW","epoch":1,"payload":{"agent_profile":"researcher","skills":[],"requested_capabilities":[]}}"#;
    let err = dwkp::decode_body(without.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
    assert_eq!(err.violation, Some(Violation::MissingField));
    assert_eq!(err.path, "/idempotency_key");

    // And the same message with one decodes.
    let with = without.replace(
        r#""payload":"#,
        r#""idempotency_key":"admit-01M24BB8G0","payload":"#,
    );
    assert!(dwkp::decode_body(with.as_bytes()).is_ok());
}

#[test]
fn the_authority_decision_has_no_approval_effect_before_approvals_exist() {
    // ADR-0006 makes policy's own function three-valued and M3c will honour
    // that; what crosses the wire is what the authority *decided*, and an
    // authority with no approval registry refuses. Shipping the third value
    // early would invite `effect != DENY` as a proceed condition -- a
    // fail-open written in good faith. M6 adds it with a schema_version bump
    // (ADR-0036 section 9).
    let decision = |effect: &str, reason: &str| {
        format!(
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.effective","schema_version":2,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G0E87TVJX9GX248ADD","payload":{{"run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1,"policy_revision":"{rev}","profile":"SAFE","granted":[],"withheld":[],"decision":{{"effect":"{effect}","reason":"{reason}","capability_result":"SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"approve-external-write","rule_source":"policy/balanced.toml:111","required_capability":"network.https:example.com"}}}}}}"#,
            rev = "9f".repeat(32)
        )
    };
    assert!(dwkp::decode_body(decision("DENY", "DENIED_BY_RULE").as_bytes()).is_ok());
    for (effect, reason, path) in [
        (
            "REQUIRE_APPROVAL",
            "DENIED_BY_RULE",
            "/payload/decision/effect",
        ),
        ("DENY", "APPROVAL_REQUIRED", "/payload/decision/reason"),
    ] {
        let err = dwkp::decode_body(decision(effect, reason).as_bytes()).unwrap_err();
        assert_eq!(
            err.violation,
            Some(Violation::UnknownVariant),
            "{effect}/{reason}"
        );
        assert_eq!(err.path, path);
    }

    // The schema must not merely reject the value -- it must not advertise it,
    // or a client will generate a branch for it.
    let text = dwk_proto::json::to_canonical_string(
        &dwk_proto::schema::emit::all()
            .into_iter()
            .find(|(path, _)| path.ends_with("direwolf.authority.effective.v2.schema.json"))
            .map(|(_, schema)| schema)
            .expect("the effective-authority schema is emitted"),
    );
    for absent in ["REQUIRE_APPROVAL", "APPROVAL_REQUIRED"] {
        assert!(
            !text.contains(absent),
            "the decision schema still advertises {absent}"
        );
    }
}

#[test]
fn a_decision_names_a_capability_and_never_a_malformed_one() {
    // ADR-0040: CAPABILITY_MALFORMED was attributed to the policy's `default`
    // rule because the wire required a rule, and no rule had run. A proposal
    // outside the vocabulary is now a refusal, so the decision enum must not
    // take the value back, and a decision is only ever about a canonical
    // action, so it always names the capability it required.
    let decision = |reason: &str, required: &str| {
        format!(
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.effective","schema_version":2,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G0E87TVJX9GX248ADD","payload":{{"run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1,"policy_revision":"{rev}","profile":"SAFE","granted":[],"withheld":[],"decision":{{"effect":"DENY","reason":"{reason}","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"default","rule_source":"policy/balanced.toml:1"{required}}}}}}}"#,
            rev = "9f".repeat(32)
        )
    };
    let with_capability = r#","required_capability":"model.call:*""#;
    assert!(dwkp::decode_body(decision("DEFAULT_DENY", with_capability).as_bytes()).is_ok());

    let err = dwkp::decode_body(decision("CAPABILITY_MALFORMED", with_capability).as_bytes())
        .unwrap_err();
    assert_eq!(err.violation, Some(Violation::UnknownVariant));
    assert_eq!(err.path, "/payload/decision/reason");

    let err = dwkp::decode_body(decision("DEFAULT_DENY", "").as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::MissingField));
    assert_eq!(err.path, "/payload/decision/required_capability");

    assert!(
        dwkp::decode_body(refusal("QUERY_AUTHORITY", "NO_CANONICAL_ACTION").as_bytes()).is_ok()
    );
}

#[test]
fn the_three_changed_responses_are_version_two_only() {
    // ADR-0040 changed three response payloads incompatibly. DWKP's peers ship
    // together (ADR-0023), so each supports exactly its new version: a
    // version-1 instance is refused as unsupported, naming the range, rather
    // than decoded under rules it predates.
    for schema in [
        "direwolf.run.grant",
        "direwolf.authority.effective",
        "direwolf.authority.refused",
    ] {
        let spec = MESSAGES
            .iter()
            .find(|m| m.schema == schema)
            .expect("the message is registered");
        assert_eq!((spec.versions.min, spec.versions.max), (2, 2), "{schema}");
    }
    let v1 = refusal("ADMIT_RUN", "STALE_EPOCH")
        .replace(r#""schema_version":2"#, r#""schema_version":1"#);
    let err = dwkp::decode_body(v1.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionUnsupported);
    assert_eq!(err.path, "/schema_version");

    let emitted: Vec<String> = dwk_proto::schema::emit::all()
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    for schema in [
        "direwolf.run.grant",
        "direwolf.authority.effective",
        "direwolf.authority.refused",
    ] {
        assert!(
            emitted.contains(&format!("dwkp/{schema}.v2.schema.json")),
            "{schema}"
        );
        assert!(
            !emitted.contains(&format!("dwkp/{schema}.v1.schema.json")),
            "{schema}"
        );
    }
    // The requests did not change shape, and stay at version 1.
    for schema in ["direwolf.run.admit", "direwolf.authority.query"] {
        assert!(
            emitted.contains(&format!("dwkp/{schema}.v1.schema.json")),
            "{schema}"
        );
    }
}

#[test]
fn tool_invoke_is_the_only_defined_effect_bearing_operation() {
    // M2 defined wire contracts and no effects; M3 added authority decisions
    // and still no effects. M4b adds exactly one effect-bearing operation --
    // ToolInvoke, with the broker that performs it and the canonicaliser that
    // makes its arguments decidable. CanonicalPreview, defined alongside it,
    // performs nothing.
    let effect_bearing: Vec<&str> = OPERATIONS
        .iter()
        .filter(|o| o.status == WireStatus::Defined && o.effect_bearing)
        .map(|o| o.name)
        .collect();
    assert_eq!(effect_bearing, ["ToolInvoke"]);
}

#[test]
fn the_runtime_cannot_express_a_policy_input_in_any_defined_message() {
    // ADR-0028: every policy input is derived and stored kernel-side. The rule
    // is about *assertion*, not about vocabulary -- the runtime may say which
    // agent profile and skills it wants and which capabilities it would like,
    // because the kernel resolves every one of those names against its own
    // records and intersects the result. What it may never do is state a
    // property the kernel derives: how tainted its context is, where content
    // came from, how sensitive a workspace is, whether a skill is trusted, or
    // that something was approved.
    //
    // So this checks two different things:
    //
    //   * the derived properties appear in no message at all, in either
    //     direction, at any depth;
    //   * the authority vocabulary -- capabilities, grants, profiles, policy
    //     revisions -- appears only in kernel-to-runtime *responses*, plus the
    //     three request fields the architecture sanctions by name.
    //
    // A new request field that is not on the sanctioned list fails here, which
    // is the point: adding one has to be a deliberate, reviewed act.
    let never_anywhere = [
        "taint",
        "taint_level",
        "origin",
        "privacy_class",
        "sensitivity",
        "skill_trust",
        "trust",
        "provenance",
        "approval",
        "approved",
        "binding",
        "budget",
    ];
    let authority_vocabulary = [
        "capability",
        "capabilities",
        "granted",
        "withheld",
        "grant",
        "cap_id",
        "policy_revision",
        "profile",
        "decision",
        "effect",
        "rule_id",
        "rule_source",
        // M4b: facts of a canonical action the authority states, never a
        // request (ADR-0043).
        "environment",
        "byte_count",
        "canonical_path",
        "invocation_id",
        "tool",
    ];
    // The only request fields permitted to name authority vocabulary, each
    // sanctioned by DWKP_OPERATIONS.md and ADR-0036.
    let sanctioned_request_fields = [
        "agent_profile",          // which profile to admit under; kernel resolves it
        "skills",                 // which skills to activate; skills only narrow
        "requested_capabilities", // a request, not an assertion: ask more, get less
        "proposed",               // an action to decide, not to perform
    ];

    let schemas = dwk_proto::schema::emit::all();
    let mut checked_requests = 0;
    for (path, schema) in &schemas {
        if !path.starts_with("dwkp/") || path.ends_with("operations.json") {
            continue;
        }
        let text = dwk_proto::json::to_canonical_string(schema);
        for input in never_anywhere {
            assert!(
                !text.contains(&format!("\"{input}\":")),
                "{path} declares a field named {input}"
            );
        }
        let is_request = text.contains("\"x-direwolf-message-type\":\"request\"");
        if !is_request {
            continue;
        }
        checked_requests += 1;
        for word in authority_vocabulary {
            if sanctioned_request_fields.contains(&word) {
                continue;
            }
            assert!(
                !text.contains(&format!("\"{word}\":")),
                "{path} is a request and declares an authority field named {word}"
            );
        }
    }
    assert!(
        checked_requests >= 8,
        "expected to have checked every defined request, saw {checked_requests}"
    );
}
