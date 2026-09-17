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
        "direwolf.tool.invoke",
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
    // M3 defined three of them (AdmitRun, ReleaseRun, QueryAuthority), so the
    // floor drops by three. It is a floor, not an equality: the point is that
    // reserving remains the normal state of an operation nobody can police yet.
    assert!(
        OPERATIONS
            .iter()
            .filter(|o| o.status == WireStatus::Reserved)
            .count()
            >= 13
    );
}

#[test]
fn tool_invoke_is_still_reserved_after_m3() {
    // The operation that carries every effect stays off the wire until the
    // milestone that owns the first tool. M3 owns the *pipeline* -- admission,
    // capabilities, policy, audit -- and can prove all of it through
    // QueryAuthority, which decides without performing. Defining ToolInvoke
    // first would mean either an opaque argument map, which the second-path
    // rule forbids, or a decision-only form indistinguishable from
    // QueryAuthority. See ADR-0036.
    let tool_invoke = OPERATIONS
        .iter()
        .find(|o| o.name == "ToolInvoke")
        .expect("ToolInvoke is in the inventory");
    assert_eq!(tool_invoke.status, WireStatus::Reserved);
    assert!(tool_invoke.request.is_none());
    assert!(tool_invoke.responses.is_empty());
}

fn refusal(operation: &str, reason: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.refused","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","payload":{{"operation":"{operation}","reason":"{reason}"}}}}"#
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
    assert_eq!(pairs, 9, "the M3 refusal matrix has nine pairs");
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
        .find(|(path, _)| path.ends_with("direwolf.authority.refused.v1.schema.json"))
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
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.effective","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","payload":{{"run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1,"policy_revision":"{rev}","profile":"SAFE","granted":[],"withheld":[],"decision":{{"effect":"DENY","reason":"RUN_NOT_ADMITTED","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"default","rule_source":"policy/balanced.toml:1"}}}}}}"#,
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
fn admit_run_is_the_only_operation_that_carries_an_idempotency_key() {
    // Admission mints authority, so a retry that is not deduplicated mints a
    // second grant. The key is Required rather than Optional because an
    // optional one leaves the kernel two paths and a retry takes the
    // unprotected one (ADR-0036 section 8).
    //
    // Everything else stays Forbidden, and for reasons rather than by default:
    // ReleaseRun is idempotent by shape -- releasing twice is acknowledged
    // twice and resurrects nothing -- and QueryAuthority is pure, so a replay
    // has nothing to duplicate. A key on either would be a field with no
    // meaning, which is a field that can acquire one.
    for spec in MESSAGES {
        let expected = if spec.schema == "direwolf.run.admit" {
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
            r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.authority.effective","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G0E87TVJX9GX248ADD","payload":{{"run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1,"policy_revision":"{rev}","profile":"SAFE","granted":[],"withheld":[],"decision":{{"effect":"{effect}","reason":"{reason}","capability_result":"SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"approve-external-write","rule_source":"policy/balanced.toml:111"}}}}}}"#,
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
            .find(|(path, _)| path.ends_with("direwolf.authority.effective.v1.schema.json"))
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
fn no_defined_operation_is_effect_bearing_yet() {
    // M2 defined wire contracts and no effects. M3 adds authority decisions and
    // still no effects: admitting a run, releasing it and asking what it may do
    // change kernel records only. The first effect-bearing operation on the
    // wire arrives with the broker that performs it and the canonicaliser that
    // makes its arguments decidable.
    for op in OPERATIONS
        .iter()
        .filter(|o| o.status == WireStatus::Defined)
    {
        assert!(
            !op.effect_bearing,
            "{} is defined and effect-bearing",
            op.name
        );
    }
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
        checked_requests >= 6,
        "expected to have checked every defined request, saw {checked_requests}"
    );
}
