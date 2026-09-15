//! DWKP message construction, negotiation and the operation inventory.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::messages::{Handshake, HandshakeAccepted, LeaseGrant, ProtocolErrorPayload};
use dwk_proto::dwkp::registry::{OPERATIONS, WireStatus};
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::envelope::{Header, MessageType};
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
        "direwolf.run.admit",
        "direwolf.run.release",
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
        "direwolf.authority.query",
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
    assert!(
        OPERATIONS
            .iter()
            .filter(|o| o.status == WireStatus::Reserved)
            .count()
            >= 16
    );
}

#[test]
fn no_defined_operation_is_effect_bearing_in_m2() {
    // M2 defines wire contracts, not effects. The first effect-bearing
    // operation arrives with the kernel that can police it.
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
    // ADR-0028: taint, origin, privacy class, workspace sensitivity, skill set
    // and trust, provenance. None of them is a field of any DWKP message this
    // build decodes, at any depth.
    let policy_inputs = [
        "taint",
        "taint_level",
        "origin",
        "privacy_class",
        "sensitivity",
        "skills",
        "skill_trust",
        "trust",
        "provenance",
        "capability",
        "capabilities",
        "approval",
        "approved",
        "grant",
    ];
    let schemas = dwk_proto::schema::emit::all();
    for (path, schema) in &schemas {
        if !path.starts_with("dwkp/") {
            continue;
        }
        let text = dwk_proto::json::to_canonical_string(schema);
        for input in policy_inputs {
            assert!(
                !text.contains(&format!("\"{input}\":")),
                "{path} declares a field named {input}"
            );
        }
    }
}
