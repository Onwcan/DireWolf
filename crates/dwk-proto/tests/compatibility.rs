//! The three compatibility rules of ADR-0023, as three separate tests — not one
//! blanket assertion — plus the guarantees that make "preserve" mean something.
//!
//! | family    | unknown field | unknown message          |
//! |-----------|---------------|--------------------------|
//! | DWKP      | REJECT        | REJECT                   |
//! | DWCP      | PRESERVE      | retained, logged, skipped |
//! | event log | RETAIN BYTES  | RETAIN BYTES             |

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwcp::{self, DwcpBody};
use dwk_proto::events::{EventRecord, EventView};
use dwk_proto::json::{self, ParseOptions, Value};
use dwk_proto::{ErrorCode, Violation, dwkp};

const MSG: &str = "msg_01M24BB8G0E87TVJX9GX248ADD";
const CAUSE: &str = "msg_01M24BB8G1FQR94D2PF2XVQDV4";
const SES: &str = "ses_01M24BB8G2E87V1ZPZXQ7DSCVW";
const EVT: &str = "evt_01M24BB8G4EKX8P1DMZ95GB82V";
const TS: &str = "2026-09-12T09:14:22.481Z";

/// The same extension, spelled identically, offered to each family.
const EXTENSION: &str = r#""x_future":{"retry_after_ms":1500,"ratio":0.25}"#;

#[test]
fn dwkp_rejects_the_unknown_field() {
    let doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"request","schema":"direwolf.heartbeat","schema_version":1,
            "ts":"{TS}","session_id":"{SES}","epoch":47,"payload":{{{EXTENSION}}}}}"#
    );
    // DWKP's number domain would reject 0.25 first; strip it so the test
    // isolates the unknown-field rule.
    let doc = doc.replace(",\"ratio\":0.25", "");
    let err = dwkp::decode_body(doc.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
    assert_eq!(err.violation, Some(Violation::UnknownField));
    assert_eq!(err.path, "/payload/x_future");
}

#[test]
fn dwcp_preserves_the_unknown_field_and_re_emits_it() {
    let doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"response","schema":"direwolf.error","schema_version":1,
            "ts":"{TS}","x_envelope_future":[1,2],
            "payload":{{"code":"RATE_LIMITED","detail":"slow down","retryable":true,{EXTENSION}}}}}"#
    );
    let message = dwcp::decode(doc.as_bytes()).unwrap();
    let DwcpBody::Error(error) = &message.body else {
        panic!("expected a known error message")
    };
    // Known fields validated and typed.
    assert_eq!(error.code.as_str(), "RATE_LIMITED");
    assert!(error.retryable);
    // Unknown fields kept, in the payload and in the envelope.
    assert!(error.extensions.get("x_future").is_some());
    assert!(message.header_extensions.get("x_envelope_future").is_some());

    // Re-emission loses nothing: the re-encoded message has the same value as
    // the input, member for member.
    let original = json::parse(doc.as_bytes(), ParseOptions::ijson()).unwrap();
    let reemitted = json::parse(
        &message.to_canonical_bytes().unwrap(),
        ParseOptions::ijson(),
    )
    .unwrap();
    assert_eq!(
        json::to_canonical_bytes(&original),
        json::to_canonical_bytes(&reemitted)
    );
}

#[test]
fn event_log_retains_the_unknown_field_as_the_original_bytes() {
    // Deliberately irregular formatting: canonical re-emission would change
    // these bytes. Verbatim retention must not.
    let doc = format!(
        "{{ \"v\":1, \"id\":\"{EVT}\", \"type\":\"event\",\n  \"schema\":\"direwolf.session.lease_acquired\",\
         \"schema_version\":1,\"ts\":\"{TS}\",\"session_id\":\"{SES}\",\n  \"payload\":{{\"epoch\":48,{EXTENSION}}} }}\n"
    );
    let record = EventRecord::read(doc.as_bytes()).unwrap();
    assert_eq!(record.raw(), doc.as_bytes());
    let EventView::Known { event, .. } = record.view() else {
        panic!("expected a known event")
    };
    let dwk_proto::events::KnownEvent::LeaseAcquired(acquired) = event;
    assert_eq!(acquired.epoch.get(), 48);
    assert!(acquired.extensions.get("x_future").is_some());
}

#[test]
fn dwkp_rejects_an_unknown_operation() {
    let doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"request","schema":"direwolf.session.created","schema_version":1,"ts":"{TS}","payload":{{}}}}"#
    );
    assert_eq!(
        dwkp::decode_body(doc.as_bytes()).unwrap_err().code,
        ErrorCode::UnknownOperation
    );
}

#[test]
fn dwcp_retains_an_unknown_message_for_logging_and_skipping() {
    let doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"request","schema":"direwolf.session.created","schema_version":1,"ts":"{TS}","payload":{{"title":"t","n":1.5}}}}"#
    );
    let message = dwcp::decode(doc.as_bytes()).unwrap();
    let DwcpBody::Unknown { payload } = &message.body else {
        panic!("expected Unknown")
    };
    assert_eq!(payload.get("title"), Some(&Value::String("t".to_owned())));
    let original = json::parse(doc.as_bytes(), ParseOptions::ijson()).unwrap();
    assert_eq!(
        message.to_canonical_bytes().unwrap(),
        json::to_canonical_bytes(&original)
    );
}

#[test]
fn event_log_retains_an_unknown_event_and_its_bytes() {
    let doc = format!(
        "{{\"v\":1,\"id\":\"{EVT}\",\"type\":\"event\",\"schema\":\"direwolf.memory.promoted\",\"schema_version\":4,\"ts\":\"{TS}\",\"payload\":{{\"why\":\"because\"}}}}"
    );
    let record = EventRecord::read(doc.as_bytes()).unwrap();
    assert_eq!(record.raw(), doc.as_bytes());
    let EventView::Unknown {
        schema,
        schema_version,
        ..
    } = record.view()
    else {
        panic!("expected Unknown")
    };
    assert_eq!(schema.as_deref(), Some("direwolf.memory.promoted"));
    assert_eq!(*schema_version, Some(4));
}

#[test]
fn not_crashing_is_not_the_same_as_preserving() {
    // A reader that parsed an unknown event into "nothing interesting" and wrote
    // back only what it understood would pass a "does not crash" test and still
    // destroy the record. Assert the stronger property on a batch: reading and
    // re-writing a log is the identity on bytes.
    let log: Vec<String> = [
        format!("{{\"v\":1,\"id\":\"{EVT}\",\"type\":\"event\",\"schema\":\"direwolf.session.lease_acquired\",\"schema_version\":1,\"ts\":\"{TS}\",\"session_id\":\"{SES}\",\"payload\":{{\"epoch\":3}}}}"),
        format!("{{\"v\":1,\"id\":\"{EVT}\",\"type\":\"event\",\"schema\":\"direwolf.x.y\",\"schema_version\":1,\"ts\":\"{TS}\",\"payload\":{{\"big\":123456789012345678901234567890}}}}"),
        "{\"v\":7,\"totally\":\"different\",\"payload\":{\"f\":1e-300}}".to_owned(),
    ]
    .to_vec();
    let rewritten: Vec<Vec<u8>> = log
        .iter()
        .map(|line| EventRecord::read(line.as_bytes()).unwrap().raw().to_vec())
        .collect();
    for (line, out) in log.iter().zip(rewritten) {
        assert_eq!(out, line.as_bytes());
    }
}

#[test]
fn preservation_never_relaxes_lexical_strictness() {
    // Forward compatibility tolerates what a newer peer adds. It does not accept
    // what no peer could mean.
    let dup = br#"{"v":1,"v":1}"#;
    assert_eq!(dwcp::decode(dup).unwrap_err().code, ErrorCode::DuplicateKey);
    assert_eq!(
        EventRecord::read(dup).unwrap_err().code,
        ErrorCode::DuplicateKey
    );
    let deep = "[".repeat(40);
    assert_eq!(
        dwcp::decode(deep.as_bytes()).unwrap_err().code,
        ErrorCode::MaxDepthExceeded
    );
    assert_eq!(
        EventRecord::read(deep.as_bytes()).unwrap_err().code,
        ErrorCode::MaxDepthExceeded
    );
}

#[test]
fn a_normalisation_collision_is_an_unknown_field_in_dwkp_and_kept_by_dwcp() {
    // ADR-0034. The two keys below are equal under Unicode NFC and differ as
    // text. No reader normalises, so the outcome is the same whatever Unicode
    // version the host library ships -- which is the property that failed
    // before, because Rust ships 17.0 and CPython 3.12 ships 15.0.
    let pre = char::from_u32(0xE9).unwrap();
    let dec = format!("e{}", char::from_u32(0x301).unwrap());
    let colliding = format!(r#""caf{pre}":1,"caf{dec}":2"#);

    // DWKP: neither name is declared, so the first is already an unknown field.
    let dwkp_doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"request","schema":"direwolf.heartbeat","schema_version":1,
            "ts":"{TS}","session_id":"{SES}","epoch":47,"payload":{{{colliding}}}}}"#
    );
    let err = dwkp::decode_body(dwkp_doc.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
    assert_eq!(err.violation, Some(Violation::UnknownField));
    assert_eq!(err.path, format!("/payload/caf{pre}"));

    // DWCP: both members are preserved, and re-emission keeps both.
    let dwcp_doc = format!(
        r#"{{"v":1,"id":"{MSG}","type":"response","schema":"direwolf.error","schema_version":1,
            "ts":"{TS}","causation_id":"{CAUSE}",
            "payload":{{"code":"E","detail":"d","retryable":false,{colliding}}}}}"#
    );
    let message = dwcp::decode(dwcp_doc.as_bytes()).expect("DWCP preserves both members");
    let reemitted = message.to_canonical_bytes().unwrap();
    let Value::Object(envelope) = json::parse(&reemitted, ParseOptions::ijson()).unwrap() else {
        panic!("a message is an object")
    };
    let Some(Value::Object(payload)) = envelope.get("payload") else {
        panic!("payload is an object")
    };
    let number = |n: i64| Value::Number(json::Number::from_i64(n).unwrap());
    assert_eq!(payload.get(&format!("caf{pre}")), Some(&number(1)));
    assert_eq!(payload.get(&format!("caf{dec}")), Some(&number(2)));

    // Event records keep the bytes regardless.
    let event = format!(
        r#"{{"v":1,"id":"{EVT}","type":"event","schema":"direwolf.session.lease_acquired",
            "schema_version":1,"ts":"{TS}","session_id":"{SES}","payload":{{"epoch":48,{colliding}}}}}"#
    );
    let record = EventRecord::read(event.as_bytes()).expect("a record");
    assert_eq!(record.raw(), event.as_bytes());
}

#[test]
fn every_name_dwkp_interprets_is_ascii() {
    // The reason the test above can hold without a Unicode database: a key that
    // is not byte-equal to a declared name cannot be made equal to one by
    // normalisation, because every declared name is ASCII. If a future message
    // declares a non-ASCII field, this fails and ADR-0034 must be revisited.
    for spec in dwk_proto::dwkp::registry::MESSAGES {
        assert!(spec.schema.is_ascii(), "schema {}", spec.schema);
    }
    for key in dwk_proto::envelope::ENVELOPE_KEYS {
        assert!(key.is_ascii(), "envelope key {key}");
    }
    for (path, schema) in dwk_proto::schema::emit::all() {
        let names = schema_property_names(&schema);
        for name in names {
            assert!(name.is_ascii(), "{path} declares a non-ASCII name: {name}");
        }
    }
}

/// Every `properties` key in an emitted schema, at any depth.
fn schema_property_names(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Value::Object(object) = value {
        for (key, child) in object.iter() {
            if key == "properties"
                && let Value::Object(properties) = child
            {
                out.extend(properties.iter().map(|(name, _)| name.to_owned()));
            }
            out.extend(schema_property_names(child));
        }
    }
    out
}

#[test]
fn a_response_with_a_version_this_build_lacks_is_unsupported_in_every_family() {
    let doc = format!(
        r#"{{"v":2,"id":"{MSG}","type":"response","schema":"direwolf.ack","schema_version":1,"ts":"{TS}","causation_id":"{CAUSE}","payload":{{}}}}"#
    );
    assert_eq!(
        dwkp::decode_body(doc.as_bytes()).unwrap_err().code,
        ErrorCode::VersionUnsupported
    );
    assert_eq!(
        dwcp::decode(doc.as_bytes()).unwrap_err().code,
        ErrorCode::VersionUnsupported
    );
    // The event log does not fail: it retains what it cannot read.
    assert!(matches!(
        EventRecord::read(doc.as_bytes()).unwrap().view(),
        EventView::Unknown { .. }
    ));
}
