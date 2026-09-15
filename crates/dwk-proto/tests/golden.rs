//! Cross-language golden vectors: `tests/protocol/vectors/{valid,invalid}.json`.
//!
//! The Python bindings run the same files (`runtime/tests/proto/`). Expected
//! canonical bytes come from an independent V8 oracle, not from either
//! implementation, so agreement here means both match the standard rather than
//! merely each other.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use common::{hex_decode, input_bytes, load_vectors, str_field};
use dwk_proto::dwcp::{self, DwcpBody};
use dwk_proto::events::{EventRecord, EventView};
use dwk_proto::{dwkp, frame, json};

#[test]
fn every_valid_vector_decodes_and_reencodes_to_the_oracle_bytes() {
    let doc = load_vectors("valid.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 20);
    for v in vectors {
        let name = str_field(v, "name");
        let bytes = input_bytes(v);
        match str_field(v, "family") {
            "dwkp" => {
                let message = dwkp::decode_body(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                let canonical = message
                    .to_canonical_bytes()
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    String::from_utf8(canonical).unwrap(),
                    str_field(v, "canonical"),
                    "{name}"
                );
                let framed = message.to_frame().unwrap();
                assert_eq!(
                    framed,
                    hex_decode(str_field(v, "frame_hex")),
                    "{name}: frame"
                );
                // And the frame decodes back to the same message.
                let frames = frame::decode_all(&framed).unwrap();
                assert_eq!(frames.len(), 1);
                assert_eq!(dwkp::decode_frame(&frames[0]).unwrap(), message, "{name}");
            }
            "dwcp" => {
                let message = dwcp::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                let canonical = message.to_canonical_bytes().unwrap();
                assert_eq!(
                    String::from_utf8(canonical).unwrap(),
                    str_field(v, "canonical"),
                    "{name}"
                );
                let expect = str_field(v, "expect");
                match (&message.body, expect) {
                    (DwcpBody::Error(_), "error") | (DwcpBody::Unknown { .. }, "unknown") => {}
                    (body, _) => panic!("{name}: expected {expect}, got {body:?}"),
                }
            }
            "event" => {
                let record = EventRecord::read(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    record.raw(),
                    bytes.as_slice(),
                    "{name}: bytes must be retained verbatim"
                );
                let expect = str_field(v, "expect");
                let got = match record.view() {
                    EventView::Known { .. } => "known",
                    EventView::Unknown { .. } => "unknown",
                    EventView::Invalid { .. } => "invalid",
                };
                assert_eq!(got, expect, "{name}: {:?}", record.view());
            }
            other => panic!("unknown family {other}"),
        }
    }
}

#[test]
fn every_invalid_vector_is_rejected_with_the_expected_code() {
    let doc = load_vectors("invalid.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 80);
    for v in vectors {
        let name = str_field(v, "name");
        let bytes = input_bytes(v);
        let result = match str_field(v, "family") {
            "dwkp" => dwkp::decode_body(&bytes).map(|_| ()),
            "dwcp" => dwcp::decode(&bytes).map(|_| ()),
            "event" => EventRecord::read(&bytes).map(|_| ()),
            other => panic!("unknown family {other}"),
        };
        let err = match result {
            Ok(()) => panic!("{name}: accepted an input that must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), str_field(v, "code"), "{name}: {err}");
        if let Some(violation) = v.get("violation").and_then(|x| x.as_str()) {
            assert_eq!(
                err.violation.map(|x| x.as_str()),
                Some(violation),
                "{name}: {err}"
            );
        }
        if let Some(path) = v.get("path").and_then(|x| x.as_str()) {
            assert_eq!(err.path, path, "{name}: {err}");
        }
    }
}

#[test]
fn lexical_vectors_fail_before_any_semantic_interpretation() {
    // A duplicate or colliding key must be rejected by the lexer itself, not by
    // a later stage that has already chosen one of the two values.
    let doc = load_vectors("invalid.json");
    for v in doc["vectors"].as_array().unwrap() {
        let code = str_field(v, "code");
        if matches!(
            code,
            "PROTOCOL_DUPLICATE_KEY" | "PROTOCOL_NORMALIZATION_COLLISION"
        ) {
            let options = if str_field(v, "family") == "dwkp" {
                json::ParseOptions::dwkp()
            } else {
                json::ParseOptions::ijson()
            };
            let err = json::parse(&input_bytes(v), options).expect_err(str_field(v, "name"));
            assert_eq!(err.code.as_str(), code, "{}", str_field(v, "name"));
        }
    }
}
