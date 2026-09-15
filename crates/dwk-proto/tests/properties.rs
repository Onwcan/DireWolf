//! Property tests: invariants over generated inputs rather than chosen examples.
//!
//! Each property names what would break without it. None restates a getter.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::messages::{HeartbeatPayload, LeaseGrant};
use dwk_proto::dwkp::{self, DwkpBody, DwkpMessage};
use dwk_proto::envelope::{Header, MessageType};
use dwk_proto::frame::{self, ContentType, FrameDecoder};
use dwk_proto::json::{self, Number, Object, ParseOptions, Value};
use dwk_proto::version::{VersionRange, negotiate};
use dwk_proto::wire::id::{AnyId, SessionId, decode_uuid7, encode_uuid};
use dwk_proto::wire::scalar::{Epoch, SchemaName, Timestamp, Version};
use dwk_proto::{ErrorCode, Violation};
use proptest::prelude::*;

// ---- generators ----------------------------------------------------------

fn uuid7() -> impl Strategy<Value = u128> {
    any::<u128>().prop_map(|v| {
        let with_version = (v & !(0xF_u128 << 76)) | (7_u128 << 76);
        (with_version & !(0b11_u128 << 62)) | (0b10_u128 << 62)
    })
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-(1_i64 << 53) + 1..(1_i64 << 53)).prop_map(|i| Value::Number(Number::Int(i))),
        any::<f64>()
            .prop_filter_map("finite", Number::from_f64)
            .prop_map(Value::Number),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((any::<String>(), inner), 0..6).prop_map(|members| {
                let mut object = Object::new();
                for (k, v) in members {
                    // Colliding keys are the lexer's problem, not the generator's.
                    let _ = object.insert(k, v);
                }
                Value::Object(object)
            }),
        ]
    })
}

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

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    // Without this, a canonical hash could depend on how a peer happened to
    // chunk its writes.
    #[test]
    fn framing_round_trips_under_any_chunking(
        bodies in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..2048), 1..5),
        chunk in 1_usize..512,
    ) {
        let stream: Vec<u8> = bodies.iter().flat_map(|b| frame::encode(ContentType::Json, b).unwrap()).collect();
        let mut decoder = FrameDecoder::new();
        let mut out = Vec::new();
        for piece in stream.chunks(chunk) {
            let mut rest = piece;
            while !rest.is_empty() {
                let (used, frame) = decoder.feed(rest).unwrap();
                if let Some(f) = frame { out.push(f.body); }
                rest = &rest[used..];
            }
        }
        decoder.finish().unwrap();
        prop_assert_eq!(out, bodies);
    }

    // The frame decoder is the first code attacker bytes reach.
    #[test]
    fn the_frame_decoder_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = frame::decode_all(&bytes);
    }

    // Nor may the lexer; and anything it accepts it must re-read identically.
    #[test]
    fn the_lexer_never_panics_and_what_it_accepts_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        for options in [ParseOptions::dwkp(), ParseOptions::ijson()] {
            if let Ok(value) = json::parse(&bytes, options) {
                let canonical = json::to_canonical_bytes(&value);
                prop_assert_eq!(json::parse(&canonical, options).unwrap(), value);
            }
        }
    }

    // Canonicalisation must be a function of the value alone.
    #[test]
    fn canonicalisation_is_idempotent(value in json_value()) {
        let once = json::to_canonical_bytes(&value);
        let reparsed = json::parse(&once, ParseOptions::ijson()).unwrap();
        prop_assert_eq!(&reparsed, &value);
        prop_assert_eq!(json::to_canonical_bytes(&reparsed), once);
    }

    // A lexer that accepts what an established parser rejects is a parser
    // differential: two components reading one message two ways.
    #[test]
    fn the_lexer_never_accepts_what_serde_json_rejects(value in json_value(), cut in any::<prop::sample::Index>(), flip in any::<u8>()) {
        let mut bytes = json::to_canonical_bytes(&value);
        if !bytes.is_empty() {
            let i = cut.index(bytes.len());
            bytes[i] ^= flip;
        }
        if json::parse(&bytes, ParseOptions::ijson()).is_ok() {
            prop_assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_ok(), "{:?}", String::from_utf8_lossy(&bytes));
        }
    }

    // One spelling per identifier.
    #[test]
    fn identifiers_have_exactly_one_spelling(v in uuid7(), noise in "[0-9A-Za-z]{26}") {
        let text = encode_uuid(v);
        prop_assert_eq!(decode_uuid7(&text), Some(v));
        if let Some(decoded) = decode_uuid7(&noise) {
            prop_assert_eq!(encode_uuid(decoded), noise);
        }
    }

    // Negotiation must never pick a version one side does not speak, or one
    // below the floor, and must pick the highest that qualifies.
    #[test]
    fn negotiation_is_sound_and_maximal(a in 1_u16..20, b in 1_u16..20, c in 1_u16..20, d in 1_u16..20, floor in 1_u16..20) {
        let offered = VersionRange::new(a.min(b), a.max(b)).unwrap();
        let supported = VersionRange::new(c.min(d), c.max(d)).unwrap();
        let exists = (1..=u16::MAX).any(|v| offered.contains(v) && supported.contains(v) && v >= floor);
        match negotiate(offered, supported, floor) {
            Ok(v) => {
                prop_assert!(offered.contains(v) && supported.contains(v) && v >= floor);
                prop_assert!(!(v + 1..=u16::MAX).any(|w| offered.contains(w) && supported.contains(w)));
            }
            Err(e) => {
                prop_assert!(!exists);
                prop_assert_eq!(e.code, ErrorCode::VersionUnsupported);
            }
        }
    }

    // Any lease grant the kernel could send survives framing unchanged.
    #[test]
    fn lease_grants_round_trip(session in uuid7(), cause in uuid7(), epoch in 1_u64..=9_007_199_254_740_991) {
        let mut h = header(MessageType::Response, "direwolf.lease.grant");
        h.causation_id = AnyId::parse(&format!("msg_{}", encode_uuid(cause)));
        let message = DwkpMessage {
            header: h,
            body: DwkpBody::LeaseGrant(LeaseGrant {
                session_id: SessionId::from_uuid(session).unwrap(),
                epoch: Epoch::new(epoch).unwrap(),
            }),
        };
        let frames = frame::decode_all(&message.to_frame().unwrap()).unwrap();
        prop_assert_eq!(dwkp::decode_frame(&frames[0]).unwrap(), message);
    }

    // Adding any undeclared member anywhere in a DWKP message is rejected —
    // never ignored, whatever its name or value.
    #[test]
    fn any_undeclared_member_is_rejected(key in "x_[a-z_]{1,16}", in_payload in any::<bool>(), extra in json_value()) {
        let mut h = header(MessageType::Request, "direwolf.heartbeat");
        h.session_id = SessionId::parse("ses_01M24BB8G2E87V1ZPZXQ7DSCVW");
        h.epoch = Epoch::new(7);
        let message = DwkpMessage { header: h, body: DwkpBody::Heartbeat(HeartbeatPayload {}) };
        let Value::Object(envelope) = message.to_value().unwrap() else { unreachable!() };
        let mut members = envelope.into_members();
        if in_payload {
            let payload = members.iter_mut().find(|(k, _)| k == "payload").unwrap();
            let Value::Object(p) = &mut payload.1 else { unreachable!() };
            p.insert(key.clone(), extra).unwrap();
        } else {
            members.push((key.clone(), extra));
        }
        let mut rebuilt = Object::new();
        for (k, v) in members { rebuilt.insert(k, v).unwrap(); }
        let err = dwkp::decode_value(Value::Object(rebuilt)).unwrap_err();
        prop_assert_eq!(err.violation, Some(Violation::UnknownField));
        prop_assert!(err.path.ends_with(&key));
    }
}
