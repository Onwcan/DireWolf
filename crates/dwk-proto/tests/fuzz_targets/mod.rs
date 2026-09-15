//! Fuzz target bodies, shared by two engines.
//!
//! * `fuzz/fuzz_targets/*.rs` — coverage-guided libFuzzer via `cargo fuzz`
//!   (nightly, Linux CI; see `.github/workflows/fuzz.yml`).
//! * `tests/fuzz_smoke.rs` — a deterministic mutation loop on stable Rust that
//!   runs on every `cargo test` and can be given a time budget locally.
//!
//! Both include this file, so the invariants are written once. Each target
//! panics — the only signal a fuzzer understands — when an invariant breaks.
//! Every invariant is one the protocol's security argument depends on.

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto::dwcp;
use dwk_proto::dwkp;
use dwk_proto::envelope::ENVELOPE_KEYS;
use dwk_proto::events::EventRecord;
use dwk_proto::frame::{self, FrameDecoder};
use dwk_proto::json::{self, ParseOptions, Value};
use dwk_proto::limits::MAX_FRAME_BODY;
use dwk_proto::version::SUPPORTED_ENVELOPE;

/// Framing: never panics; incremental decoding under an input-chosen chunking
/// agrees with whole-buffer decoding; no frame exceeds the limit or is empty.
pub(crate) fn frame_decoder(data: &[u8]) {
    let whole = frame::decode_all(data);
    let chunk = usize::from(data.first().copied().unwrap_or(1)).max(1);
    let mut decoder = FrameDecoder::new();
    let mut frames = Vec::new();
    let mut failed = None;
    'outer: for piece in data.chunks(chunk) {
        let mut rest = piece;
        while !rest.is_empty() {
            match decoder.feed(rest) {
                Ok((used, frame)) => {
                    if let Some(f) = frame {
                        frames.push(f);
                    }
                    rest = &rest[used..];
                }
                Err(e) => {
                    failed = Some(e);
                    break 'outer;
                }
            }
        }
    }
    let incremental = match failed {
        Some(e) => Err(e),
        None => decoder.finish().map(|()| frames),
    };
    match (&whole, &incremental) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "chunking changed the frames"),
        (Err(a), Err(b)) => assert_eq!(a.code, b.code, "chunking changed the error"),
        _ => panic!("chunking changed acceptance: whole={whole:?} incremental={incremental:?}"),
    }
    if let Ok(frames) = whole {
        for f in frames {
            assert!(!f.body.is_empty() && f.body.len() <= MAX_FRAME_BODY);
        }
    }
}

/// DWKP decode: never panics; an accepted body contains only declared
/// envelope keys, re-encodes, and the canonical re-encoding decodes to the same
/// message. Invalid data never yields a message that would not survive its own
/// round trip.
pub(crate) fn dwkp_decode(data: &[u8]) {
    let Ok(message) = dwkp::decode_body(data) else {
        return;
    };
    let original =
        json::parse(data, ParseOptions::dwkp()).expect("accepted bodies are lexically valid");
    let Value::Object(object) = original else {
        panic!("accepted a non-object message")
    };
    for (key, _) in object.iter() {
        assert!(
            ENVELOPE_KEYS.contains(&key),
            "accepted undeclared envelope key {key:?}"
        );
    }
    let canonical = message
        .to_canonical_bytes()
        .expect("an accepted message re-encodes");
    assert_eq!(
        dwkp::decode_body(&canonical).expect("canonical form decodes"),
        message
    );
    let framed = message.to_frame().expect("an accepted message frames");
    let frames = frame::decode_all(&framed).expect("own frame decodes");
    assert_eq!(
        dwkp::decode_frame(&frames[0]).expect("own frame body decodes"),
        message
    );
}

/// Canonical JSON: never panics; parse(canonical(v)) == v; canonicalisation is
/// idempotent; the strict profile never accepts what the I-JSON profile rejects.
pub(crate) fn canonical_roundtrip(data: &[u8]) {
    let strict = json::parse(data, ParseOptions::dwkp());
    let ijson = json::parse(data, ParseOptions::ijson());
    if strict.is_ok() {
        assert!(
            ijson.is_ok(),
            "the DWKP profile accepted what I-JSON rejects"
        );
        assert_eq!(
            strict.as_ref().ok(),
            ijson.as_ref().ok(),
            "profiles disagree on a value both accept"
        );
    }
    let Ok(value) = ijson else { return };
    let once = json::to_canonical_bytes(&value);
    let reparsed = json::parse(&once, ParseOptions::ijson()).expect("canonical output parses");
    assert_eq!(reparsed, value, "canonical form changed the value");
    assert_eq!(
        json::to_canonical_bytes(&reparsed),
        once,
        "canonicalisation is not idempotent"
    );
}

/// Envelope and versions across families: never panics; a message DWKP accepts
/// has a supported `v`; DWCP re-emission is value-preserving; event records are
/// always retained byte for byte.
pub(crate) fn envelope_version(data: &[u8]) {
    if let Ok(message) = dwkp::decode_body(data) {
        assert!(SUPPORTED_ENVELOPE.contains(message.header.v.get()));
    }
    if let Ok(message) = dwcp::decode(data) {
        let reemitted = message
            .to_canonical_bytes()
            .expect("an accepted DWCP message re-encodes");
        let original =
            json::parse(data, ParseOptions::ijson()).expect("accepted DWCP is lexically valid");
        let again = json::parse(&reemitted, ParseOptions::ijson()).expect("re-emitted DWCP parses");
        assert_eq!(again, original, "DWCP re-emission lost or changed data");
    }
    if let Ok(record) = EventRecord::read(data) {
        assert_eq!(
            record.raw(),
            data,
            "an event record was not retained verbatim"
        );
    }
}

/// A fuzz target body.
pub(crate) type Target = fn(&[u8]);

/// Every target, by name, for the smoke harness.
pub(crate) const TARGETS: &[(&str, Target)] = &[
    ("frame_decoder", frame_decoder),
    ("dwkp_decode", dwkp_decode),
    ("canonical_roundtrip", canonical_roundtrip),
    ("envelope_version", envelope_version),
];
