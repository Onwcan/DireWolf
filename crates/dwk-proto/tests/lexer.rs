//! The strict lexer against hostile input, and against an independent parser.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::ErrorCode;
use dwk_proto::json::{self, Number, ParseOptions, Value};
use dwk_proto::limits::MAX_DEPTH;

const BS: char = '\\';

fn dwkp(s: &[u8]) -> Result<Value, dwk_proto::ProtocolError> {
    json::parse(s, ParseOptions::dwkp())
}

fn nest(open: &str, close: &str, depth: usize) -> String {
    format!("{}0{}", open.repeat(depth), close.repeat(depth))
}

/// A JSON string literal containing a `\uXXXX` escape, built at runtime.
fn escaped(hex: &str) -> String {
    format!("\"{BS}u{hex}\"")
}

#[test]
fn depth_exactly_at_the_limit_is_accepted() {
    assert!(dwkp(nest("[", "]", MAX_DEPTH).as_bytes()).is_ok());
    assert!(dwkp(nest("{\"k\":", "}", MAX_DEPTH).as_bytes()).is_ok());
}

#[test]
fn depth_one_over_the_limit_is_rejected_for_arrays_objects_and_mixtures() {
    for doc in [
        nest("[", "]", MAX_DEPTH + 1),
        nest("{\"k\":", "}", MAX_DEPTH + 1),
        format!("{}0{}", "{\"k\":[".repeat(17), "]}".repeat(17)),
    ] {
        assert_eq!(
            dwkp(doc.as_bytes()).unwrap_err().code,
            ErrorCode::MaxDepthExceeded
        );
    }
}

#[test]
fn a_million_open_brackets_is_rejected_at_the_limit_not_parsed_to_the_end() {
    let bomb = "[".repeat(1_000_000);
    let err = dwkp(bomb.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MaxDepthExceeded);
    assert_eq!(
        err.offset,
        Some(MAX_DEPTH),
        "rejected as the 33rd container opens"
    );
}

#[test]
fn a_duplicate_key_is_rejected_before_its_value_is_read() {
    // The second value is malformed; had the lexer read it, the error would be
    // INVALID_JSON. DUPLICATE_KEY proves the duplicate was caught first, while
    // both members were still lexically observable.
    let err = dwkp(br#"{"schema":"a","schema": not json"#).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateKey);
    assert_eq!(err.path, "/schema");
}

#[test]
fn duplicate_keys_are_detected_at_every_depth() {
    let err = dwkp(br#"{"a":{"b":[{"c":1,"c":2}]}}"#).unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateKey);
    assert_eq!(err.path, "/a/b/0/c");
}

#[test]
fn an_escaped_spelling_of_an_existing_key_is_a_duplicate() {
    // "v" and its escaped form decode to the same key.
    let doc = format!("{{\"v\":1,{}:2}}", escaped("0076"));
    assert_eq!(
        dwkp(doc.as_bytes()).unwrap_err().code,
        ErrorCode::DuplicateKey
    );
}

#[test]
fn the_same_key_in_sibling_objects_is_not_a_duplicate() {
    assert!(dwkp(br#"[{"a":1},{"a":2}]"#).is_ok());
    assert!(dwkp(br#"{"a":{"a":{"a":1}}}"#).is_ok());
}

#[test]
fn keys_that_collide_only_under_normalisation_are_distinct_members() {
    // The lexer compares keys as text and consults no Unicode database, so
    // these are two members, not a duplicate (ADR-0034). DWKP still refuses the
    // document, because neither name is declared — see
    // `compatibility.rs::a_normalisation_collision_is_an_unknown_field_in_dwkp`.
    let pre = char::from_u32(0xE9).unwrap();
    let dec = format!("e{}", char::from_u32(0x301).unwrap());
    let doc = format!("{{\"caf{pre}\":1,\"caf{dec}\":2}}");
    let value = dwkp(doc.as_bytes()).expect("two distinct keys");
    let Value::Object(object) = value else {
        panic!("expected an object")
    };
    assert_eq!(object.len(), 2);
    // One spelling alone is accepted too: nothing forces NFC on a sender.
    assert!(dwkp(format!("{{\"caf{dec}\":1}}").as_bytes()).is_ok());
}

#[test]
fn a_singleton_decomposition_is_not_a_duplicate_of_its_target() {
    // U+212A KELVIN SIGN normalises to U+004B, but the reader never normalises,
    // so the decision does not depend on which Unicode version it was built
    // against. Both languages read two members here.
    let kelvin = char::from_u32(0x212A).unwrap();
    let doc = format!("{{\"K\":1,\"{kelvin}\":2}}");
    let value = dwkp(doc.as_bytes()).expect("two distinct keys");
    let Value::Object(object) = value else {
        panic!("expected an object")
    };
    assert_eq!(object.len(), 2);
}

#[test]
fn no_protocol_decision_consults_a_unicode_database() {
    // The property ADR-0034 rests on: the crate links nothing that carries
    // Unicode tables, so a decision cannot depend on a table version. This is
    // asserted structurally, from the manifest, because the absence of a
    // dependency is not otherwise visible from a test.
    let manifest = include_str!("../Cargo.toml");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a dependencies section")
        .split("[dev-dependencies]")
        .next()
        .expect("a dev-dependencies section after it");
    assert!(
        deps.lines()
            .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#')),
        "dwk-proto has gained a dependency: {deps}"
    );
}

#[test]
fn numbers_outside_the_dwkp_domain_are_rejected_not_rounded() {
    for n in [
        "1.0",
        "1e3",
        "-0.5",
        "9007199254740992",
        "-9007199254740992",
        "1E400",
    ] {
        assert_eq!(
            dwkp(n.as_bytes()).unwrap_err().code,
            ErrorCode::NumberOutOfDomain,
            "{n}"
        );
    }
    assert_eq!(
        dwkp(b"9007199254740991").unwrap(),
        Value::Number(Number::Int(9_007_199_254_740_991))
    );
    assert_eq!(
        dwkp(b"-9007199254740991").unwrap(),
        Value::Number(Number::Int(-9_007_199_254_740_991))
    );
}

#[test]
fn escaped_surrogate_pairs_decode_and_lone_ones_do_not() {
    let pair = format!("[\"{BS}ud83d{BS}ude00\"]");
    let emoji = char::from_u32(0x1F600).unwrap().to_string();
    assert_eq!(
        dwkp(pair.as_bytes()).unwrap(),
        Value::Array(vec![Value::String(emoji)])
    );
    for bad in [
        format!("[{}]", escaped("d83d")),
        format!("[{}]", escaped("de00")),
        format!("[\"{BS}ud83dx\"]"),
        format!("[\"{BS}ude00{BS}ud83d\"]"),
    ] {
        assert_eq!(
            dwkp(bad.as_bytes()).unwrap_err().code,
            ErrorCode::InvalidJson,
            "{bad}"
        );
    }
}

/// Grammar agreement with `serde_json`, an independent and heavily fuzzed
/// parser, on documents chosen to sit on grammar edges. The strict lexer may
/// reject *more* — duplicates, collisions, depth, number domain — but it must
/// never accept a document `serde_json` considers ungrammatical, and must agree
/// on the value of everything both accept.
#[test]
fn grammar_agrees_with_serde_json() {
    let mut corpus: Vec<Vec<u8>> = [
        "{}",
        "[]",
        "0",
        "-0",
        "1",
        "true",
        "false",
        "null",
        "\"\"",
        " [ 1 , 2 ] ",
        "[1,]",
        "[,1]",
        "{,}",
        "{\"a\"}",
        "{\"a\":}",
        "{:1}",
        "01",
        "1.",
        ".1",
        "1e",
        "1e+",
        "-",
        "--1",
        "+1",
        "0x10",
        "tru",
        "nul",
        "NaN",
        "[1 2]",
        "\"abc",
        "{\"a\":[{\"b\":null}]}",
        "\t\n\r [ ] \n",
        "[1e10]",
        "[1E-2]",
        "[123.456e+7]",
        "{\"\":1}",
        "[[[[]]]]",
        "[1]x",
        "{}{}",
        "[\"a\u{e9}\"]",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    for esc in ["0041", "00e9", "0000", "d834", "dd1e"] {
        corpus.push(format!("[{}]", escaped(esc)).into_bytes());
    }
    corpus.push(format!("[\"{BS}ud834{BS}udd1e\"]").into_bytes());
    corpus.push(format!("[\"{BS}z\"]").into_bytes());
    corpus.push(format!("[\"{BS}/\"]").into_bytes());
    corpus.push(b"[\"\x01\"]".to_vec());
    corpus.push(b"\xef\xbb\xbf{}".to_vec());
    corpus.push(b"[\"\xc3\"]".to_vec());

    for doc in &corpus {
        let shown = String::from_utf8_lossy(doc);
        let ours = json::parse(doc, ParseOptions::ijson());
        let theirs: Result<serde_json::Value, _> = serde_json::from_slice(doc);
        if let Ok(value) = &ours {
            let reference = theirs.unwrap_or_else(|e| {
                panic!("strict lexer accepted {shown:?}, serde_json rejected it: {e}")
            });
            let reparsed: serde_json::Value =
                serde_json::from_str(&json::to_canonical_string(value)).unwrap();
            assert!(
                same_value(&reparsed, &reference),
                "value mismatch for {shown:?}"
            );
        }
    }
}

/// Structural equality with numbers compared as doubles, so `-0` equals `0`.
/// RFC 8785 serialises both as `0`, and the strict lexer's value model has one
/// representation per number; `serde_json` keeps the sign of zero.
fn same_value(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value as J;
    match (a, b) {
        (J::Number(x), J::Number(y)) => x.as_f64() == y.as_f64(),
        (J::Array(x), J::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_value(p, q))
        }
        (J::Object(x), J::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_value(v, w)))
        }
        _ => a == b,
    }
}
