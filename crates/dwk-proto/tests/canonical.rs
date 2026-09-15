//! RFC 8785 canonicalisation beyond the RFC's own samples.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use common::load_vectors;
use dwk_proto::json::{self, Number, ParseOptions, Value, number::format_es};

#[test]
fn every_double_serialises_exactly_as_v8_does() {
    let doc = load_vectors("numbers.json");
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(
        vectors.len() > 8000,
        "the V8 corpus is missing or truncated"
    );
    let mut failures = Vec::new();
    for v in vectors {
        let bits = u64::from_str_radix(v["bits"].as_str().unwrap(), 16).unwrap();
        let expected = v["es"].as_str().unwrap();
        let x = f64::from_bits(bits);
        // Through the value model too: integral safe values become Int.
        let via_value = json::to_canonical_string(&Value::Number(Number::from_f64(x).unwrap()));
        if format_es(x).as_deref() != Some(expected) || via_value != expected {
            failures.push(format!(
                "{bits:016x}: expected {expected}, got {:?} / {via_value}",
                format_es(x)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches, first: {:?}",
        failures.len(),
        failures.first()
    );
}

#[test]
fn canonicalisation_is_idempotent_and_order_insensitive() {
    let a = br#"{ "b": [1, 2.50, {"z": null, "a": true}], "a": "x" }"#;
    let b = br#"{"a":"x","b":[1,2.5,{"a":true,"z":null}]}"#;
    let ca = json::to_canonical_bytes(&json::parse(a, ParseOptions::ijson()).unwrap());
    let cb = json::to_canonical_bytes(&json::parse(b, ParseOptions::ijson()).unwrap());
    assert_eq!(
        ca, cb,
        "semantically identical values must canonicalise identically"
    );
    assert_eq!(ca, b.to_vec(), "already-canonical input is a fixed point");
    let again = json::to_canonical_bytes(&json::parse(&ca, ParseOptions::ijson()).unwrap());
    assert_eq!(again, ca);
}

#[test]
fn numbers_with_different_spellings_have_one_canonical_form() {
    for (spelling, canonical) in [
        ("1", "1"),
        ("1.0", "1"),
        ("1e0", "1"),
        ("10E-1", "1"),
        ("-0", "0"),
        ("-0.0", "0"),
        ("0.5", "0.5"),
        ("5e-1", "0.5"),
        ("1e21", "1e+21"),
        ("100000000000000000000", "100000000000000000000"),
        ("1e-7", "1e-7"),
        ("0.000001", "0.000001"),
        ("9007199254740993", "9007199254740992"),
    ] {
        let v = json::parse(spelling.as_bytes(), ParseOptions::ijson()).unwrap();
        assert_eq!(json::to_canonical_string(&v), canonical, "{spelling}");
    }
}

#[test]
fn strings_are_escaped_exactly_as_section_3_2_2_2_requires() {
    const BS: char = '\\';
    let mut input = String::new();
    let mut expected = String::from('"');
    for c in 0u32..0x20 {
        input.push(char::from_u32(c).unwrap());
        match c {
            0x08 => expected.push_str(&format!("{BS}b")),
            0x09 => expected.push_str(&format!("{BS}t")),
            0x0a => expected.push_str(&format!("{BS}n")),
            0x0c => expected.push_str(&format!("{BS}f")),
            0x0d => expected.push_str(&format!("{BS}r")),
            // Lowercase hex, four digits.
            _ => expected.push_str(&format!("{BS}u{c:04x}")),
        }
    }
    // Quote and backslash are escaped; solidus, DEL, U+2028, U+2029 and U+FFFD
    // are emitted literally.
    input.push('"');
    input.push(BS);
    input.push('/');
    for c in [0x7f_u32, 0x2028, 0x2029, 0xfffd] {
        input.push(char::from_u32(c).unwrap());
    }
    expected.push(BS);
    expected.push('"');
    expected.push(BS);
    expected.push(BS);
    expected.push('/');
    for c in [0x7f_u32, 0x2028, 0x2029, 0xfffd] {
        expected.push(char::from_u32(c).unwrap());
    }
    expected.push('"');
    assert_eq!(json::to_canonical_string(&Value::String(input)), expected);
}

#[test]
fn keys_sort_by_utf16_code_units_not_by_code_points() {
    // U+1F600 is 0xD83D 0xDE00 in UTF-16, which sorts before U+FB33 (0xFB33),
    // although its code point is larger. Byte order would put it last.
    let emoji = char::from_u32(0x1F600).unwrap().to_string();
    let dalet = char::from_u32(0xFB33).unwrap().to_string();
    let v = json::parse(
        format!("{{\"{dalet}\":1,\"{emoji}\":2}}").as_bytes(),
        ParseOptions::ijson(),
    )
    .unwrap();
    assert_eq!(
        json::to_canonical_string(&v),
        format!("{{\"{emoji}\":2,\"{dalet}\":1}}")
    );
}

#[test]
fn canonicalisation_does_not_normalise_unicode() {
    // RFC 8785 applies no normalisation; neither do we. Decomposed text in a
    // value stays decomposed.
    let decomposed = format!("e{}", char::from_u32(0x301).unwrap());
    let v = Value::String(decomposed.clone());
    assert_eq!(json::to_canonical_string(&v), format!("\"{decomposed}\""));
}
