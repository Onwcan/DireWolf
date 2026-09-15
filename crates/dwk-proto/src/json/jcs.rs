//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Used for every byte string that is hashed, MACed or compared: frame bodies
//! produced by this crate, and — per ADR-0032 — approval binding hashes, device
//! MACs, audit chaining and capability MACs in later milestones. One canonical
//! encoding, implemented once, in the TCB.
//!
//! * Members sorted by the UTF-16 code units of their keys (§3.2.3).
//! * Strings escaped per §3.2.2.2: `"`, `\`, and U+0000–U+001F only, with the
//!   short forms for `\b \t \n \f \r` and lowercase `\u00hh` otherwise.
//!   Everything else, including U+2028/U+2029 and U+007F, is emitted literally.
//! * Numbers per ECMAScript `Number::toString` (§3.2.2.3), see
//!   [`super::number`].
//! * No whitespace; UTF-8 output (§3.2.1, §3.2.4).
//!
//! **No Unicode normalisation is applied to strings or keys.** RFC 8785 does
//! not normalise, and doing so would make the canonical form of a value differ
//! from the value. Normalisation-colliding keys are rejected at parse time
//! instead, so two members can never canonicalise ambiguously.
//!
//! Lone surrogates cannot occur: [`Value::String`] holds a Rust `String`, which
//! is always valid Unicode, and the lexer rejects lone surrogate escapes.

use std::cmp::Ordering;

use crate::json::number::format_es;
use crate::json::value::{Number, Object, Value};

/// Serialise a value in canonical form.
#[must_use]
pub fn to_canonical_bytes(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(&mut out, value);
    out.into_bytes()
}

/// Serialise a value in canonical form, as a string.
#[must_use]
pub fn to_canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(Number::Int(i)) => out.push_str(&i.to_string()),
        // `Number` is finite by construction; "null" is unreachable in practice
        // and exists only so this function is total.
        Value::Number(Number::Float(f)) => out.push_str(&format_es(*f).unwrap_or_default()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(object) => write_object(out, object),
    }
}

fn write_object(out: &mut String, object: &Object) {
    let mut members: Vec<(&str, &Value)> = object.iter().collect();
    members.sort_by(|(a, _), (b, _)| utf16_cmp(a, b));
    out.push('{');
    for (i, (key, value)) in members.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, value);
    }
    out.push('}');
}

/// Compare two strings by their UTF-16 code units, as §3.2.3 requires.
///
/// This differs from byte or code-point order for keys mixing supplementary
/// characters with BMP characters above U+E000: U+1F600 sorts *before* U+FB33
/// here, because its high surrogate 0xD83D is less than 0xFB33.
#[must_use]
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::to_canonical_string;
    use crate::json::lex::{ParseOptions, parse};

    fn canon(input: &str) -> String {
        parse(input.as_bytes(), ParseOptions::ijson())
            .map_or_else(|e| format!("ERROR {e}"), |v| to_canonical_string(&v))
    }

    /// RFC 8785 §3.2.2 input and §3.2.4 bytes, verbatim from the RFC.
    /// Source: <https://www.rfc-editor.org/rfc/rfc8785.txt>.
    #[test]
    fn rfc_8785_section_3_2_worked_example() {
        let input = r#"{
            "numbers": [333333333.33333329, 1E30, 4.50,
                        2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"#;
        let rfc_hex = concat!(
            "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 ",
            "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a ",
            "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 ",
            "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37 ",
            "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 ",
            "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d",
        );
        let rfc_bytes: Vec<u8> = rfc_hex
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        assert_eq!(rfc_bytes.len(), 118);
        assert_eq!(canon(input).into_bytes(), rfc_bytes);
    }

    /// RFC 8785 §3.2.3 sorting sample, verbatim.
    #[test]
    fn rfc_8785_section_3_2_3_sort_order() {
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let out = canon(input);
        let order = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let positions: Vec<usize> = order.iter().filter_map(|name| out.find(name)).collect();
        assert_eq!(positions.len(), order.len(), "{out}");
        assert!(positions.windows(2).all(|w| w.first() < w.get(1)), "{out}");
    }
}
