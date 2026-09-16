//! The strict JSON lexer.
//!
//! # Why this exists instead of `serde_json`
//!
//! Duplicate-key checks must observe the **lexical** object, before any map has
//! collapsed two members into one. A general-purpose
//! deserializer can be driven to expose that, but using `serde_json` merely as a
//! tokenizer would put it and its locked dependencies — ~66 k source lines, ~430
//! of them containing `unsafe` (byte scanning, number formatting) — into the
//! trusted computing base to do a job this file does in safe Rust. `serde_json`
//! is kept as a dev-only differential oracle instead: the lexer and property
//! tests check that it and this lexer agree on grammar. ADR-0033 §3 records the
//! measurement.
//!
//! # What is enforced, in the order it is enforced
//!
//! 1. The whole input is valid UTF-8 (`PROTOCOL_INVALID_UTF8`). No lossy decode,
//!    no replacement characters.
//! 2. It is exactly one RFC 8259 JSON value with optional surrounding
//!    whitespace (`PROTOCOL_INVALID_JSON`). No byte-order mark, comments,
//!    trailing commas, `NaN`, `Infinity`, single quotes, raw control characters
//!    in strings, or lone surrogate escapes.
//! 3. No container opens beyond [`MAX_DEPTH`] (`PROTOCOL_MAX_DEPTH_EXCEEDED`),
//!    checked **before** the container is descended into.
//! 4. No object has two members whose keys are byte-identical
//!    (`PROTOCOL_DUPLICATE_KEY`), checked when the second key is read and
//!    **before** its value is parsed. Keys are compared as bytes; normalisation
//!    is not consulted, and DWKP's rejection of any undeclared member is what
//!    makes a normalisation collision unrepresentable there (ADR-0034).
//! 5. Numbers are inside the profile's domain (`PROTOCOL_NUMBER_OUT_OF_DOMAIN`).
//!
//! Recursion depth is bounded by [`MAX_DEPTH`], so the lexer cannot exhaust the
//! stack; total work and allocation are linear in input length, which the
//! framing layer bounds at 1 MiB.

use std::collections::HashMap;

use crate::error::{ErrorCode, ProtocolError, quote_key};
use crate::json::value::{Number, Object, Value};
use crate::limits::{MAX_DEPTH, MAX_SAFE_INTEGER};

/// Which numbers a profile admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberDomain {
    /// Integers written without fraction or exponent, magnitude ≤ 2^53 − 1.
    /// The DWKP profile: no value on the authority wire has two spellings.
    SafeInteger,
    /// Any finite I-JSON number (RFC 7493). DWCP and event records use this so
    /// unknown extension data survives; their *known* fields still use typed
    /// integers.
    IJson,
}

/// Lexer profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    numbers: NumberDomain,
}

impl ParseOptions {
    /// DWKP: safe integers only.
    #[must_use]
    pub const fn dwkp() -> Self {
        Self {
            numbers: NumberDomain::SafeInteger,
        }
    }

    /// DWCP and event records: I-JSON numbers.
    #[must_use]
    pub const fn ijson() -> Self {
        Self {
            numbers: NumberDomain::IJson,
        }
    }

    /// The number domain.
    #[must_use]
    pub const fn numbers(self) -> NumberDomain {
        self.numbers
    }
}

/// Parse `input` as exactly one strict JSON value.
pub fn parse(input: &[u8], options: ParseOptions) -> Result<Value, ProtocolError> {
    let text = std::str::from_utf8(input).map_err(|e| {
        ProtocolError::new(ErrorCode::InvalidUtf8, "body is not well-formed UTF-8")
            .at_offset(e.valid_up_to())
    })?;
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        options,
        path: Vec::new(),
    };
    parser.skip_ws();
    if parser.pos >= parser.bytes.len() {
        return Err(parser.invalid("empty input"));
    }
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.invalid("trailing data after the JSON value"));
    }
    Ok(value)
}

enum Segment {
    Key(String),
    Index(usize),
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    options: ParseOptions,
    path: Vec<Segment>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn pointer(&self) -> String {
        let mut out = String::new();
        for segment in &self.path {
            out.push('/');
            match segment {
                Segment::Key(k) => out.push_str(&k.replace('~', "~0").replace('/', "~1")),
                Segment::Index(i) => out.push_str(&i.to_string()),
            }
        }
        out
    }

    fn error(&self, code: ErrorCode, detail: impl Into<String>) -> ProtocolError {
        ProtocolError::new(code, detail)
            .at_offset(self.pos)
            .with_path(&self.pointer())
    }

    fn invalid(&self, detail: &str) -> ProtocolError {
        self.error(ErrorCode::InvalidJson, detail)
    }

    fn expect(&mut self, byte: u8, what: &str) -> Result<(), ProtocolError> {
        if self.peek() == Some(byte) {
            self.bump();
            Ok(())
        } else {
            Err(self.invalid(what))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ProtocolError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => Ok(Value::Number(self.number()?)),
            Some(_) => Err(self.invalid("expected a JSON value")),
            None => Err(self.invalid("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, ProtocolError> {
        let end = self.pos.saturating_add(word.len());
        if self.bytes.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.invalid("invalid literal"))
        }
    }

    fn enter(&self, depth: usize) -> Result<usize, ProtocolError> {
        let next = depth.saturating_add(1);
        if next > MAX_DEPTH {
            Err(self.error(
                ErrorCode::MaxDepthExceeded,
                format!("nesting exceeds the limit of {MAX_DEPTH}"),
            ))
        } else {
            Ok(next)
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ProtocolError> {
        let depth = self.enter(depth)?;
        self.bump(); // '{'
        let mut members: Vec<(String, Value)> = Vec::new();
        // Each key -> the index of the member that introduced it. Keys are
        // compared by bytes: no Unicode database is consulted anywhere in a
        // protocol decision (ADR-0034).
        let mut seen: HashMap<String, usize> = HashMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(Object::from_members_unchecked(members)));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.invalid("expected an object key"));
            }
            let key_offset = self.pos;
            let key = self.string()?;
            if seen.contains_key(&key) {
                self.path.push(Segment::Key(key.clone()));
                let err = self.error(
                    ErrorCode::DuplicateKey,
                    format!("duplicate key {}", quote_key(&key)),
                );
                return Err(err.at_offset(key_offset));
            }
            seen.insert(key.clone(), members.len());
            self.skip_ws();
            self.expect(b':', "expected ':' after an object key")?;
            self.skip_ws();
            self.path.push(Segment::Key(key.clone()));
            let value = self.value(depth)?;
            self.path.pop();
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Object(Object::from_members_unchecked(members)));
                }
                _ => return Err(self.invalid("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ProtocolError> {
        let depth = self.enter(depth)?;
        self.bump(); // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            self.path.push(Segment::Index(items.len()));
            let item = self.value(depth)?;
            self.path.pop();
            items.push(item);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.invalid("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        self.bump(); // opening quote
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.bump();
            }
            // Stopping bytes are ASCII, so this is always a char boundary.
            out.push_str(self.text.get(run_start..self.pos).unwrap_or_default());
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    self.escape(&mut out)?;
                }
                Some(_) => return Err(self.invalid("unescaped control character in string")),
                None => return Err(self.invalid("unterminated string")),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), ProtocolError> {
        let Some(b) = self.peek() else {
            return Err(self.invalid("unterminated escape"));
        };
        self.bump();
        let c = match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                if (0xD800..=0xDBFF).contains(&first) {
                    if self.peek() != Some(b'\\') {
                        return Err(self.invalid("lone high surrogate escape"));
                    }
                    self.bump();
                    if self.peek() != Some(b'u') {
                        return Err(self.invalid("lone high surrogate escape"));
                    }
                    self.bump();
                    let second = self.hex4()?;
                    if !(0xDC00..=0xDFFF).contains(&second) {
                        return Err(self.invalid("high surrogate not followed by a low surrogate"));
                    }
                    let scalar = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                    char::from_u32(scalar).ok_or_else(|| self.invalid("invalid surrogate pair"))?
                } else if (0xDC00..=0xDFFF).contains(&first) {
                    return Err(self.invalid("lone low surrogate escape"));
                } else {
                    char::from_u32(first).ok_or_else(|| self.invalid("invalid unicode escape"))?
                }
            }
            _ => return Err(self.invalid("invalid escape character")),
        };
        out.push(c);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, ProtocolError> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(b @ b'0'..=b'9') => b - b'0',
                Some(b @ b'a'..=b'f') => b - b'a' + 10,
                Some(b @ b'A'..=b'F') => b - b'A' + 10,
                _ => return Err(self.invalid("expected four hex digits")),
            };
            v = (v << 4) | u32::from(digit);
            self.bump();
        }
        Ok(v)
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<Number, ProtocolError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.bump();
        }
        let int_start = self.pos;
        match self.peek() {
            Some(b'0') => {
                self.bump();
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.invalid("leading zero in number"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.invalid("expected a digit")),
        }
        let int_end = self.pos;
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.bump();
            if self.digits() == 0 {
                return Err(self.invalid("expected a digit after the decimal point"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if self.digits() == 0 {
                return Err(self.invalid("expected a digit in the exponent"));
            }
        }
        let lexeme = self.text.get(start..self.pos).unwrap_or_default();

        if integral {
            let digits = self.text.get(int_start..int_end).unwrap_or_default();
            if let Some(i) = safe_integer(digits, negative) {
                return Ok(Number::Int(i));
            }
        }
        match self.options.numbers {
            NumberDomain::SafeInteger => {
                let why = if integral {
                    "integer magnitude exceeds 2^53 - 1"
                } else {
                    "fraction or exponent not permitted; integers only"
                };
                Err(self
                    .error(ErrorCode::NumberOutOfDomain, why)
                    .at_offset(start))
            }
            NumberDomain::IJson => lexeme
                .parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .ok_or_else(|| {
                    self.error(
                        ErrorCode::NumberOutOfDomain,
                        "number is not a finite double",
                    )
                    .at_offset(start)
                }),
        }
    }
}

/// Parse decimal `digits` (already grammar-checked) as a safe integer.
fn safe_integer(digits: &str, negative: bool) -> Option<i64> {
    let mut v: i64 = 0;
    for b in digits.bytes() {
        let d = i64::from(b.checked_sub(b'0')?);
        v = v.checked_mul(10)?.checked_add(d)?;
        if v > MAX_SAFE_INTEGER {
            return None;
        }
    }
    Some(if negative { -v } else { v })
}
